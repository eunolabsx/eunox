// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import "time"

// killDimension is one revocable identity axis, declared once with everything the Redis
// backend needs to handle it: its durable key prefix, its pub/sub channel word, the operator
// names an error message uses, whether its tombstones expire, which local cache holds it, and
// the Revocation an observer is handed.
//
// # Why a table
//
// The two original axes were hand-mirrored across eight places — both backends' reads, the
// kill/revive writer, the pub/sub handler, the reconcile commit, the reconcile union, Reset's
// key sweep and both backends' Status — and the pair was spelled out at each. Adding a third by the same method is six edits that
// must agree, with no compiler check on any of them: a `jti:kill:` event the handler forgets is
// a revocation that propagates to Redis, survives the reconcile, and silently never reaches one
// replica's cache. That is a fail-OPEN on the emergency stop, and it is invisible until someone
// revokes a credential during an incident.
//
// Every one of those sites now iterates killDimensions, so a fourth axis is one entry rather
// than six edits, and the entry cannot be half-written: the struct has no optional field.
//
// # Why the caches stay named fields
//
// The obvious next step — one `map[string]map[string]bool` keyed by dimension name — would
// remove the accessors below. It is not taken because the sets are reached under each holder's
// own lock and a nested map puts a second lookup in front of every dimension on the read path,
// which runs ahead of every policy evaluation on every request. The named fields stay; what the
// table supplies is the ACCESSOR, so no path has to know which field a dimension lives in.
type killDimension struct {
	// name is the pub/sub channel word and the durable key's middle segment — one value, so a
	// writer cannot publish on one dimension's channel while writing another's key.
	name string
	// entity and idField are the operator-facing halves of an error message: the method name
	// ("KillAgent") and the parameter it names ("agentID").
	entity  string
	idField string
	// keyPrefix is the durable Redis key prefix, always name-derived; held as its own field
	// so the existing constants stay the single spelling of what is already in Redis.
	keyPrefix string
	// expires marks a dimension whose tombstones carry the session TTL. Only sessions do: an
	// agent kill and a token revocation are durable revocations of a long-lived identity, and
	// a revocation that quietly expires is one an operator did not withdraw.
	expires bool
	// cache and memCache return the live set for this dimension on each backend. Two
	// accessors rather than one over an interface: both are called under the holder's own
	// lock on paths that must not allocate an interface value, and the two backends store
	// their sets in unrelated fields.
	cache    func(r *Redis) map[string]bool
	memCache func(m *InMemory) map[string]bool
	// slot returns the field of a Status this dimension's ids are reported in.
	//
	// On the DECLARATION rather than a switch inside the snapshot builder: Status has a named
	// field per dimension (it is a JSON contract, so the ids cannot become one anonymous map),
	// and a builder that switched on the name would let a dimension added here go silently
	// missing from every snapshot an operator reads to confirm what is in force. Required —
	// TestKillDimensions_EveryEntryIsComplete fails an entry that omits it.
	slot func(st *Status) *[]string
	// replace installs a fresh cache map for this dimension, for the reconcile commit and
	// Reset. Called under r.mu.
	replace func(r *Redis, m map[string]bool)
	// event builds the Revocation an observer is handed for this dimension.
	event func(id string) Revocation
	// subject reads this dimension's value out of a Subject, so a check can be written once
	// over the table where a per-dimension one would drift from the writer's list.
	subject func(s Subject) string
}

// killDimensions is every revocable axis except the global stop, which names no id and so has
// no key prefix, no cache and no per-id event.
//
// Iterated BY POINTER everywhere (`for i := range`, not `for _, dim := range`). The entry is
// ~100 bytes of strings and closures, and ShouldBlock walks the whole table on every request
// ahead of every policy evaluation — a by-value range copies it per dimension per call for
// nothing. The entries are package-level and never mutated, so the pointer is to fixed data.
//
// ORDER is the gate order ShouldBlock and HealthStatus both walk. It does not decide the
// answer — a match on any dimension blocks — but it decides which revocation a request is
// attributed to when several match, and both backends walk it identically so they cannot
// disagree about that.
var killDimensions = []killDimension{
	{
		name:      "agent",
		entity:    "Agent",
		idField:   "agentID",
		keyPrefix: redisAgentPrefix,
		cache:     func(r *Redis) map[string]bool { return r.killedAgents },
		memCache:  func(m *InMemory) map[string]bool { return m.killedAgents },
		slot:      func(st *Status) *[]string { return &st.KilledAgents },
		replace:   func(r *Redis, m map[string]bool) { r.killedAgents = m },
		event:     func(id string) Revocation { return Revocation{AgentID: id} },
		subject:   func(s Subject) string { return s.AgentID },
	},
	{
		name:      "session",
		entity:    "Session",
		idField:   "sessionID",
		keyPrefix: redisSessionPfx,
		expires:   true,
		cache:     func(r *Redis) map[string]bool { return r.killedSessions },
		memCache:  func(m *InMemory) map[string]bool { return m.killedSessions },
		slot:      func(st *Status) *[]string { return &st.KilledSessions },
		replace:   func(r *Redis, m map[string]bool) { r.killedSessions = m },
		event:     func(id string) Revocation { return Revocation{SessionID: id} },
		subject:   func(s Subject) string { return s.SessionID },
	},
	{
		name:      "jti",
		entity:    "JTI",
		idField:   "jti",
		keyPrefix: redisJTIPrefix,
		cache:     func(r *Redis) map[string]bool { return r.revokedJTIs },
		memCache:  func(m *InMemory) map[string]bool { return m.revokedJTIs },
		slot:      func(st *Status) *[]string { return &st.RevokedJTIs },
		replace:   func(r *Redis, m map[string]bool) { r.revokedJTIs = m },
		event:     func(id string) Revocation { return Revocation{JTI: id} },
		subject:   func(s Subject) string { return s.JTI },
	},
}

// dimensionByName returns the declared dimension, for the pub/sub handler which has only the
// channel word an event arrived under.
func dimensionByName(name string) (*killDimension, bool) {
	for i := range killDimensions {
		if killDimensions[i].name == name {
			return &killDimensions[i], true
		}
	}
	return nil, false
}

// ttl is how long this dimension's durable tombstone lives, given the backend's configured
// session TTL. Zero is durable-until-revived.
func (d *killDimension) ttl(sessionKillTTL time.Duration) time.Duration {
	if d.expires {
		return sessionKillTTL
	}
	return 0
}
