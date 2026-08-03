// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// contracts: the operator-facing surface of the effect layer's authoring-time half.
//
// It verifies a contract corpus — every entry loaded, every declared digest recomputed
// against its content, duplicate ids reported — and prints the `effect.ref` pin an author
// copies into a manifest. Both were reachable only from `go test` before, which meant a
// corpus you were handed could not be checked without writing Go, and pinning an entry
// meant hand-computing a digest.
//
// Everything here is LOCAL. eunox never fetches the registry, on the decision path or off
// it, and this must not become the path that starts: the digest is over the contract's own
// content, so verification and pinning both work offline against files on disk.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/registry"
)

// defaultContractsDir is the corpus shipped in this repository. It is a convenience for
// the common case, not a lookup path: nothing searches for a corpus, and a directory that
// is not there is an error rather than a silent empty result.
const defaultContractsDir = "registry/contracts"

// reportUnreadableCorpusDir explains a corpus directory that could not be read, adding
// where the path came from when the operator did not choose it. The default is
// CWD-relative, so a bare `eunox contracts` from an installed binary dead-ends on a path
// nothing in the output identifies as a default — the first-run experience for anyone not
// standing in a checkout.
func reportUnreadableCorpusDir(resolved, requested string, statErr error) {
	fmt.Fprintf(os.Stderr, "eunox contracts: cannot read corpus directory %q: %v\n", resolved, statErr)
	if requested == defaultContractsDir {
		fmt.Fprintf(os.Stderr, "  (%q is the default, resolved against the current directory — pass --dir to name a corpus, e.g. --dir ./registry/contracts from a checkout)\n", defaultContractsDir)
	}
}

// cmdContracts runs the `contracts` subcommand and returns the process exit code (rather
// than calling os.Exit itself), so tests can drive every branch — including the failure
// paths — without terminating the test binary.
func cmdContracts(args []string) int {
	fs := flag.NewFlagSet("contracts", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage:
  eunox contracts [--dir <corpus-dir>] [--trust-keys <file>]
  eunox contracts [--dir <corpus-dir>] --ref <contract-id>
  eunox contracts [--dir <corpus-dir>] --attest-payload <contract-id> [--role <role>] [--statement <statement>]

Verify a local effect-contract corpus: every *.json entry is loaded and validated,
each entry's declared digest is recomputed from its own content, and duplicate ids
are reported. Without --ref, the verified corpus is listed with the pin for each
entry.

With --trust-keys, each entry's signed attestations are additionally verified
against a local trusted-key file, and the listing gains an ATTESTATION column: who
attests to the entry, and who DISPUTES it. A signature by a key the file does not
hold is reported as unverified, never as an error — a corpus may be signed by
parties you have not chosen to trust. A signature by a key it DOES hold that fails
to verify is an error: the entry was edited after it was signed.

With --ref, print just the "effect.ref" value for one contract id — the
"<id>@sha256:<hex>" string a manifest capability pins — so an author copies a pin
rather than hand-computing a digest.

With --attest-payload, print the exact bytes a signer covers when attesting to an
entry, so a publisher signs them with their own tooling and key. eunox verifies
attestations; it never mints them, and it holds no signing key.

Everything is local: eunox never fetches the registry or any key, and the digest is
over the contract's own content, so this works offline.

Exit codes:
  0  Corpus valid (and, with --ref/--attest-payload, the requested value printed).
  2  Usage error, an unreadable corpus or trust store, an invalid entry, a trusted
     signature that does not verify, or an unknown contract id.

Flags:
`)
		fs.PrintDefaults()
	}

	dir := fs.String("dir", defaultContractsDir, "Directory holding the corpus entries (*.json).")
	ref := fs.String("ref", "", "Print the effect.ref pin for this contract id and exit.")
	trustKeys := fs.String("trust-keys", "", "Local JSON file of trusted attestation public keys; verifies each entry's signatures and adds an ATTESTATION column.")
	attestPayload := fs.String("attest-payload", "", "Print the bytes a signer covers for this contract id and exit (see --role/--statement).")
	role := fs.String("role", registry.AttestRoleVendor, "Signer role for --attest-payload: \"vendor\" or \"reviewer\".")
	statement := fs.String("statement", registry.AttestStatementAttests, "Statement for --attest-payload: \"attests\" or \"disputes\".")

	if err := fs.Parse(args); err != nil {
		// flag.ErrHelp is a successful query (fs.Usage already printed), not a usage error.
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if rest := fs.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "eunox contracts: unexpected argument %q; the corpus directory is given with --dir\n", rest[0])
		return 2
	}
	// Two query modes that each print one value and exit. Combining them would have to pick
	// one silently, so it is a usage error instead.
	if *ref != "" && *attestPayload != "" {
		fmt.Fprintln(os.Stderr, "eunox contracts: --ref and --attest-payload each print one value; pass only one")
		return 2
	}

	// ExpandHome for parity with every other operator-supplied path in the CLI.
	resolved, err := config.ExpandHome(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox contracts: %v\n", err)
		return 2
	}
	// LoadCorpus globs, so a missing directory yields an empty corpus rather than an
	// error. Reporting "0 contracts, valid" for a path that does not exist would be a
	// clean bill of health for something never read — the exact shape the loader's own
	// fail-on-first-invalid rule exists to prevent one level down.
	if info, statErr := os.Stat(resolved); statErr != nil {
		reportUnreadableCorpusDir(resolved, *dir, statErr)
		return 2
	} else if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "eunox contracts: %q is not a directory\n", resolved)
		return 2
	}

	contracts, err := registry.LoadCorpus(resolved)
	if err != nil {
		// The loader fails on the FIRST invalid entry — a bad digest, an unknown class, a
		// duplicate id — and its message already names the file and the reason.
		fmt.Fprintf(os.Stderr, "eunox contracts: %v\n", err)
		return 2
	}

	// Signature verification is opt-in, because it needs a key file only the operator can
	// supply — there is no default trust store and nothing is fetched to build one. Without
	// --trust-keys the corpus verifies exactly as it did before (digest integrity), and the
	// listing simply omits the column rather than printing an unverified one that reads like
	// a verdict.
	//
	// It runs BEFORE the --ref and --attest-payload branches, not after. Those two are the
	// moments a decision is made — an author copies a pin, a publisher signs — so they are
	// exactly where a tampered entry has to STOP the command (exit 2) and a trusted reviewer's
	// DISPUTE has to reach the operator (a stderr warning; a dispute is advisory and does not
	// change the exit code). Returning early made `--ref` with `--trust-keys` exit 0 having
	// verified nothing, which is the false assurance the listing's own column rule exists to
	// avoid.
	var statuses map[string]registry.AttestationStatus
	if *trustKeys != "" {
		store, storeErr := registry.LoadTrustStore(*trustKeys)
		if storeErr != nil {
			fmt.Fprintf(os.Stderr, "eunox contracts: %v\n", storeErr)
			return 2
		}
		statuses = make(map[string]registry.AttestationStatus, len(contracts))
		for i := range contracts {
			st, verifyErr := contracts[i].VerifyAttestations(store)
			if verifyErr != nil {
				// A trusted key whose signature does not verify is tampering, not a
				// reporting nuance: stop rather than print a corpus listing with one row
				// quietly saying "-".
				fmt.Fprintf(os.Stderr, "eunox contracts: %v\n", verifyErr)
				return 2
			}
			statuses[contracts[i].ID] = st
		}
		if *ref == "" && *attestPayload == "" {
			wf(os.Stdout, "OK    %s  (%d trusted attestation key(s))\n", *trustKeys, store.Len())
		}
	}

	if *ref != "" {
		return writeContractRef(os.Stdout, contracts, *ref, statuses)
	}
	if *attestPayload != "" {
		return writeAttestPayload(os.Stdout, contracts, *attestPayload, *role, *statement, statuses)
	}
	writeContractCorpus(os.Stdout, resolved, contracts, statuses)
	return 0
}

// writeAttestPayload prints the exact bytes a signer covers for one entry, so a publisher can
// sign them with their own tooling. eunox verifies attestations and never mints them — it
// holds no signing key and has no subcommand that would want one — so the deliverable here is
// the payload, not a signature.
//
// The digest that goes into the payload is the one LoadCorpus already recomputed from the
// entry's content, so a signature made from this output is bound to the content in the file
// rather than to whatever the file happened to declare.
//
// It warns on a DISPUTE for the same reason --ref does, and the case is if anything stronger:
// putting a signature on an entry is a more durable commitment than pasting a pin, and a
// publisher who is about to make one is exactly who needs to know that a reviewer they trust
// read the entry and disagreed.
func writeAttestPayload(out io.Writer, contracts []registry.Contract, id, role, statement string, statuses map[string]registry.AttestationStatus) int {
	c := findContract(contracts, id)
	if c == nil {
		return reportUnknownContractID(id, "--attest-payload")
	}
	warnIfDisputed(id, statuses)
	payload, err := registry.NewSignaturePayload(c, role, statement)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox contracts: %v\n", err)
		return 2
	}
	// No trailing newline: the payload is the signed byte string, and a shell
	// redirection of this output has to be the bytes and nothing else.
	wf(out, "%s", payload)
	return 0
}

// findContract returns the entry with this id, or nil. It is one linear walk shared by the
// two single-entry commands rather than a copy in each: they had the same scan and the same
// not-found message differing only in the flag name, which is two places to edit for one
// lookup and two places for the message to drift.
func findContract(contracts []registry.Contract, id string) *registry.Contract {
	for i := range contracts {
		if contracts[i].ID == id {
			return &contracts[i]
		}
	}
	return nil
}

// reportUnknownContractID is the shared not-found path; askedBy names the flag that asked,
// so the message points at the one the operator actually typed. An unknown id is an error
// rather than empty output for both callers: a pin an author pastes, and a payload a
// publisher signs, both have to come from an entry that exists.
func reportUnknownContractID(id, askedBy string) int {
	fmt.Fprintf(os.Stderr, "eunox contracts: no contract with id %q in the corpus (run without %s to list the ids it holds)\n", id, askedBy)
	return 2
}

// warnIfDisputed reports a trusted key's DISPUTE of the entry a single-entry command is about
// to hand over, on stderr so the value on stdout stays pipeable. Nothing when the caller passed
// no --trust-keys (statuses is nil) or nobody disputed.
//
// It is one function rather than a line in each caller because the two callers are the two
// moments an author commits to an entry — pasting a pin, signing an attestation — and a warning
// that fires at one and not the other is the shape that silently regresses. It deliberately
// does not change the exit code: a dispute is a community-advisory signal, not a verdict eunox
// is in a position to issue.
func warnIfDisputed(id string, statuses map[string]registry.AttestationStatus) {
	st, ok := statuses[id]
	if !ok || len(st.Disputed) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "eunox contracts: WARNING %q is DISPUTED by %v (a trusted key you configured); read their reasoning before relying on it\n", id, st.Disputed)
}

// writeContractRef prints the pin for one contract id. An unknown id is an error, not an
// empty line: a pin an author pastes has to come from an entry that exists.
//
// When attestations were verified (--trust-keys), a DISPUTE on the entry being pinned is
// reported on stderr rather than swallowed. Printing the pin anyway is deliberate — a dispute
// is a community-advisory signal and not a verdict eunox is in a position to issue — but the
// one moment an author is about to commit to an entry is the moment they need to know someone
// who read it disagreed.
func writeContractRef(out io.Writer, contracts []registry.Contract, id string, statuses map[string]registry.AttestationStatus) int {
	c := findContract(contracts, id)
	if c == nil {
		return reportUnknownContractID(id, "--ref")
	}
	warnIfDisputed(id, statuses)
	wf(out, "%s\n", c.Ref())
	return 0
}

// writeContractCorpus lists a verified corpus: one row per entry with the fields a
// reviewer selects on, plus the pin. The digest each row carries has already been
// recomputed from the entry's content by LoadCorpus, so a listed row is a verified one.
//
// statuses is nil unless the caller passed --trust-keys, in which case each row gains an
// ATTESTATION column reporting what verified. The column is omitted entirely rather than
// filled with a placeholder when no trust store was given: a column of "-" beside every entry
// reads as "nobody signed these", when the truth is "nothing was checked".
func writeContractCorpus(out io.Writer, dir string, contracts []registry.Contract, statuses map[string]registry.AttestationStatus) {
	wf(out, "OK    %s  (%d contract(s), every declared digest matches its content)\n", dir, len(contracts))
	if len(contracts) == 0 {
		wln(out, "\n(no *.json entries)")
		return
	}
	wln(out)
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	// One row shape, assembled as cells and joined once, rather than a header literal and a
	// row call per column set. The two-copy form was four places to edit for a new column,
	// and the copies could drift so that the header and the rows disagreed on column count —
	// which tabwriter renders as a silently misaligned table, not an error.
	writeRow := func(cells []string) { wf(tw, "%s\n", strings.Join(cells, "\t")) }
	header := []string{"ID", "TOOL", "CLASS", "REVIEW"}
	if statuses != nil {
		header = append(header, "ATTESTATION")
	}
	writeRow(append(header, "REF"))

	var disputed int
	for i := range contracts {
		c := &contracts[i]
		class := c.Effect.Class
		if c.Effect.ByArgument != nil {
			// An argument-parameterized contract has no single class; saying which argument
			// selects one is more useful than printing the base block's class as if it were
			// the answer for every call.
			class = "by " + c.Effect.ByArgument.Argument
		}
		cells := []string{c.ID, c.Tool, class, c.Attestation.Review}
		if statuses != nil {
			st := statuses[c.ID]
			if len(st.Disputed) > 0 {
				disputed++
			}
			cells = append(cells, st.Summary())
		}
		writeRow(append(cells, c.Ref()))
	}
	// The write errors tabwriter can report are the same non-actionable stdout failures wf
	// discards; the report is already emitted by the time this returns.
	_ = tw.Flush()
	wln(out)
	if disputed > 0 {
		// Repeated below the table because the table is what gets scrolled past. A dispute
		// is the one row state that should change what an operator does next, and it is
		// deliberately not an error exit: someone who looked disagreeing is a signal to weigh,
		// not a verdict eunox is in a position to issue.
		wf(out, "%d entr(y/ies) carry a DISPUTE from a key you trust. A dispute is a community-advisory\n", disputed)
		wln(out, "signal, not a scanner verdict: read the disputing party's reasoning before pinning.")
		wln(out)
	}
	wln(out, "A review state is provenance, not a correctness guarantee: a contract asserts what a")
	wln(out, "tool does, and nothing here observes whether it is telling the truth. A verified")
	wln(out, "attestation says WHO is making the claim, never that the claim is true.")
}

// writeEffectCoverage reports how much of a manifest carries an effect contract, and names
// what does not.
//
// The ratio is the operator's progress meter on the registry flywheel, and the names are
// the worklist: under an effectCeiling every unannotated capability resolves to the
// fail-closed default (irreversible, unquantified) and therefore ESCALATES, so "how much of
// my policy is annotated" is the question that predicts the approval queue. Without this it
// was answerable only by reading YAML.
//
// listTargets governs whether the worklist NAMES the capabilities or only counts them: the
// operator-facing `validate` path names them (that is the point), while the doctor bundle —
// which is written to be pasted into a public bug report — counts them, since a capability
// target is a resource URI or a tool name and every other line of that bundle is
// deliberately a count or a digest.
//
// Printed for every manifest, ceiling or not. A policy with no ceiling still benefits from
// knowing the ratio before it adds one — that is precisely when the answer changes what
// happens — so the line states which regime it is reporting under rather than staying
// silent until a ceiling exists.
func writeEffectCoverage(out io.Writer, prefix string, m *config.LocalManifest, listTargets bool) {
	if m == nil {
		return
	}
	total := len(m.Capabilities)
	if total == 0 {
		return
	}
	annotated := m.EffectAnnotatedCount()
	wf(out, "%seffect coverage: %d/%d capabilities annotated\n", prefix, annotated, total)
	unannotated := m.EffectUnannotatedTargets()
	if len(unannotated) == 0 {
		return
	}
	if !listTargets {
		// The doctor bundle is generated to be pasted into a public bug report, and every
		// other manifest line there is a count or a digest — never a target. A capability
		// target is a resource URI or a tool name ("resource:postgres://prod-billing/*"),
		// so listing them here would make this the one place the bundle leaks manifest
		// contents. The ratio still tells the reader what they need.
		wf(out, "%s  unannotated: %d (run `eunox validate` locally to list them)\n", prefix, len(unannotated))
		return
	}
	consequence := "these would escalate if an effectCeiling were added"
	if m.HasEffectCeiling() {
		consequence = "these ESCALATE under this policy's effectCeiling"
	}
	wf(out, "%s  unannotated (%s):\n", prefix, consequence)
	for _, t := range unannotated {
		wf(out, "%s    %s\n", prefix, t)
	}
}
