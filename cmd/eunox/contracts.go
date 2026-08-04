// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// contracts: the operator-facing surface of the effect layer's authoring-time half. Verifies
// a contract corpus (loads every entry, recomputes each declared digest, reports duplicate
// ids) and prints the `effect.ref` pin an author copies into a manifest — previously reachable
// only from `go test`. Everything is local: the digest is over the contract's own content, so
// this works offline and must stay that way.

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

// defaultContractsDir is a convenience default, not a search path: a missing directory is
// an error rather than a silent empty result.
const defaultContractsDir = "registry/contracts"

// reportUnreadableCorpusDir explains an unreadable corpus directory, naming the default
// explicitly when the operator did not pass --dir — a bare `eunox contracts` run outside a
// checkout otherwise dead-ends on a CWD-relative path nothing identifies as the default.
func reportUnreadableCorpusDir(resolved, requested string, statErr error) {
	fmt.Fprintf(os.Stderr, "eunox contracts: cannot read corpus directory %q: %v\n", resolved, statErr)
	if requested == defaultContractsDir {
		fmt.Fprintf(os.Stderr, "  (%q is the default, resolved against the current directory — pass --dir to name a corpus, e.g. --dir ./registry/contracts from a checkout)\n", defaultContractsDir)
	}
}

// cmdContracts runs the `contracts` subcommand, returning the exit code (rather than
// calling os.Exit) so tests can drive every branch including the failure paths.
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
	// Combining the two query modes would have to pick one silently; reject instead.
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
	// LoadCorpus globs, so a missing directory yields an empty corpus, not an error —
	// stat it ourselves first so a typo'd --dir doesn't report "0 contracts, valid".
	if info, statErr := os.Stat(resolved); statErr != nil {
		reportUnreadableCorpusDir(resolved, *dir, statErr)
		return 2
	} else if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "eunox contracts: %q is not a directory\n", resolved)
		return 2
	}

	contracts, err := registry.LoadCorpus(resolved)
	if err != nil {
		// LoadCorpus fails on the first invalid entry; its message names the file and reason.
		fmt.Fprintf(os.Stderr, "eunox contracts: %v\n", err)
		return 2
	}

	// Signature verification is opt-in (needs an operator-supplied key file; nothing is
	// fetched) and runs BEFORE the --ref/--attest-payload branches: those are the moments an
	// author commits to an entry, so a tampered one must stop the command there rather than
	// let `--ref --trust-keys` exit 0 having verified nothing.
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
				// A trusted key whose signature fails to verify is tampering: stop rather
				// than print a listing with one row quietly saying "-".
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

// writeAttestPayload prints the exact bytes a signer covers for one entry — eunox verifies
// attestations and never mints them, so the deliverable is the payload, not a signature. The
// digest is the one LoadCorpus already recomputed from content, binding a signature to the
// file's actual bytes rather than its declared digest.
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
	// No trailing newline: the payload is the exact signed byte string.
	wf(out, "%s", payload)
	return 0
}

// findContract returns the entry with this id, or nil — one linear walk shared by the two
// single-entry commands so the lookup and not-found message can't drift between them.
func findContract(contracts []registry.Contract, id string) *registry.Contract {
	for i := range contracts {
		if contracts[i].ID == id {
			return &contracts[i]
		}
	}
	return nil
}

// reportUnknownContractID is the shared not-found path; askedBy names the flag the operator
// typed so the message points at it. Errors rather than empty output either way — the pin an
// author pastes and the payload a publisher signs both must come from an entry that exists.
func reportUnknownContractID(id, askedBy string) int {
	fmt.Fprintf(os.Stderr, "eunox contracts: no contract with id %q in the corpus (run without %s to list the ids it holds)\n", id, askedBy)
	return 2
}

// warnIfDisputed reports a trusted key's DISPUTE of the entry a single-entry command is about
// to hand over, on stderr so stdout stays pipeable. It never changes the exit code — a dispute
// is a community-advisory signal, not a verdict eunox is in a position to issue.
func warnIfDisputed(id string, statuses map[string]registry.AttestationStatus) {
	st, ok := statuses[id]
	if !ok || len(st.Disputed) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "eunox contracts: WARNING %q is DISPUTED by %v (a trusted key you configured); read their reasoning before relying on it\n", id, st.Disputed)
}

// writeContractRef prints the pin for one contract id, warning on stderr (not blocking) if a
// trusted key disputed the entry — printed anyway since a dispute is advisory, not a verdict.
func writeContractRef(out io.Writer, contracts []registry.Contract, id string, statuses map[string]registry.AttestationStatus) int {
	c := findContract(contracts, id)
	if c == nil {
		return reportUnknownContractID(id, "--ref")
	}
	warnIfDisputed(id, statuses)
	wf(out, "%s\n", c.Ref())
	return 0
}

// writeContractCorpus lists a verified corpus: one row per entry with the fields a reviewer
// selects on, plus the pin. statuses is nil unless --trust-keys was passed; the ATTESTATION
// column is then omitted entirely rather than filled with placeholders — a column of "-"
// beside every entry would read as "nobody signed these" when the truth is "nothing checked".
func writeContractCorpus(out io.Writer, dir string, contracts []registry.Contract, statuses map[string]registry.AttestationStatus) {
	wf(out, "OK    %s  (%d contract(s), every declared digest matches its content)\n", dir, len(contracts))
	if len(contracts) == 0 {
		wln(out, "\n(no *.json entries)")
		return
	}
	wln(out)
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	// One row shape, assembled as cells and joined once: a header literal plus a separate
	// per-column row call could drift on column count, which tabwriter renders as a
	// silently misaligned table rather than an error.
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
			// No single class for an argument-parameterized contract; name the selecting
			// argument instead of printing the base block's class as if it applied to every call.
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
		// Repeated below the table since the table itself is what gets scrolled past.
		wf(out, "%d entr(y/ies) carry a DISPUTE from a key you trust. A dispute is a community-advisory\n", disputed)
		wln(out, "signal, not a scanner verdict: read the disputing party's reasoning before pinning.")
		wln(out)
	}
	wln(out, "A review state is provenance, not a correctness guarantee: a contract asserts what a")
	wln(out, "tool does, and nothing here observes whether it is telling the truth. A verified")
	wln(out, "attestation says WHO is making the claim, never that the claim is true.")
}

// writeEffectCoverage reports how much of a manifest carries an effect contract, and names
// what does not — under an effectCeiling every unannotated capability escalates, so this
// ratio predicts the approval queue. listTargets names the capabilities (validate) vs. only
// counting them (the doctor bundle, which is pasted into public bug reports and must not
// leak resource URIs / tool names).
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
		// The doctor bundle is pasted into public bug reports; a target like
		// "resource:postgres://prod-billing/*" would leak manifest contents.
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
