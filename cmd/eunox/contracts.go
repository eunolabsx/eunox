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
	"text/tabwriter"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/registry"
)

// defaultContractsDir is the corpus shipped in this repository. It is a convenience for
// the common case, not a lookup path: nothing searches for a corpus, and a directory that
// is not there is an error rather than a silent empty result.
const defaultContractsDir = "registry/contracts"

// cmdContracts runs the `contracts` subcommand and returns the process exit code (rather
// than calling os.Exit itself), so tests can drive every branch — including the failure
// paths — without terminating the test binary.
func cmdContracts(args []string) int {
	fs := flag.NewFlagSet("contracts", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage:
  eunox contracts [--dir <corpus-dir>]
  eunox contracts [--dir <corpus-dir>] --ref <contract-id>

Verify a local effect-contract corpus: every *.json entry is loaded and validated,
each entry's declared digest is recomputed from its own content, and duplicate ids
are reported. Without --ref, the verified corpus is listed with the pin for each
entry.

With --ref, print just the "effect.ref" value for one contract id — the
"<id>@sha256:<hex>" string a manifest capability pins — so an author copies a pin
rather than hand-computing a digest.

Everything is local: eunox never fetches the registry, and the digest is over the
contract's own content, so this works offline.

Exit codes:
  0  Corpus valid (and, with --ref, the pin printed).
  2  Usage error, an unreadable corpus, an invalid entry, or an unknown --ref id.

Flags:
`)
		fs.PrintDefaults()
	}

	dir := fs.String("dir", defaultContractsDir, "Directory holding the corpus entries (*.json).")
	ref := fs.String("ref", "", "Print the effect.ref pin for this contract id and exit.")

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
		fmt.Fprintf(os.Stderr, "eunox contracts: cannot read corpus directory %q: %v\n", resolved, statErr)
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

	if *ref != "" {
		return writeContractRef(os.Stdout, contracts, *ref)
	}
	writeContractCorpus(os.Stdout, resolved, contracts)
	return 0
}

// writeContractRef prints the pin for one contract id. An unknown id is an error, not an
// empty line: a pin an author pastes has to come from an entry that exists.
func writeContractRef(out io.Writer, contracts []registry.Contract, id string) int {
	for i := range contracts {
		if contracts[i].ID == id {
			wf(out, "%s\n", contracts[i].Ref())
			return 0
		}
	}
	fmt.Fprintf(os.Stderr, "eunox contracts: no contract with id %q in the corpus (run without --ref to list the ids it holds)\n", id)
	return 2
}

// writeContractCorpus lists a verified corpus: one row per entry with the fields a
// reviewer selects on, plus the pin. The digest each row carries has already been
// recomputed from the entry's content by LoadCorpus, so a listed row is a verified one.
func writeContractCorpus(out io.Writer, dir string, contracts []registry.Contract) {
	wf(out, "OK    %s  (%d contract(s), every declared digest matches its content)\n", dir, len(contracts))
	if len(contracts) == 0 {
		wln(out, "\n(no *.json entries)")
		return
	}
	wln(out)
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	wf(tw, "ID\tTOOL\tCLASS\tREVIEW\tREF\n")
	for i := range contracts {
		c := &contracts[i]
		class := c.Effect.Class
		if c.Effect.ByArgument != nil {
			// An argument-parameterized contract has no single class; saying which argument
			// selects one is more useful than printing the base block's class as if it were
			// the answer for every call.
			class = "by " + c.Effect.ByArgument.Argument
		}
		wf(tw, "%s\t%s\t%s\t%s\t%s\n", c.ID, c.Tool, class, c.Attestation.Review, c.Ref())
	}
	// The write errors tabwriter can report are the same non-actionable stdout failures wf
	// discards; the report is already emitted by the time this returns.
	_ = tw.Flush()
	wln(out)
	wln(out, "A review state is provenance, not a correctness guarantee: a contract asserts what a")
	wln(out, "tool does, and nothing here observes whether it is telling the truth.")
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
