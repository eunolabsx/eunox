// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests that guard the published documentation snippets against regressions: a
// removed-but-still-documented subcommand (validate-token) and a fetch policy
// snippet whose SSRF-guard regex must remain valid YAML. The cmd/eunox tests
// run with CWD = the package dir, so the site lives at ../../site.

package main

import (
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/config"
	"gopkg.in/yaml.v3"
)

// sitePublicDir is the published-site output directory, relative to the
// cmd/eunox package directory (the test CWD), two levels up from the repo
// root.
func sitePublicDir() string {
	return filepath.Join("..", "..", "site", "public")
}

// TestSiteDocsHaveNoValidateTokenSubcommand guards against re-publishing the
// removed `validate-token` subcommand in the docs. It checks the deploy page
// directly and, to stay robust, scans every published *.html file.
func TestSiteDocsHaveNoValidateTokenSubcommand(t *testing.T) {
	deployPath := filepath.Join(sitePublicDir(), "deploy", "index.html")
	b, err := os.ReadFile(deployPath)
	if err != nil {
		t.Skipf("published deploy page absent (%v); run the site build to materialize it", err)
	}
	if strings.Contains(string(b), "validate-token") {
		t.Errorf("%s still documents the removed `validate-token` subcommand", deployPath)
	}

	// Robust sweep: no published HTML page may mention the removed subcommand.
	root := sitePublicDir()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(content), "validate-token") {
			t.Errorf("%s still documents the removed `validate-token` subcommand", path)
		}
		return nil
	})
	if err != nil {
		t.Skipf("published site directory not walkable (%v); run the site build", err)
	}
}

var (
	// preCodeBlockRe matches a single <pre><code> ... </code></pre> span; the
	// captured group is the (still HTML-encoded) block body. Non-greedy so each
	// fenced block is matched individually.
	preCodeBlockRe = regexp.MustCompile(`(?s)<pre><code>(.*?)</code></pre>`)
	// htmlTagRe strips any residual inline HTML tags inside a code block.
	htmlTagRe = regexp.MustCompile(`<[^>]*>`)
)

// TestPublishedFetchPolicySnippetParsesAsYAML extracts the fetch policy snippet
// from the published policies page (the <pre><code> block containing
// "tool:fetch") and asserts it parses as YAML. The SSRF-guard `pattern:` uses a
// single-quoted scalar so its \. escapes survive — a double-quoted scalar would
// make the snippet invalid YAML.
func TestPublishedFetchPolicySnippetParsesAsYAML(t *testing.T) {
	policiesPath := filepath.Join(sitePublicDir(), "policies", "index.html")
	b, err := os.ReadFile(policiesPath)
	if err != nil {
		t.Skipf("published policies page absent (%v); run the site build to materialize it", err)
	}
	page := string(b)

	var snippet string
	for _, m := range preCodeBlockRe.FindAllStringSubmatch(page, -1) {
		body := m[1]
		if strings.Contains(body, "tool:fetch") {
			snippet = body
			break
		}
	}
	if snippet == "" {
		t.Fatalf("no <pre><code> block containing %q found in %s", "tool:fetch", policiesPath)
	}

	// Strip any inline HTML tags, then HTML-unescape (&quot;->" &lt;-< &gt;->
	// &amp;->&) so the YAML scanner sees the literal source.
	yamlText := html.UnescapeString(htmlTagRe.ReplaceAllString(snippet, ""))

	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlText), &doc); err != nil {
		t.Fatalf("published fetch policy snippet does not parse as YAML: %v\n--- snippet ---\n%s", err, yamlText)
	}

	// The SSRF guard must use a single-quoted scalar so the \. escapes are valid
	// YAML; a double-quoted scalar would either fail to parse or change meaning.
	if !strings.Contains(yamlText, "pattern: '") {
		t.Errorf("fetch policy SSRF guard must use a single-quoted scalar (pattern: '...'); snippet:\n%s", yamlText)
	}
}

// snippetNameRe extracts a capability manifest's `name:` field (optionally
// double-quoted) to label a subtest more usefully than a bare index.
var snippetNameRe = regexp.MustCompile(`(?m)^name:\s*"?([\w-]+)"?`)

// TestPublishedPolicySnippetsLoadAsManifests extracts every published policy
// snippet that declares `schemaVersion:` (i.e. every reference manifest on the
// page — the plain `eunox validate ...` shell-command block is not YAML and is
// excluded by that filter) and loads each through config.LoadManifest, the same
// path `eunox validate` and `eunox proxy --config` run — not just a bare YAML
// unmarshal. A snippet can parse as valid YAML while still being rejected by the
// real manifest loader: the Fetch policy's RE2-incompatible `argumentSchema.pattern`
// (a negative lookahead Go's regexp engine does not support) was exactly this case,
// and TestPublishedFetchPolicySnippetParsesAsYAML's plain yaml.Unmarshal check did
// not catch it.
func TestPublishedPolicySnippetsLoadAsManifests(t *testing.T) {
	policiesPath := filepath.Join(sitePublicDir(), "policies", "index.html")
	b, err := os.ReadFile(policiesPath)
	if err != nil {
		t.Skipf("published policies page absent (%v); run the site build to materialize it", err)
	}
	page := string(b)

	var snippets []string
	for _, m := range preCodeBlockRe.FindAllStringSubmatch(page, -1) {
		body := html.UnescapeString(htmlTagRe.ReplaceAllString(m[1], ""))
		if strings.Contains(body, "schemaVersion:") {
			snippets = append(snippets, body)
		}
	}
	if len(snippets) == 0 {
		t.Fatalf("no manifest snippet (containing %q) found in %s", "schemaVersion:", policiesPath)
	}

	dir := t.TempDir()
	for i, snippet := range snippets {
		label := fmt.Sprintf("snippet_%d", i)
		if m := snippetNameRe.FindStringSubmatch(snippet); m != nil {
			label = m[1]
		}
		t.Run(label, func(t *testing.T) {
			path := filepath.Join(dir, label+".yaml")
			if err := os.WriteFile(path, []byte(snippet), 0o600); err != nil {
				t.Fatalf("writing snippet to temp file: %v", err)
			}
			if _, err := config.LoadManifest(path); err != nil {
				t.Errorf("published policy snippet does not load as a valid manifest: %v\n--- snippet ---\n%s", err, snippet)
			}
		})
	}
}
