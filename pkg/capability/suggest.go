// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import "strings"

// NearestString returns the candidate closest to s by case-insensitive
// Levenshtein edit distance, provided that distance is less than 3; otherwise
// it returns "". Candidates are considered in order, so ties resolve to the
// earliest — pass them pre-sorted for lexicographic tie-breaking. It powers the
// "did you mean …?" hints for unrecognized manifest keys and condition types.
func NearestString(s string, candidates []string) string {
	best := ""
	bestDist := 3
	ls := strings.ToLower(s)
	for _, c := range candidates {
		if d := levenshtein(ls, strings.ToLower(c)); d < bestDist {
			bestDist = d
			best = c
		}
	}
	return best
}

// levenshtein returns the edit distance between a and b, measured in Unicode code
// points (runes), not UTF-8 bytes — a single multi-byte rune typo counts as one
// edit, so "did you mean …?" hints rank correctly for non-ASCII input.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
