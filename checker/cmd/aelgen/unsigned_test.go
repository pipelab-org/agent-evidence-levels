// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

func TestUnsignedHashChain(t *testing.T) {
	priv, pub, fp := labeledKey("unsigned-chain-test")
	cases, err := buildCases(priv, fp)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"ael0/unsigned_hash_chain": true, "ael0/valid": true, "ael0/unpublished_key": true}
	root := t.TempDir()
	for _, c := range cases {
		if !wanted[c.name] {
			continue
		}
		delete(wanted, c.name)
		t.Run(c.name, func(t *testing.T) {
			if err := writeCase(root, c, pub, fp); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, c.name)
			raw, err := os.ReadFile(filepath.Join(dir, "recorders/r1.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
			if len(lines) < 2 {
				t.Fatalf("need a chain, got %d records", len(lines))
			}
			unsigned := c.name == "ael0/unsigned_hash_chain"
			prev := zeroHash()
			for i, line := range lines {
				parts := strings.Split(line, ".")
				if len(parts) != 2 || parts[0] == "" {
					t.Fatalf("record %d: missing payload or delimiter", i)
				}
				payload, err := base64.RawURLEncoding.DecodeString(parts[0])
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				if err := json.Unmarshal(payload, &fields); err != nil {
					t.Fatal(err)
				}
				canonical, err := canonicalValue(fields)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(payload, canonical) {
					t.Fatalf("record %d: noncanonical payload", i)
				}
				if fields["prev"] != prev {
					t.Fatalf("record %d: predecessor = %v, want %s", i, fields["prev"], prev)
				}
				prev = shaHex(payload)
				sig, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					t.Fatal(err)
				}
				if unsigned {
					if len(sig) != 0 {
						t.Fatalf("record %d: unsigned case has a signature", i)
					}
					if fields["run"] != "run-ael0-unsigned-hash-chain" {
						t.Fatalf("unexpected run: %v", fields["run"])
					}
				} else if !ed25519.Verify(pub, payload, sig) {
					t.Fatalf("record %d: signed control has invalid signature", i)
				}
			}
			keys, err := os.ReadDir(filepath.Join(dir, "keys"))
			if err != nil {
				t.Fatal(err)
			}
			wantKeys := 0
			if c.name == "ael0/valid" {
				wantKeys = 1
			}
			if len(keys) != wantKeys {
				t.Fatalf("published keys = %d, want %d", len(keys), wantKeys)
			}
			art, err := ael.LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err != nil {
				t.Fatal(err)
			}
			report := ael.Evaluate(art)
			if len(report.Runs) != 1 {
				t.Fatalf("run count = %d", len(report.Runs))
			}
			result := report.Runs[0]
			wantAuth, wantGrade := "PASS", "AEL0"
			if unsigned {
				wantAuth, wantGrade = "FAIL", "ungraded"
			} else if wantKeys == 0 {
				wantAuth, wantGrade = "UV", "ungraded"
			}
			if got := string(result.Checks["a"].Status); got != wantAuth {
				t.Fatalf("authentication = %s, want %s", got, wantAuth)
			}
			if got := reportGrade(result); got != wantGrade {
				t.Fatalf("grade = %s, want %s", got, wantGrade)
			}
			if unsigned && !strings.Contains(result.Checks["a"].Message, "malformed compact record line") {
				t.Fatalf("unexpected failure: %s", result.Checks["a"].Message)
			}
		})
	}
	if len(wanted) != 0 {
		t.Fatalf("missing cases: %v", wanted)
	}
}
