// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

func TestUnsignedHashChain(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(fixtureSeed)
	pub := priv.Public().(ed25519.PublicKey)
	fp := fingerprint(pub)
	cases, err := buildCases(priv, fp)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := writeCaseManifest(root, cases); err != nil {
		t.Fatal(err)
	}
	assertFixtureBytes(t, filepath.Join(root, "CASES.txt"), filepath.Join(corpusFixtureRoot, "CASES.txt"))
	for _, c := range cases {
		if c.name == "ael0/valid" {
			invalid := c
			invalid.name = "ael0/invalid_signature_control"
			invalid.records = cloneRecords(c.records)
			invalid.records[0].sig[0] ^= 1
			cases = append(cases, invalid)
			break
		}
	}
	wanted := map[string]bool{"ael0/unsigned_hash_chain": true, "ael0/valid": true, "ael0/unpublished_key": true, "ael0/invalid_signature_control": true}
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
			if len(lines) != 3 {
				t.Fatalf("want three records, got %d", len(lines))
			}
			unsigned := c.name == "ael0/unsigned_hash_chain"
			invalidSignature := c.name == "ael0/invalid_signature_control"
			prev := strings.Repeat("0", sha256.Size*2)
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
				canonical, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(payload, canonical) {
					t.Fatalf("record %d: noncanonical payload", i)
				}
				if fields["prev"] != prev {
					t.Fatalf("record %d: predecessor = %v, want %s", i, fields["prev"], prev)
				}
				// Hash decoded stored bytes independently of the generator helper.
				sum := sha256.Sum256(payload)
				prev = hex.EncodeToString(sum[:])
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
				} else if invalidSignature && i == 0 {
					if len(sig) != ed25519.SignatureSize || ed25519.Verify(pub, payload, sig) {
						t.Fatal("control must have a full-length invalid signature")
					}
					rec, err := ael.ParseRecordLine(line, "control", i+1)
					if err != nil || rec.LineErr != nil || rec.ParseErr != nil {
						t.Fatalf("invalid-signature control failed parsing: %v, %+v", err, rec)
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
			if c.name == "ael0/valid" || invalidSignature {
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
			if unsigned || invalidSignature {
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
			if invalidSignature && !strings.Contains(result.Checks["a"].Message, "signature verification failed") {
				t.Fatalf("unexpected signature failure: %s", result.Checks["a"].Message)
			}
			if unsigned {
				// The checker rejects syntax before parsing these links. The assertions
				// above establish fixture contents, not checker link validation.
				for _, file := range []string{"manifest.json", "expect.json", "recorders/r1.jsonl"} {
					assertFixtureBytes(t, filepath.Join(dir, file), filepath.Join(corpusFixtureRoot, c.name, file))
				}
			}
		})
	}
	if len(wanted) != 0 {
		t.Fatalf("missing cases: %v", wanted)
	}
}

func assertFixtureBytes(t *testing.T, generated, committed string) {
	t.Helper()
	got, err := os.ReadFile(generated)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("generated fixture differs from %s", committed)
	}
}
