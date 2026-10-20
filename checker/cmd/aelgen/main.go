// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

// Test-only deterministic fixture material. This is not a secret and must never
// be reused outside the public conformance corpus.
var fixtureSeed = []byte("AEL-FIXTURE-TEST-SEED-v1-0000000")

type signedRecord struct {
	payload []byte
	sig     []byte
}

func (r signedRecord) line() string {
	return base64.RawURLEncoding.EncodeToString(r.payload) + "." + base64.RawURLEncoding.EncodeToString(r.sig)
}

type recordPlan struct {
	typ      string
	ts       string
	seq      *int
	extra    map[string]any
	rawPatch func([]byte) []byte
}

type expected struct {
	Grade any               `json:"grade,omitempty"`
	R     string            `json:"r,omitempty"`
	Must  map[string]string `json:"must,omitempty"`
	Runs  []runExpected     `json:"runs,omitempty"`
	Note  string            `json:"note"`
}

type runExpected struct {
	ID    string            `json:"id"`
	Grade any               `json:"grade"`
	R     string            `json:"r"`
	Must  map[string]string `json:"must"`
}

type caseDef struct {
	name            string
	records         []signedRecord
	recorderRecords map[string][]signedRecord
	recorderKeys    map[string]string
	policies        map[string][]byte
	anchors         []byte
	counterparty    []signedRecord
	expect          expected
	publishKeys     bool
	omitKeys        map[string]bool
	badKeyFiles     map[string][]byte
	keys            map[string]ed25519.PublicKey
	manifestExtra   map[string]any
	coverage        string
	custody         string
	govExpect       *govExpectation
	limitScenario   map[string]any
	readme          string
}

// govExpectation is the expected governability output for a fixture, written to
// expect_gov.json and asserted by the governability conformance test.
type govExpectation struct {
	Events    map[string]govEventExpect `json:"events"`
	Coverage  string                    `json:"coverage,omitempty"`
	Gaps      []string                  `json:"gaps,omitempty"`
	Anomalies []string                  `json:"anomalies,omitempty"`
}

type govEventExpect struct {
	Status string `json:"status"`
	Class  string `json:"class"`
}

// version is set by the release build with -ldflags -X. Local source builds
// deliberately identify themselves as development builds.
var version = "devel"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("aelgen %s (%s)\n", releaseVersion(), runtime.Version())
		return
	}
	outDir := flag.String("out", "", "fixture output directory")
	report := flag.Bool("report", false, "run checker over generated fixtures and print a report")
	reportJSON := flag.Bool("json", false, "emit the machine-readable corpus report instead of the human one")
	flag.Parse()
	if *outDir == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: aelgen --out <dir> [--report [--json]]")
		os.Exit(2)
	}
	if *reportJSON && !*report {
		fmt.Fprintln(os.Stderr, "aelgen: --json requires --report")
		os.Exit(2)
	}
	if err := generate(*outDir, *report, *reportJSON); err != nil {
		fmt.Fprintf(os.Stderr, "aelgen: %v\n", err)
		os.Exit(statusForGenerateError(err))
	}
}

func releaseVersion() string {
	if version == "" {
		return "devel"
	}
	return version
}

// statusForGenerateError maps a generate failure onto a process status.
//
// A corpus that disagrees with its expectations is a finding about the corpus.
// A reporter that could not run is a finding about the tool. Collapsing them
// would let a broken run read as a failing corpus and a failing corpus read as
// a broken run, so they get different statuses.
//
// This is a named function rather than an inline branch because it is the
// decision an operator's automation actually reads, and a test that constructs
// the error itself and asserts on its own construction proves nothing about it.
func statusForGenerateError(err error) int {
	if err == nil {
		return 0
	}
	var mismatch *corpusMismatchError
	if errors.As(err, &mismatch) {
		return exitCorpusMismatch
	}
	return 1
}

func generate(outDir string, report, reportJSON bool) error {
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(fixtureSeed)
	pub := priv.Public().(ed25519.PublicKey)
	fp := fingerprint(pub)

	cases, err := buildCases(priv, fp)
	if err != nil {
		return err
	}
	for _, c := range cases {
		if err := writeCase(outDir, c, pub, fp); err != nil {
			return err
		}
	}
	if err := writeCaseManifest(outDir, cases); err != nil {
		return err
	}
	if err := writePackageFixtures(outDir); err != nil {
		return err
	}
	if report {
		result, err := reportCases(outDir, cases, reportOptions{JSON: reportJSON})
		if err != nil {
			return err
		}
		if result.ExitStatus() != 0 {
			return &corpusMismatchError{report: result}
		}
		return nil
	}
	return nil
}

// corpusMismatchError reports a corpus that disagrees with its expectations.
// It is distinct from an ordinary error so the caller can exit with the status
// meaning "the corpus did not conform" rather than "the reporter broke".
type corpusMismatchError struct {
	report CorpusReport
}

func (e *corpusMismatchError) Error() string {
	return fmt.Sprintf("%d of %d corpus cases do not match their expectations", e.report.Mismatched, e.report.Total)
}

type packageFixture struct {
	packageDir    string
	statusPath    string
	statusSigPath string
	recordID      string
}

type packageFixtureStatus struct {
	State          string
	IssuedAt       string
	NextUpdate     string
	EffectiveAt    string
	OmitNextUpdate bool
}

const packageFixtureEvaluationTime = "2026-01-03T12:00:00Z"

func writePackageFixtures(root string) error {
	if _, err := writePackageFixture(root, "valid_verification_record", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	}
	if _, err := writePackageFixture(root, "valid_evaluation_package", "evaluation-package", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	}
	if signedManifest, err := writePackageFixture(root, "manifest_signature_tampered", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifestWithoutSignature(signedManifest.packageDir, func(manifest map[string]any) error {
		manifest["issued_at"] = "2026-01-04T00:00:00Z"
		return nil
	}); err != nil {
		return err
	}
	if carriesGrade, err := writePackageFixture(root, "evaluation_carries_grade", "evaluation-package", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(carriesGrade.packageDir, "package-operator", func(manifest map[string]any) error {
		manifest["grades"] = packageFixtureGrades([]string{"run-ael1-valid"})
		return nil
	}); err != nil {
		return err
	}
	if omittedInput, err := writePackageFixture(root, "undeclared_signer_key", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(omittedInput.packageDir, "package-verifier", func(manifest map[string]any) error {
		_, _, verifierFP := labeledKey("package-verifier")
		want := "inputs/package-keys/" + verifierFP + ".pub"
		inputs, ok := manifest["verification_inputs"].([]any)
		if !ok {
			return fmt.Errorf("fixture verification inputs have wrong type")
		}
		filtered := make([]any, 0, len(inputs))
		for _, value := range inputs {
			blob, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("fixture verification input has wrong type")
			}
			if blob["path"] != want {
				filtered = append(filtered, blob)
			}
		}
		manifest["verification_inputs"] = filtered
		return nil
	}); err != nil {
		return err
	}
	if _, err := writePackageFixture(root, "tampered_blob", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "packages", "tampered_blob", "package", "results", "stdout.txt"), []byte("tampered fixture blob\n"), 0o644); err != nil {
		return err
	}
	if _, err := writePackageFixture(root, "missing_blob", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(root, "packages", "missing_blob", "package", "results", "stderr.txt")); err != nil {
		return err
	}
	if pathEscape, err := writePackageFixture(root, "path_escape", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(pathEscape.packageDir, "package-verifier", func(manifest map[string]any) error {
		files, ok := manifest["files"].([]any)
		if !ok || len(files) == 0 {
			return fmt.Errorf("fixture file manifest is empty")
		}
		first, ok := files[0].(map[string]any)
		if !ok {
			return fmt.Errorf("fixture file entry has wrong type")
		}
		first["path"] = "../escaped"
		return nil
	}); err != nil {
		return err
	}
	for _, kind := range []string{"evaluation-package", "verification-record"} {
		name := strings.ReplaceAll(kind, "-", "_")
		if duplicateFile, err := writePackageFixture(root, "duplicate_file_path_"+name, kind, "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
			return err
		} else if err := rewritePackageManifest(duplicateFile.packageDir, packageFixtureSignerLabel(kind), func(manifest map[string]any) error {
			return duplicatePackageBlob(manifest, "files")
		}); err != nil {
			return err
		}
		if duplicateInput, err := writePackageFixture(root, "duplicate_verification_input_path_"+name, kind, "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
			return err
		} else if err := rewritePackageManifest(duplicateInput.packageDir, packageFixtureSignerLabel(kind), func(manifest map[string]any) error {
			return duplicatePackageBlob(manifest, "verification_inputs")
		}); err != nil {
			return err
		}
	}
	for _, reference := range []struct {
		name   string
		fields []string
	}{
		{name: "artifact_manifest", fields: []string{"artifact_binding", "manifest"}},
		{name: "checker_executable", fields: []string{"checker", "executable"}},
		{name: "machine_output", fields: []string{"artifact_evaluation", "machine_output"}},
		{name: "stdout", fields: []string{"artifact_evaluation", "stdout"}},
		{name: "stderr", fields: []string{"artifact_evaluation", "stderr"}},
		{name: "conformance_result", fields: []string{"conformance", "result"}},
	} {
		fixtureName := "referenced_" + reference.name + "_absent_from_files"
		if fixture, err := writePackageFixture(root, fixtureName, "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
			return err
		} else if err := rewritePackageManifest(fixture.packageDir, "package-verifier", func(manifest map[string]any) error {
			blob, err := packageFixtureBlob(manifest, reference.fields...)
			if err != nil {
				return err
			}
			path, ok := blob["path"].(string)
			if !ok {
				return fmt.Errorf("fixture %s blob has invalid path", reference.name)
			}
			return removePackageFileManifestEntry(manifest, path)
		}); err != nil {
			return err
		}
	}
	if inputAbsent, err := writePackageFixture(root, "verification_input_absent_from_files", "evaluation-package", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(inputAbsent.packageDir, "package-operator", func(manifest map[string]any) error {
		blob, err := firstPackageFixtureVerificationInput(manifest)
		if err != nil {
			return err
		}
		path, ok := blob["path"].(string)
		if !ok {
			return fmt.Errorf("fixture verification input has invalid path")
		}
		return removePackageFileManifestEntry(manifest, path)
	}); err != nil {
		return err
	}
	if inputMismatch, err := writePackageFixture(root, "verification_input_binding_mismatch", "evaluation-package", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(inputMismatch.packageDir, "package-operator", func(manifest map[string]any) error {
		blob, err := firstPackageFixtureVerificationInput(manifest)
		if err != nil {
			return err
		}
		size, ok := blob["size"].(float64)
		if !ok {
			return fmt.Errorf("fixture verification input has invalid size")
		}
		blob["size"] = size + 1
		blob["digest"] = strings.Repeat("0", 64)
		return nil
	}); err != nil {
		return err
	}
	if missingVerifier, err := writePackageFixture(root, "verification_record_missing_verifier", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(missingVerifier.packageDir, "package-verifier", func(manifest map[string]any) error {
		delete(manifest, "verifier")
		return nil
	}); err != nil {
		return err
	}
	if operatorRewrapped, err := writePackageFixture(root, "evaluation_rewrapped_by_operator", "evaluation-package", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if grades, err := packageFixtureGradesForArtifact(operatorRewrapped.packageDir); err != nil {
		return err
	} else if err := rewritePackageManifest(operatorRewrapped.packageDir, "package-operator", func(manifest map[string]any) error {
		_, _, operatorFP := labeledKey("package-operator")
		manifest["kind"] = "verification-record"
		manifest["operator"] = map[string]any{"id": "placeholder-operator"}
		manifest["verifier"] = map[string]any{
			"id": "forged-independent-verifier", "key": operatorFP,
			"relationship_to_producer": "independent", "relationship_to_operator": "independent",
		}
		manifest["grades"] = grades
		return nil
	}); err != nil {
		return err
	}
	if sameProducer, err := writePackageFixture(root, "verifier_is_producer", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(sameProducer.packageDir, "package-verifier", func(manifest map[string]any) error {
		verifier := manifest["verifier"].(map[string]any)
		verifier["id"] = "placeholder-producer"
		return nil
	}); err != nil {
		return err
	}
	if sameOperator, err := writePackageFixture(root, "verifier_is_operator", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(sameOperator.packageDir, "package-verifier", func(manifest map[string]any) error {
		verifier := manifest["verifier"].(map[string]any)
		verifier["id"] = "placeholder-operator"
		return nil
	}); err != nil {
		return err
	}
	if _, err := writePackageFixture(root, "omitted_discovered_run", "verification-record", "multi_run/manifest_omits_bad_run", []string{"run-mixed-a"}, "current"); err != nil {
		return err
	}
	if bindingOmitted, err := writePackageFixture(root, "binding_omits_discovered_run", "verification-record", "multi_run/manifest_omits_bad_run", []string{"run-mixed-a", "run-mixed-b"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(bindingOmitted.packageDir, "package-verifier", func(manifest map[string]any) error {
		binding := manifest["artifact_binding"].(map[string]any)
		binding["discovered_runs"] = []any{"run-mixed-a"}
		return nil
	}); err != nil {
		return err
	}
	if gradeOmitted, err := writePackageFixture(root, "grades_omit_discovered_run", "verification-record", "multi_run/manifest_omits_bad_run", []string{"run-mixed-a", "run-mixed-b"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(gradeOmitted.packageDir, "package-verifier", func(manifest map[string]any) error {
		manifest["grades"] = packageFixtureGrades([]string{"run-mixed-a"})
		return nil
	}); err != nil {
		return err
	}
	if evaluationFailed, err := writePackageFixture(root, "evaluation_failed", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(evaluationFailed.packageDir, "package-verifier", func(manifest map[string]any) error {
		manifest["artifact_evaluation"].(map[string]any)["exit_status"] = 3
		return nil
	}); err != nil {
		return err
	}
	if evaluationOpen, err := writePackageFixture(root, "evaluation_open", "verification-record", "multi_run/mixed", []string{"run-mixed-a", "run-mixed-b"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(evaluationOpen.packageDir, "package-verifier", func(manifest map[string]any) error {
		manifest["artifact_evaluation"].(map[string]any)["exit_status"] = 4
		return nil
	}); err != nil {
		return err
	}
	if conformanceFailed, err := writePackageFixture(root, "conformance_failed", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(conformanceFailed.packageDir, "package-verifier", func(manifest map[string]any) error {
		manifest["conformance"].(map[string]any)["exit_status"] = 1
		return nil
	}); err != nil {
		return err
	}
	if expired, err := writePackageFixture(root, "expired_record", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(expired.packageDir, "package-verifier", func(manifest map[string]any) error {
		manifest["expires_at"] = packageFixtureEvaluationTime
		return nil
	}); err != nil {
		return err
	}
	if emptyCommand, err := writePackageFixture(root, "empty_conformance_command", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(emptyCommand.packageDir, "package-verifier", func(manifest map[string]any) error {
		manifest["conformance"].(map[string]any)["command"] = []any{}
		return nil
	}); err != nil {
		return err
	}
	if gradeMismatch, err := writePackageFixture(root, "grade_disagrees_with_result", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := rewritePackageManifest(gradeMismatch.packageDir, "package-verifier", func(manifest map[string]any) error {
		grade := manifest["grades"].([]any)[0].(map[string]any)
		grade["line"] = "run run-ael1-valid: AEL-3 R-pending (coverage: declared-only; custody: same-process; anchor: none; retention: 30d/fixture)"
		return nil
	}); err != nil {
		return err
	}
	if _, err := writePackageFixture(root, "revoked_replay", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "revoked"); err != nil {
		return err
	}
	if _, err := writePackageFixture(root, "superseded_replay", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "superseded"); err != nil {
		return err
	}
	if err := writeCurrentStatusFixture(root, "status_current_stale", packageFixtureStatus{State: "current", IssuedAt: "2026-01-01T00:00:00Z", NextUpdate: "2026-01-03T00:00:00Z"}); err != nil {
		return err
	}
	if err := writeCurrentStatusFixture(root, "status_current_future_issued_at", packageFixtureStatus{State: "current", IssuedAt: "2026-01-04T00:00:00Z", NextUpdate: "2026-01-05T00:00:00Z"}); err != nil {
		return err
	}
	if err := writeCurrentStatusFixture(root, "status_current_at_issued_at", packageFixtureStatus{State: "current", IssuedAt: packageFixtureEvaluationTime, NextUpdate: "2026-01-04T00:00:00Z"}); err != nil {
		return err
	}
	if err := writeCurrentStatusFixture(root, "status_current_at_next_update", packageFixtureStatus{State: "current", IssuedAt: "2026-01-03T00:00:00Z", NextUpdate: packageFixtureEvaluationTime}); err != nil {
		return err
	}
	if err := writeCurrentStatusFixture(root, "status_current_missing_next_update", packageFixtureStatus{State: "current", IssuedAt: "2026-01-03T00:00:00Z", OmitNextUpdate: true}); err != nil {
		return err
	}
	if err := writeCurrentStatusFixture(root, "status_current_next_update_equals_issued_at", packageFixtureStatus{State: "current", IssuedAt: "2026-01-03T00:00:00Z", NextUpdate: "2026-01-03T00:00:00Z"}); err != nil {
		return err
	}
	if err := writeCurrentStatusFixture(root, "status_current_next_update_before_issued_at", packageFixtureStatus{State: "current", IssuedAt: "2026-01-03T00:00:00Z", NextUpdate: "2026-01-02T23:59:59Z"}); err != nil {
		return err
	}
	if statusSignature, err := writePackageFixture(root, "status_signature_tampered", "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current"); err != nil {
		return err
	} else if err := os.WriteFile(statusSignature.statusSigPath, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"), 0o644); err != nil {
		return err
	}
	return writePackageFixtureExpectations(root)
}

func writePackageFixture(root, name, kind, artifactCase string, discoveredRuns []string, statusState string) (packageFixture, error) {
	fixtureRoot := filepath.Join(root, "packages", name)
	packageDir := filepath.Join(fixtureRoot, "package")
	artifactSource := filepath.Join(root, filepath.FromSlash(artifactCase))
	if err := copyArtifactForPackage(artifactSource, filepath.Join(packageDir, "artifact")); err != nil {
		return packageFixture{}, err
	}
	if err := copyTree(filepath.Join(artifactSource, "keys"), filepath.Join(packageDir, "inputs", "keys")); err != nil {
		return packageFixture{}, err
	}
	operatorPriv, operatorPub, operatorFP := labeledKey("package-operator")
	verifierPriv, verifierPub, verifierFP := labeledKey("package-verifier")
	_, statusPub, statusFP := labeledKey("package-status")
	for fingerprint, pub := range map[string]ed25519.PublicKey{operatorFP: operatorPub, verifierFP: verifierPub, statusFP: statusPub} {
		if err := writeFixturePublicKey(filepath.Join(packageDir, "inputs", "package-keys"), fingerprint, pub); err != nil {
			return packageFixture{}, err
		}
	}
	report, err := writePackageFixtureFiles(packageDir)
	if err != nil {
		return packageFixture{}, err
	}
	files, err := packageFixtureBlobs(packageDir)
	if err != nil {
		return packageFixture{}, err
	}
	byPath := map[string]map[string]any{}
	for _, blob := range files {
		byPath[blob["path"].(string)] = blob
	}
	lookup := func(name string) (map[string]any, error) {
		blob, ok := byPath[name]
		if !ok {
			return nil, fmt.Errorf("fixture blob %q is absent", name)
		}
		return blob, nil
	}
	artifactManifest, err := lookup("artifact/manifest.json")
	if err != nil {
		return packageFixture{}, err
	}
	executable, err := lookup("checker/aelcheck")
	if err != nil {
		return packageFixture{}, err
	}
	machineOutput, err := lookup("results/artifact.json")
	if err != nil {
		return packageFixture{}, err
	}
	stdout, err := lookup("results/stdout.txt")
	if err != nil {
		return packageFixture{}, err
	}
	stderr, err := lookup("results/stderr.txt")
	if err != nil {
		return packageFixture{}, err
	}
	corpusResult, err := lookup("results/conformance.json")
	if err != nil {
		return packageFixture{}, err
	}
	var inputs []any
	for _, blob := range files {
		if strings.HasPrefix(blob["path"].(string), "inputs/") {
			inputs = append(inputs, blob)
		}
	}

	manifest := map[string]any{
		"kind":                 kind,
		"package_format":       1,
		"id":                   "fixture-" + name,
		"run":                  discoveredRuns[0],
		"producer":             map[string]any{"id": "placeholder-producer"},
		"verification_custody": map[string]any{"acquisition": "declared", "replay": "available", "review": "declared", "issuance": "signed"},
		"evidence_coverage":    map[string]any{"scope": "declared", "disclosure": "complete-package"},
		"artifact_binding":     map[string]any{"root": "artifact", "keys_dir": "inputs/keys", "manifest": artifactManifest, "discovered_runs": stringsToAny(discoveredRuns)},
		"files":                mapsToAny(files),
		"verification_inputs":  inputs,
		"spec":                 map[string]any{"version": ael.SpecificationVersion, "digest_algorithm": "sha-256", "digest": shaHex([]byte("fixture specification"))},
		"checker":              map[string]any{"name": "aelcheck", "source_revision": "fixture-revision", "executable": executable},
		"artifact_evaluation":  map[string]any{"arguments": []any{"--json", "artifact"}, "exit_status": 0, "machine_output": machineOutput, "stdout": stdout, "stderr": stderr},
		"conformance":          map[string]any{"corpus": map[string]any{"version": "fixture-corpus", "digest_algorithm": "sha-256", "digest": shaHex([]byte("fixture corpus"))}, "command": []any{"make", "check"}, "exit_status": 0, "result": corpusResult},
		"issued_at":            "2026-01-02T00:00:00Z",
		"status_authority":     map[string]any{"id": "placeholder-status-authority", "key": statusFP, "record_id": "fixture-" + name},
	}
	signer := verifierPriv
	if kind == "evaluation-package" {
		manifest["operator"] = map[string]any{"id": "placeholder-operator", "key": operatorFP}
		signer = operatorPriv
	} else {
		manifest["operator"] = map[string]any{"id": "placeholder-operator"}
		manifest["verifier"] = map[string]any{"id": "placeholder-verifier", "key": verifierFP, "relationship_to_producer": "independent", "relationship_to_operator": "independent"}
		manifest["grades"] = packageFixtureGradesFromReport(report)
	}
	if err := writeSignedPackageManifest(packageDir, manifest, signer); err != nil {
		return packageFixture{}, err
	}

	trustDir := filepath.Join(fixtureRoot, "trust")
	if err := writeFixturePublicKey(filepath.Join(trustDir, "operators"), operatorFP, operatorPub); err != nil {
		return packageFixture{}, err
	}
	if err := writeFixturePublicKey(filepath.Join(trustDir, "verifiers"), verifierFP, verifierPub); err != nil {
		return packageFixture{}, err
	}
	if err := writeFixturePublicKey(filepath.Join(trustDir, "status"), statusFP, statusPub); err != nil {
		return packageFixture{}, err
	}
	statusPath := filepath.Join(fixtureRoot, "status.json")
	statusSigPath := filepath.Join(fixtureRoot, "status.sig")
	if err := writeFixtureStatus(statusPath, statusSigPath, "fixture-"+name, statusState); err != nil {
		return packageFixture{}, err
	}
	return packageFixture{packageDir: packageDir, statusPath: statusPath, statusSigPath: statusSigPath, recordID: "fixture-" + name}, nil
}

func writePackageFixtureFiles(packageDir string) (ael.Report, error) {
	files := map[string][]byte{
		"checker/aelcheck":         []byte("fixture checker executable\n"),
		"inputs/specification.txt": []byte("fixture specification\n"),
		"results/stdout.txt":       []byte("fixture evaluation output\n"),
		"results/stderr.txt":       {},
		"results/conformance.json": []byte("{\"result\":\"pass\"}\n"),
	}
	for name, raw := range files {
		path := filepath.Join(packageDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return ael.Report{}, err
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			return ael.Report{}, err
		}
	}
	artifact, err := ael.LoadArtifact(filepath.Join(packageDir, "artifact"), filepath.Join(packageDir, "inputs", "keys"))
	if err != nil {
		return ael.Report{}, err
	}
	report := ael.Evaluate(artifact)
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return ael.Report{}, err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(packageDir, "results", "artifact.json"), raw, 0o644); err != nil {
		return ael.Report{}, err
	}
	return report, nil
}

func packageFixtureGradesForArtifact(packageDir string) ([]any, error) {
	artifact, err := ael.LoadArtifact(filepath.Join(packageDir, "artifact"), filepath.Join(packageDir, "inputs", "keys"))
	if err != nil {
		return nil, err
	}
	return packageFixtureGradesFromReport(ael.Evaluate(artifact)), nil
}

func packageFixtureGradesFromReport(report ael.Report) []any {
	grades := make([]any, 0, len(report.Runs))
	for _, result := range report.Runs {
		outcomes := make(map[string]any, len(result.Checks))
		for id, outcome := range result.Checks {
			outcomes[id] = outcome.Status
		}
		grades = append(grades, map[string]any{
			"run":         result.Run,
			"line":        result.GradeLine(),
			"annotations": map[string]any{"coverage": result.Coverage, "custody": result.Custody, "anchor": result.Anchor, "retention": result.Retention},
			"outcomes":    outcomes,
		})
	}
	return grades
}

func copyArtifactForPackage(source, target string) error {
	return filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		if rel == "keys" || strings.HasPrefix(filepath.ToSlash(rel), "keys/") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == "expect.json" {
			return nil
		}
		if rel == "." {
			return os.MkdirAll(target, 0o755)
		}
		destination := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		raw, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		return os.WriteFile(destination, raw, 0o644)
	})
}

func copyTree(source, target string) error {
	return filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		destination := target
		if rel != "." {
			destination = filepath.Join(target, rel)
		}
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		raw, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		return os.WriteFile(destination, raw, 0o644)
	})
}

func packageFixtureBlobs(root string) ([]map[string]any, error) {
	var blobs []map[string]any
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if name == "manifest.json" || name == "manifest.sig" {
			return nil
		}
		raw, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		blobs = append(blobs, map[string]any{"path": name, "size": len(raw), "digest_algorithm": "sha-256", "digest": shaHex(raw)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i]["path"].(string) < blobs[j]["path"].(string) })
	return blobs, nil
}

func mapsToAny(items []map[string]any) []any {
	result := make([]any, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	return result
}

func stringsToAny(items []string) []any {
	result := make([]any, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	return result
}

func packageFixtureGrades(runs []string) []any {
	grades := make([]any, 0, len(runs))
	for _, run := range runs {
		grades = append(grades, map[string]any{
			"run":         run,
			"line":        "run " + run + ": AEL-1 R-pending (coverage: declared; custody: declared; anchor: none; retention: fixture)",
			"annotations": map[string]any{"coverage": "declared", "custody": "declared", "anchor": "none", "retention": "fixture"},
			"outcomes":    map[string]any{"a": "PASS"},
		})
	}
	return grades
}

func writeSignedPackageManifest(packageDir string, manifest map[string]any, signer ed25519.PrivateKey) error {
	raw, err := canonicalValue(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(packageDir, "manifest.json"), raw, 0o644); err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(signer, raw))
	return os.WriteFile(filepath.Join(packageDir, "manifest.sig"), []byte(sig+"\n"), 0o644)
}

func rewritePackageManifest(packageDir, signerLabel string, change func(map[string]any) error) error {
	raw, err := os.ReadFile(filepath.Join(packageDir, "manifest.json"))
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if err := change(manifest); err != nil {
		return err
	}
	priv, _, _ := labeledKey(signerLabel)
	return writeSignedPackageManifest(packageDir, manifest, priv)
}

func rewritePackageManifestWithoutSignature(packageDir string, change func(map[string]any) error) error {
	raw, err := os.ReadFile(filepath.Join(packageDir, "manifest.json"))
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if err := change(manifest); err != nil {
		return err
	}
	raw, err = canonicalValue(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(packageDir, "manifest.json"), raw, 0o644)
}

func packageFixtureSignerLabel(kind string) string {
	if kind == "evaluation-package" {
		return "package-operator"
	}
	return "package-verifier"
}

func duplicatePackageBlob(manifest map[string]any, field string) error {
	values, ok := manifest[field].([]any)
	if !ok || len(values) == 0 {
		return fmt.Errorf("fixture %s is empty or has wrong type", field)
	}
	first, ok := values[0].(map[string]any)
	if !ok {
		return fmt.Errorf("fixture %s entry has wrong type", field)
	}
	duplicate := make(map[string]any, len(first)+1)
	for key, value := range first {
		duplicate[key] = value
	}
	duplicate["url"] = "https://example.invalid/duplicate"
	manifest[field] = append(values, duplicate)
	return nil
}

func packageFixtureBlob(manifest map[string]any, fields ...string) (map[string]any, error) {
	var current any = manifest
	for _, field := range fields {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("fixture package field %q has wrong type", field)
		}
		var exists bool
		current, exists = object[field]
		if !exists {
			return nil, fmt.Errorf("fixture package field %q is absent", field)
		}
	}
	blob, ok := current.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("fixture package blob has wrong type")
	}
	return blob, nil
}

func firstPackageFixtureVerificationInput(manifest map[string]any) (map[string]any, error) {
	inputs, ok := manifest["verification_inputs"].([]any)
	if !ok || len(inputs) == 0 {
		return nil, fmt.Errorf("fixture verification inputs are empty or have wrong type")
	}
	blob, ok := inputs[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("fixture verification input has wrong type")
	}
	return blob, nil
}

func removePackageFileManifestEntry(manifest map[string]any, path string) error {
	files, ok := manifest["files"].([]any)
	if !ok {
		return fmt.Errorf("fixture files have wrong type")
	}
	filtered := make([]any, 0, len(files)-1)
	removed := false
	for _, value := range files {
		blob, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("fixture file entry has wrong type")
		}
		if blob["path"] == path {
			removed = true
			continue
		}
		filtered = append(filtered, blob)
	}
	if !removed {
		return fmt.Errorf("fixture file %q is absent", path)
	}
	manifest["files"] = filtered
	return nil
}

func writeFixturePublicKey(root, fingerprint string, pub ed25519.PublicKey) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, fingerprint+".pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

func writeCurrentStatusFixture(root, name string, status packageFixtureStatus) error {
	fixture, err := writePackageFixture(root, name, "verification-record", "ael1/valid", []string{"run-ael1-valid"}, "current")
	if err != nil {
		return err
	}
	return writeFixtureStatusDefinition(fixture.statusPath, fixture.statusSigPath, fixture.recordID, status)
}

func writeFixtureStatus(path, signaturePath, recordID, state string) error {
	status := packageFixtureStatus{
		State:       state,
		IssuedAt:    "2026-01-03T00:00:00Z",
		NextUpdate:  "2026-01-04T00:00:00Z",
		EffectiveAt: "2026-01-03T00:00:00Z",
	}
	return writeFixtureStatusDefinition(path, signaturePath, recordID, status)
}

func writeFixtureStatusDefinition(path, signaturePath, recordID string, definition packageFixtureStatus) error {
	priv, _, _ := labeledKey("package-status")
	status := map[string]any{
		"status_format": 1,
		"record_id":     recordID,
		"authority":     "placeholder-status-authority",
		"issued_at":     definition.IssuedAt,
		"state":         definition.State,
	}
	if definition.State == "current" && !definition.OmitNextUpdate {
		status["next_update"] = definition.NextUpdate
	}
	if definition.State != "current" {
		status["effective_at"] = definition.EffectiveAt
	}
	if definition.State == "revoked" {
		status["reason"] = "fixture revocation"
	}
	if definition.State == "superseded" {
		status["reason"] = "fixture supersession"
		status["replacement"] = recordID + "-replacement"
	}
	raw, err := canonicalValue(status)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
	return os.WriteFile(signaturePath, []byte(sig+"\n"), 0o644)
}

func writePackageFixtureExpectations(root string) error {
	expected := map[string]map[string]string{
		"valid_verification_record":                             {"display_state": "VERIFIED"},
		"valid_evaluation_package":                              {"display_state": "EVALUATED"},
		"manifest_signature_tampered":                           {"diagnostic": "package manifest signature verification failed"},
		"evaluation_carries_grade":                              {"diagnostic": "unknown top-level key \"grades\""},
		"undeclared_signer_key":                                 {"diagnostic": "package signer public key is absent from verification inputs"},
		"tampered_blob":                                         {"diagnostic": "blob \"results/stdout.txt\" size or digest mismatch"},
		"missing_blob":                                          {"diagnostic": "required blob \"results/stderr.txt\" is missing"},
		"path_escape":                                           {"diagnostic": "file manifest entry path: must be a normalized relative path"},
		"duplicate_file_path_evaluation_package":                {"diagnostic": "file manifest lists \"artifact/manifest.json\" more than once"},
		"duplicate_file_path_verification_record":               {"diagnostic": "file manifest lists \"artifact/manifest.json\" more than once"},
		"duplicate_verification_input_path_evaluation_package":  {"diagnostic": "verification inputs list \"inputs/keys/edee7ef9e19355528cf038dace72095337ef76feebcf2aad1d2c71130cb08066.pub\" more than once"},
		"duplicate_verification_input_path_verification_record": {"diagnostic": "verification inputs list \"inputs/keys/edee7ef9e19355528cf038dace72095337ef76feebcf2aad1d2c71130cb08066.pub\" more than once"},
		"referenced_artifact_manifest_absent_from_files":        {"diagnostic": "referenced blob \"artifact/manifest.json\" is absent from file manifest"},
		"referenced_checker_executable_absent_from_files":       {"diagnostic": "referenced blob \"checker/aelcheck\" is absent from file manifest"},
		"referenced_machine_output_absent_from_files":           {"diagnostic": "referenced blob \"results/artifact.json\" is absent from file manifest"},
		"referenced_stdout_absent_from_files":                   {"diagnostic": "referenced blob \"results/stdout.txt\" is absent from file manifest"},
		"referenced_stderr_absent_from_files":                   {"diagnostic": "referenced blob \"results/stderr.txt\" is absent from file manifest"},
		"referenced_conformance_result_absent_from_files":       {"diagnostic": "referenced blob \"results/conformance.json\" is absent from file manifest"},
		"verification_input_absent_from_files":                  {"diagnostic": "referenced blob \"inputs/keys/edee7ef9e19355528cf038dace72095337ef76feebcf2aad1d2c71130cb08066.pub\" is absent from file manifest"},
		"verification_input_binding_mismatch":                   {"diagnostic": "referenced blob \"inputs/keys/edee7ef9e19355528cf038dace72095337ef76feebcf2aad1d2c71130cb08066.pub\" does not match file manifest"},
		"verification_record_missing_verifier":                  {"diagnostic": "missing required top-level key \"verifier\""},
		"evaluation_rewrapped_by_operator":                      {"diagnostic": "missing trusted package signer key"},
		"verifier_is_producer":                                  {"diagnostic": "verifier must not equal producer"},
		"verifier_is_operator":                                  {"diagnostic": "verifier must not equal operator"},
		"omitted_discovered_run":                                {"diagnostic": "artifact binding discovered runs"},
		"binding_omits_discovered_run":                          {"diagnostic": "artifact binding discovered runs"},
		"grades_omit_discovered_run":                            {"diagnostic": "verification record grades do not cover every discovered run"},
		"evaluation_failed":                                     {"display_state": "EVALUATION-FAILED"},
		"evaluation_open":                                       {"display_state": "EVALUATION-OPEN"},
		"conformance_failed":                                    {"display_state": "CONFORMANCE-FAILED"},
		"expired_record":                                        {"display_state": "EXPIRED"},
		"empty_conformance_command":                             {"diagnostic": "conformance command must not be empty"},
		"grade_disagrees_with_result":                           {"diagnostic": "disagrees with artifact evaluation machine output"},
		"revoked_replay":                                        {"display_state": "REVOKED"},
		"superseded_replay":                                     {"display_state": "SUPERSEDED"},
		"status_current_stale":                                  {"display_state": "STATUS-UNKNOWN"},
		"status_current_future_issued_at":                       {"display_state": "STATUS-UNKNOWN"},
		"status_current_at_issued_at":                           {"display_state": "VERIFIED"},
		"status_current_at_next_update":                         {"display_state": "STATUS-UNKNOWN"},
		"status_current_missing_next_update":                    {"display_state": "STATUS-UNKNOWN"},
		"status_current_next_update_equals_issued_at":           {"display_state": "STATUS-UNKNOWN"},
		"status_current_next_update_before_issued_at":           {"display_state": "STATUS-UNKNOWN"},
		"status_signature_tampered":                             {"display_state": "STATUS-UNKNOWN"},
	}
	for name, value := range expected {
		raw, err := canonicalValue(value)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, "packages", name, "package-expect.json"), raw, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func buildCases(priv ed25519.PrivateKey, fp string) ([]caseDef, error) {
	pub := priv.Public().(ed25519.PublicKey)
	rec2Priv, rec2Pub, rec2FP := labeledKey("recorder-2")
	rec3Priv, rec3Pub, rec3FP := labeledKey("recorder-3")
	logPriv, logPub, logFP := labeledKey("log-key")
	cpPriv, cpPub, cpFP := labeledKey("counterparty")

	ael0Valid, err := buildRecords(priv, "run-ael0-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael0Unsigned, err := buildRecords(priv, "run-ael0-unsigned-hash-chain", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	for i := range ael0Unsigned {
		ael0Unsigned[i].sig = nil
	}

	ael0Four, err := buildRecords(priv, "run-ael0-perturb", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:15Z"),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael1Valid, err := buildRecords(priv, "run-ael1-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		activity("2026-01-01T00:00:20Z", "net", "evt-2", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael1HeartbeatDeleted, err := buildRecords(priv, "run-ael1-heartbeat-deleted", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		activity("2026-01-01T00:00:20Z", "net", "evt-2", "out", nil, nil),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	policyHash, policyRaw, err := policyFixture()
	if err != nil {
		return nil, err
	}
	decision := map[string]any{
		"policy":     policyHash,
		"request_fp": "req-r-valid",
		"inputs":     map[string]any{"risk": 7, "kind": "egress"},
		"verdict":    "block",
	}
	rValid, err := buildRecords(priv, "run-r-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", decision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	badDecision := cloneMap(decision)
	badDecision["verdict"] = "allow"
	rMismatch, err := buildRecords(priv, "run-r-mismatch", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", badDecision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	seqTwo := 2
	seqThree := 3
	seqGap, err := buildRecords(priv, "run-ael1-seq-gap", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		{typ: "activity", ts: "2026-01-01T00:00:10Z", seq: &seqTwo, extra: eventExtra("net", "evt-1", "out", nil)},
		{typ: "close", ts: "2026-01-01T00:00:20Z", seq: &seqThree},
	})
	if err != nil {
		return nil, err
	}
	heartbeatGap, err := buildRecords(priv, "run-ael1-heartbeat-gap", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:02:00Z", "net", "evt-1", "out", nil, nil),
		closePlan("2026-01-01T00:02:10Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	nonmonotonicTS, err := buildRecords(priv, "run-ael1-nonmonotonic-ts", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:05Z"),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	wrongCount := 4
	tailTruncated, err := buildRecords(priv, "run-ael1-tail-truncated", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		closePlan("2026-01-01T00:00:20Z", &wrongCount, ""),
	})
	if err != nil {
		return nil, err
	}
	noClose, err := buildRecords(priv, "run-ael1-no-close", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
	})
	if err != nil {
		return nil, err
	}

	byteflip := cloneRecords(ael0Valid)
	byteflip[1].payload = append([]byte(nil), byteflip[1].payload...)
	byteflip[1].payload[1] = 'x'

	transpose := cloneRecords(ael0Four)
	transpose[1], transpose[2] = transpose[2], transpose[1]

	interiorDel := append(cloneRecords(ael0Four[:1]), cloneRecords(ael0Four[2:])...)

	noncanonical, err := buildRecords(priv, "run-ael0-noncanonical", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, prettyPatch),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	dupKey, err := buildRecords(priv, "run-ael0-dupkey", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, dupVPatch),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	unknownField, err := buildRecords(priv, "run-ael1-unknown-field-rejected", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		{typ: "close", ts: "2026-01-01T00:00:40Z", extra: map[string]any{"unexpected": "signed-but-unknown"}},
	})
	if err != nil {
		return nil, err
	}
	extField, err := buildRecords(priv, "run-ael1-ext-field-accepted", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		{typ: "close", ts: "2026-01-01T00:00:40Z", extra: map[string]any{"ext": map[string]any{"fixture": "reserved"}}},
	})
	if err != nil {
		return nil, err
	}
	extEventOnly, err := buildRecords(priv, "run-ael1-required-event-missing", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		{typ: "activity", ts: "2026-01-01T00:00:10Z", extra: map[string]any{"ext": map[string]any{"event": map[string]any{"class": "net", "id": "evt-1", "dir": "out"}}}},
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	ael2R1, err := buildRecords(priv, "run-ael2-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael2R2, err := buildRecords(rec2Priv, "run-ael2-valid", "r2", rec2FP, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	oneSideR2, err := buildRecords(rec2Priv, "run-ael2-valid", "r2", rec2FP, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	sameKeyR2, err := buildRecords(priv, "run-ael2-valid", "r2", fp, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	sameKeyR3, err := buildRecords(priv, "run-ael2-valid", "r3", fp, []recordPlan{
		open("2026-01-01T00:00:02Z", 60, 5),
		activity("2026-01-01T00:00:12Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:32Z"),
		closePlan("2026-01-01T00:00:42Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	thirdOmitR3, err := buildRecords(rec3Priv, "run-ael2-valid", "r3", rec3FP, []recordPlan{
		open("2026-01-01T00:00:02Z", 60, 5),
		heartbeat("2026-01-01T00:00:32Z"),
		closePlan("2026-01-01T00:00:42Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	ael3Anchor, err := buildAnchors("test-log", logPriv, map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2})
	if err != nil {
		return nil, err
	}
	ael3NoncanonicalTreeHead, err := noncanonicalTreeHeadSigned(ael3Anchor, logPriv)
	if err != nil {
		return nil, err
	}
	ael3RecorderKeyAnchor, err := buildAnchors("test-log", priv, map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2})
	if err != nil {
		return nil, err
	}
	ael3PrefixAnchor, err := buildAnchors("test-log", logPriv, map[string][]signedRecord{"r1": ael2R1[:3], "r2": ael2R2[:3]})
	if err != nil {
		return nil, err
	}
	badInclusion, err := corruptFirstProof(ael3Anchor)
	if err != nil {
		return nil, err
	}
	altHistoryR1, err := buildRecords(priv, "run-ael2-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	cpNonce := "fixture-cp-nonce-ael4"
	ael4Decision := map[string]any{
		"policy":     policyHash,
		"request_fp": "req-ael4-valid",
		"inputs":     map[string]any{"risk": 7, "kind": "egress"},
		"verdict":    "block",
	}
	ael4R1, err := buildRecords(priv, "run-ael4-valid", "r1", fp, []recordPlan{
		openNonce("2026-01-01T00:00:00Z", 60, 5, cpNonce),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", ael4Decision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael4R2, err := buildRecords(rec2Priv, "run-ael4-valid", "r2", rec2FP, []recordPlan{
		openNonce("2026-01-01T00:00:01Z", 60, 5, cpNonce),
		activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", ael4Decision, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael4R2WrongNonce, err := buildRecords(rec2Priv, "run-ael4-valid", "r2", rec2FP, []recordPlan{
		openNonce("2026-01-01T00:00:01Z", 60, 5, "fixture-cp-nonce-other"),
		activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", ael4Decision, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael4Anchor, err := buildAnchors("test-log", logPriv, map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2})
	if err != nil {
		return nil, err
	}
	ael4NonceMismatchAnchor, err := buildAnchors("test-log", logPriv, map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2WrongNonce})
	if err != nil {
		return nil, err
	}
	cpValid, err := buildCounterparty(cpPriv, "run-ael4-valid", cpNonce, "net", "evt-1")
	if err != nil {
		return nil, err
	}
	cpWrongRun, err := buildCounterparty(cpPriv, "run-other", "other-nonce", "net", "evt-1")
	if err != nil {
		return nil, err
	}
	cpUnrecorded, err := buildCounterparty(cpPriv, "run-ael4-valid", cpNonce, "net", "evt-missing")
	if err != nil {
		return nil, err
	}
	cpRecorderKey, err := buildCounterparty(priv, "run-ael4-valid", cpNonce, "net", "evt-1")
	if err != nil {
		return nil, err
	}
	ael4NoneR1, err := buildRecords(priv, "run-ael4-none", "r1", fp, []recordPlan{
		openNonce("2026-01-01T00:00:00Z", 60, 5, cpNonce),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael4NoneR2, err := buildRecords(rec2Priv, "run-ael4-none", "r2", rec2FP, []recordPlan{
		openNonce("2026-01-01T00:00:01Z", 60, 5, cpNonce),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael4NoneAnchor, err := buildAnchors("test-log", logPriv, map[string][]signedRecord{"r1": ael4NoneR1, "r2": ael4NoneR2})
	if err != nil {
		return nil, err
	}
	cpNone, err := buildCounterpartyNone(cpPriv, "run-ael4-none", cpNonce, "net")
	if err != nil {
		return nil, err
	}
	cpEmpty, err := buildCounterpartyEmpty(cpPriv, "run-ael4-valid", cpNonce, "net")
	if err != nil {
		return nil, err
	}

	mixedA1, err := buildRecords(priv, "run-mixed-a", "r1a", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-a", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	mixedA2, err := buildRecords(rec2Priv, "run-mixed-a", "r2a", rec2FP, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		activity("2026-01-01T00:00:11Z", "net", "evt-a", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	mixedB1, err := buildRecords(priv, "run-mixed-b", "r1b", fp, []recordPlan{
		open("2026-01-01T01:00:00Z", 60, 5),
		activity("2026-01-01T01:00:10Z", "net", "evt-b", "out", nil, nil),
	})
	if err != nil {
		return nil, err
	}
	mixedB2, err := buildRecords(rec2Priv, "run-mixed-b", "r2b", rec2FP, []recordPlan{
		open("2026-01-01T01:00:01Z", 60, 5),
		activity("2026-01-01T01:00:11Z", "net", "evt-b", "out", nil, nil),
	})
	if err != nil {
		return nil, err
	}

	ael2Extra := map[string]any{"correspondence": map[string]any{"classes": []any{"net"}, "match": "id"}}
	ael2EmptyClassesExtra := map[string]any{"correspondence": map[string]any{"classes": []any{}, "match": "id"}}
	ael3Extra := cloneAnyMap(ael2Extra)
	ael3Extra["anchor"] = map[string]any{"log": "test-log", "log_key": logFP, "file": "anchors.json"}
	ael3RecorderKeyExtra := cloneAnyMap(ael2Extra)
	ael3RecorderKeyExtra["anchor"] = map[string]any{"log": "test-log", "log_key": fp, "file": "anchors.json"}
	ael3LogKeyForgeryExtra := cloneAnyMap(ael2Extra)
	ael3LogKeyForgeryExtra["anchor"] = map[string]any{"log": "test-log", "log_key": fp, "file": "anchors.json"}
	ael4Extra := cloneAnyMap(ael3Extra)
	ael4Extra["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{"net"}, "key": cpFP}
	ael4EmptyFlowsExtra := cloneAnyMap(ael3Extra)
	ael4EmptyFlowsExtra["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{}, "key": cpFP}
	ael4RecorderKeyExtra := cloneAnyMap(ael3Extra)
	ael4RecorderKeyExtra["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{"net"}, "key": fp}
	mixedOmitRunExtra := cloneAnyMap(ael2Extra)
	mixedOmitRunExtra["runs"] = []any{"run-mixed-a"}
	multiKeys := map[string]ed25519.PublicKey{fp: pub, rec2FP: rec2Pub}
	threeKeys := map[string]ed25519.PublicKey{fp: pub, rec2FP: rec2Pub, rec3FP: rec3Pub}
	anchoredKeys := map[string]ed25519.PublicKey{fp: pub, rec2FP: rec2Pub, logFP: logPub}
	ael4Keys := map[string]ed25519.PublicKey{fp: pub, rec2FP: rec2Pub, logFP: logPub, cpFP: cpPub}

	// governability extension fixtures
	govPolicyHash, govPolicyRaw, err := govPolicyFixture()
	if err != nil {
		return nil, err
	}
	govTamperedPolicyRaw, err := canonicalValue(map[string]any{
		"v":       1,
		"rules":   []any{},
		"default": "allow",
		"reversibility": map[string]any{
			"pay": "reversible",
			"net": "reversible",
		},
	})
	if err != nil {
		return nil, err
	}
	govDecision := map[string]any{"policy": govPolicyHash, "request_fp": "fp-gov", "inputs": map[string]any{}, "verdict": "allow"}
	govPolicyBound, err := buildRecords(priv, "run-gov-policy-bound", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "pay", "evt-1", "out", govDecision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	govDeclared, err := buildRecords(priv, "run-gov-declared", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		govActivity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, "reversible"),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	govUnclassified, err := buildRecords(priv, "run-gov-unclassified", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	govDowngrade, err := buildRecords(priv, "run-gov-downgrade", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		govActivity("2026-01-01T00:00:10Z", "pay", "evt-1", "out", govDecision, "reversible"),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	govScopedPlan := []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		govActivity("2026-01-01T00:00:20Z", "pay", "evt-2", "out", nil, "irreversible"),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:50Z", nil, ""),
	}
	govScopedR1, err := buildRecords(priv, "run-gov-scoped-out", "r1", fp, govScopedPlan)
	if err != nil {
		return nil, err
	}
	govScopedR2, err := buildRecords(rec2Priv, "run-gov-scoped-out", "r2", rec2FP, govScopedPlan)
	if err != nil {
		return nil, err
	}

	// governability merge worst-case: two recorders, same event id, POLICY-BOUND
	// reversible on one and UNCLASSIFIED irreversible on the other. The merge must
	// keep the irreversible worst case, which then trips the coverage GAP because
	// the manifest's correspondence.classes deliberately omits the event class.
	govMergeR1, err := buildRecords(priv, "run-gov-merge-worstcase", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", govDecision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	govMergeR2, err := buildRecords(rec2Priv, "run-gov-merge-worstcase", "r2", rec2FP, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	govMergeCorr := map[string]any{"correspondence": map[string]any{"classes": []any{"dns"}, "match": "id"}}

	// round-2 governability fixtures

	// (a) empty/absent decision.policy with an agent-declared reversible class.
	// DECLARED reports the declared class but MUST NOT lower the coverage gate:
	// the event class is left out of correspondence.classes so the invariant fires
	// a GAP even though the declared class is reversible. This is the exact
	// empty-policy bypass the invariant closes.
	govDeclaredNoLowerR1, err := buildRecords(priv, "run-gov-declared-no-lower", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		govActivity("2026-01-01T00:00:10Z", "pay", "evt-1", "out", nil, "reversible"),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	govDeclaredNoLowerR2, err := buildRecords(rec2Priv, "run-gov-declared-no-lower", "r2", rec2FP, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		govActivity("2026-01-01T00:00:11Z", "pay", "evt-1", "out", nil, "reversible"),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	// (b) POLICY-SILENT: a hash-verified policy that is silent on the event class.
	govSilentHash, govSilentRaw, err := govSilentPolicyFixture()
	if err != nil {
		return nil, err
	}
	govSilentDecision := map[string]any{"policy": govSilentHash, "request_fp": "fp-gov-silent", "inputs": map[string]any{}, "verdict": "allow"}
	govPolicySilent, err := buildRecords(priv, "run-gov-policy-silent", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "dns", "evt-1", "out", govSilentDecision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	// (c) POLICY-INVALID via an out-of-vocabulary policy value.
	govInvalidHash, govInvalidRaw, err := govInvalidValuePolicyFixture()
	if err != nil {
		return nil, err
	}
	govInvalidDecision := map[string]any{"policy": govInvalidHash, "request_fp": "fp-gov-invalid", "inputs": map[string]any{}, "verdict": "allow"}
	govPolicyInvalidValue, err := buildRecords(priv, "run-gov-policy-invalid-value", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", govInvalidDecision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	// (d) UNASSESSABLE with a recoverable class: schema-invalid activity record
	// (unknown top-level key) that still verifies at the rung. The event id and
	// class are recovered, so it is reported UNASSESSABLE gated irreversible and
	// its class is checked against correspondence (left out -> GAP).
	govUnassessableRecoverable, err := buildRecords(priv, "run-gov-unassessable-recoverable", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		schemaInvalidActivity("2026-01-01T00:00:10Z", "pay", "evt-1", "out"),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	// (e) UNASSESSABLE with an unrecoverable class: schema-invalid activity whose
	// event object omits class, so the run's coverage becomes UNASSESSABLE.
	govUnassessableUnrecoverable, err := buildRecords(priv, "run-gov-unassessable-unrecoverable", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		schemaInvalidNoClassActivity("2026-01-01T00:00:10Z", "evt-1", "out"),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	// (f) DUPLICATE-ID-CLASS-CONFLICT: two recorders, same event id, different
	// event.class. The duty covers the union of classes and raises the anomaly.
	govConflictR1, err := buildRecords(priv, "run-gov-dup-id-conflict", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	govConflictR2, err := buildRecords(rec2Priv, "run-gov-dup-id-conflict", "r2", rec2FP, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		activity("2026-01-01T00:00:11Z", "pay", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	// correspondence covers both classes so the union is fully covered; the anomaly
	// must still be raised even though coverage is OK.
	govConflictCorr := map[string]any{"correspondence": map[string]any{"classes": []any{"net", "pay"}, "match": "id"}}

	bornWrong, err := buildRecords(priv, "run-limit-born-wrong", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		fixtureActivity("2026-01-01T00:00:10Z", "tool", "tool-write-1", "internal", map[string]any{
			"kind": "tool_result",
			"tool": "write_file",
			"result": map[string]any{
				"path":            "/work/report.txt",
				"write_succeeded": false,
				"error":           "permission denied",
			},
		}),
		fixtureActivity("2026-01-01T00:00:20Z", "report", "report-1", "out", map[string]any{
			"kind": "agent_claim",
			"claim": map[string]any{
				"path":            "/work/report.txt",
				"write_succeeded": true,
			},
		}),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	selfConfirmation, err := buildRecords(priv, "run-limit-self-confirmation", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		fixtureActivity("2026-01-01T00:00:10Z", "report", "status-write-1", "internal", map[string]any{
			"kind":                    "agent_authored_status",
			"path":                    "/work/status.json",
			"status":                  "healthy",
			"independently_confirmed": false,
		}),
		fixtureActivity("2026-01-01T00:00:20Z", "tool", "status-read-1", "internal", map[string]any{
			"kind":   "read_back",
			"path":   "/work/status.json",
			"status": "healthy",
			"source": "same_agent",
		}),
		fixtureActivity("2026-01-01T00:00:30Z", "report", "report-1", "out", map[string]any{
			"kind": "agent_claim",
			"claim": map[string]any{
				"path":                    "/work/status.json",
				"independently_confirmed": true,
				"status":                  "healthy",
			},
		}),
		heartbeat("2026-01-01T00:00:40Z"),
		closePlan("2026-01-01T00:00:50Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	return []caseDef{
		{name: "ael0/valid", records: ael0Valid, expect: expect(0, "pending", map[string]string{"a": "PASS", "b": "PASS", "d": "PASS", "e": "PASS", "h": "PASS"})},
		{name: "ael0/byteflip", records: byteflip, expect: expect("ungraded", "pending", map[string]string{"a": "FAIL"})},
		{name: "ael0/transpose", records: transpose, expect: expect("ungraded", "pending", map[string]string{"d": "FAIL", "e": "FAIL"})},
		{name: "ael0/interior_del", records: interiorDel, expect: expect("ungraded", "pending", map[string]string{"d": "PASS", "e": "FAIL"})},
		{name: "ael0/noncanonical", records: noncanonical, expect: expect("ungraded", "pending", map[string]string{"b": "FAIL"})},
		{name: "ael0/dupkey", records: dupKey, expect: expect("ungraded", "pending", map[string]string{"b": "FAIL"})},
		{
			name: "ael0/unsigned_hash_chain", records: ael0Unsigned,
			omitKeys: map[string]bool{fp: true}, coverage: "declared-only", custody: "same-process",
			expect: expected{
				Runs: []runExpected{{ID: "run-ael0-unsigned-hash-chain", Grade: "ungraded", R: "pending", Must: map[string]string{"a": "FAIL"}}},
				Note: "Synthetic in-process records have coherent SHA-256 payload links, empty signature segments, and no published key. Empty signatures fail the compact record syntax before payload parsing or key lookup. This case doesn't establish checker validation of the links or support for external unsigned JSONL formats.",
			},
		},
		{name: "ael0/unpublished_key", records: ael0Valid, publishKeys: false, expect: expect("ungraded", "pending", map[string]string{"a": "UV"})},
		{name: "ael0/bad_key_length", records: ael0Valid, badKeyFiles: map[string][]byte{fp: []byte(base64.StdEncoding.EncodeToString([]byte("short")) + "\n")}, expect: expect("ungraded", "pending", map[string]string{"a": "UV"})},
		{name: "ael0/tail_truncated_silent", records: ael0Valid[:2], expect: expect(0, "pending", map[string]string{"a": "PASS", "b": "PASS", "d": "PASS", "e": "PASS"})},
		{name: "ael1/valid", records: ael1Valid, expect: expect(1, "pending", map[string]string{"f": "PASS", "g": "PASS", "h": "PASS", "i": "PASS"})},
		{name: "ael1/heartbeat_deleted", records: ael1HeartbeatDeleted, expect: expect(0, "pending", map[string]string{"h": "FAIL"})},
		{name: "ael1/seq_gap", records: seqGap, expect: expect(0, "pending", map[string]string{"g": "FAIL"})},
		{name: "ael1/heartbeat_gap", records: heartbeatGap, expect: expect(0, "pending", map[string]string{"h": "FAIL"})},
		{name: "ael1/nonmonotonic_ts", records: nonmonotonicTS, expect: expect(0, "pending", map[string]string{"h": "FAIL"})},
		{name: "ael1/tail_truncated", records: tailTruncated, expect: expect(0, "pending", map[string]string{"i": "FAIL"})},
		{name: "ael1/no_close", records: noClose, expect: expect(0, "pending", map[string]string{"j": "FAIL"})},
		{name: "ael1/unknown_field_rejected", records: unknownField, expect: expect("ungraded", "pending", map[string]string{"w": "FAIL"})},
		{name: "ael1/ext_field_accepted", records: extField, expect: expect(1, "pending", map[string]string{"w": "PASS"})},
		{name: "ael1/required_event_missing", records: extEventOnly, expect: expect("ungraded", "pending", map[string]string{"w": "FAIL"})},
		{name: "r/valid", records: rValid, policies: map[string][]byte{policyHash: policyRaw}, expect: expect(1, "+R", map[string]string{"R": "PASS"})},
		{name: "r/verdict_mismatch", records: rMismatch, policies: map[string][]byte{policyHash: policyRaw}, expect: expect(1, "fail", map[string]string{"R": "FAIL"})},
		{name: "ael2/valid", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"k": "PASS", "l": "PASS", "m": "PASS"})},
		{name: "ael2/manifest_key_forgery", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": sameKeyR2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"l": "FAIL"})},
		{name: "ael2/empty_classes", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2EmptyClassesExtra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"m": "UV"})},
		{name: "ael2/one_side_deleted", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": oneSideR2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"m": "FAIL"})},
		{name: "ael2/same_key", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": sameKeyR2}, recorderKeys: map[string]string{"r1": fp, "r2": fp}, keys: map[string]ed25519.PublicKey{fp: pub}, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"l": "FAIL"})},
		{name: "ael2/third_recorder_shares_key", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2, "r3": sameKeyR3}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP, "r3": fp}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"l": "FAIL"})},
		{name: "ael2/third_recorder_omits_event", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2, "r3": thirdOmitR3}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP, "r3": rec3FP}, keys: threeKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"m": "FAIL"})},
		{name: "ael3/valid", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael3Anchor, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(3, "pending", map[string]string{"n": "PASS", "o": "PASS", "p": "PASS", "q": "PASS", "u": "PASS"})},
		{name: "ael3/treehead_noncanonical_signed", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael3NoncanonicalTreeHead, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "FAIL"})},
		{name: "ael3/bad_inclusion", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: badInclusion, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"o": "FAIL"})},
		{name: "ael3/alt_history", recorderRecords: map[string][]signedRecord{"r1": altHistoryR1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael3Anchor, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"p": "FAIL"})},
		{name: "ael3/no_logkey", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, omitKeys: map[string]bool{logFP: true}, anchors: ael3Anchor, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "UV"})},
		{name: "ael3/no_anchors_file", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "UV", "o": "UV", "p": "UV", "q": "UV"})},
		{name: "ael3/logkey_not_independent", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, anchors: ael3RecorderKeyAnchor, manifestExtra: ael3RecorderKeyExtra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "PASS", "o": "PASS", "p": "PASS", "u": "FAIL"})},
		{name: "ael3/logkey_forgery", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": "", "r2": rec2FP}, keys: multiKeys, anchors: ael3RecorderKeyAnchor, manifestExtra: ael3LogKeyForgeryExtra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"l": "PASS", "n": "PASS", "u": "FAIL"})},
		{name: "ael3/unanchored_tail", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael3PrefixAnchor, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "PASS", "o": "PASS", "p": "PASS", "q": "FAIL", "u": "PASS"})},
		{name: "ael4/valid", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpValid, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(4, "+R", map[string]string{"r": "PASS", "s": "PASS", "t": "PASS", "v": "PASS", "R": "PASS"})},
		{name: "ael4/counterparty_none", recorderRecords: map[string][]signedRecord{"r1": ael4NoneR1, "r2": ael4NoneR2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4NoneAnchor, counterparty: cpNone, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(4, "pending", map[string]string{"r": "PASS", "s": "PASS", "t": "PASS", "v": "PASS"})},
		{name: "ael4/counterparty_empty_statement", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpEmpty, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"s": "FAIL"})},
		{name: "ael4/wrong_run_confirmation", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpWrongRun, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"s": "FAIL"})},
		{name: "ael4/cp_nonce_mismatch", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2WrongNonce}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4NonceMismatchAnchor, counterparty: cpValid, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"s": "FAIL"})},
		{name: "ael4/no_counterparty_file", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"r": "UV", "s": "UV", "t": "UV"})},
		{name: "ael4/unrecorded_delivery", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpUnrecorded, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"t": "FAIL"})},
		{name: "ael4/empty_flows", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpValid, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4EmptyFlowsExtra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"t": "UV"})},
		{name: "ael4/cp_key_not_independent", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael4Anchor, counterparty: cpRecorderKey, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4RecorderKeyExtra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"r": "PASS", "s": "PASS", "t": "PASS", "v": "FAIL"})},
		{name: "multi_run/mixed", recorderRecords: map[string][]signedRecord{"r1a": mixedA1, "r2a": mixedA2, "r1b": mixedB1, "r2b": mixedB2}, recorderKeys: map[string]string{"r1a": fp, "r2a": rec2FP, "r1b": fp, "r2b": rec2FP}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expectRuns([]runExpected{
			{ID: "run-mixed-a", Grade: 2, R: "pending", Must: map[string]string{"k": "PASS", "l": "PASS", "m": "PASS"}},
			{ID: "run-mixed-b", Grade: 0, R: "pending", Must: map[string]string{"j": "FAIL"}},
		})},
		{name: "multi_run/manifest_omits_bad_run", recorderRecords: map[string][]signedRecord{"r1a": mixedA1, "r2a": mixedA2, "r1b": mixedB1, "r2b": mixedB2}, recorderKeys: map[string]string{"r1a": fp, "r2a": rec2FP, "r1b": fp, "r2b": rec2FP}, keys: multiKeys, manifestExtra: mixedOmitRunExtra, coverage: "enforced-total", custody: "same-operator", expect: expectRuns([]runExpected{
			{ID: "run-mixed-a", Grade: 2, R: "pending", Must: map[string]string{"k": "PASS", "l": "PASS", "m": "PASS"}},
			{ID: "run-mixed-b", Grade: 0, R: "pending", Must: map[string]string{"j": "FAIL"}},
		})},
		{
			name: "limits/born_wrong_tool_result", records: bornWrong,
			expect: expect(1, "pending", map[string]string{"a": "PASS", "b": "PASS", "d": "PASS", "e": "PASS", "f": "PASS", "g": "PASS", "h": "PASS", "i": "PASS", "w": "PASS"}),
			limitScenario: map[string]any{
				"case":         "limits/born_wrong_tool_result",
				"ground_truth": map[string]any{"write_succeeded": false},
				"contradicting_evidence": []any{
					map[string]any{"event_id": "tool-write-1", "fact": "write_succeeded", "value": false},
					map[string]any{"event_id": "tool-write-1", "fact": "path", "value": "/work/report.txt"},
				},
				"recorded_claim": []any{
					map[string]any{"event_id": "report-1", "fact": "write_succeeded", "value": true},
					map[string]any{"event_id": "report-1", "fact": "path", "value": "/work/report.txt"},
				},
				"bound_facts":    []any{"path"},
				"expected_grade": 1,
				"interpretation": "AEL verifies that the signed claim was recorded intact; it does not make the claim true.",
			},
			// Pins that the fixture narrative in ext.fixture carries no governability
			// meaning. ext.gov is a graded sub-namespace; ext.fixture must never
			// become one by accident.
			govExpect: &govExpectation{
				Events: map[string]govEventExpect{
					"tool-write-1": {Status: "UNCLASSIFIED", Class: "irreversible"},
					"report-1":     {Status: "UNCLASSIFIED", Class: "irreversible"},
				},
				Coverage: "N/A",
			},
		},
		{
			name: "limits/self_referential_confirmation", records: selfConfirmation,
			expect: expect(1, "pending", map[string]string{"a": "PASS", "b": "PASS", "d": "PASS", "e": "PASS", "f": "PASS", "g": "PASS", "h": "PASS", "i": "PASS", "w": "PASS"}),
			limitScenario: map[string]any{
				"case":         "limits/self_referential_confirmation",
				"ground_truth": map[string]any{"independently_confirmed": false},
				"contradicting_evidence": []any{
					map[string]any{"event_id": "status-write-1", "fact": "independently_confirmed", "value": false},
					map[string]any{"event_id": "status-write-1", "fact": "path", "value": "/work/status.json"},
					map[string]any{"event_id": "status-read-1", "fact": "source", "value": "same_agent"},
					map[string]any{"event_id": "status-read-1", "fact": "path", "value": "/work/status.json"},
				},
				"recorded_claim": []any{
					map[string]any{"event_id": "report-1", "fact": "independently_confirmed", "value": true},
					map[string]any{"event_id": "report-1", "fact": "path", "value": "/work/status.json"},
				},
				"bound_facts":    []any{"path"},
				"expected_grade": 1,
				"interpretation": "Reading back an agent-authored status file is not independent confirmation, even when the read and claim are faithfully recorded.",
			},
			govExpect: &govExpectation{
				Events: map[string]govEventExpect{
					"status-write-1": {Status: "UNCLASSIFIED", Class: "irreversible"},
					"status-read-1":  {Status: "UNCLASSIFIED", Class: "irreversible"},
					"report-1":       {Status: "UNCLASSIFIED", Class: "irreversible"},
				},
				Coverage: "N/A",
			},
		},
		{name: "gov/policy_bound", records: govPolicyBound, policies: map[string][]byte{govPolicyHash: govPolicyRaw}, expect: expect(1, "+R", map[string]string{"R": "PASS"}), govExpect: &govExpectation{Events: map[string]govEventExpect{"evt-1": {Status: "POLICY-BOUND", Class: "irreversible"}}, Coverage: "N/A"}},
		{name: "gov/declared", records: govDeclared, expect: expect(1, "pending", map[string]string{"f": "PASS", "w": "PASS"}), govExpect: &govExpectation{Events: map[string]govEventExpect{"evt-1": {Status: "DECLARED", Class: "reversible"}}, Coverage: "N/A"}},
		{name: "gov/unclassified", records: govUnclassified, expect: expect(1, "pending", map[string]string{"f": "PASS"}), govExpect: &govExpectation{Events: map[string]govEventExpect{"evt-1": {Status: "UNCLASSIFIED", Class: "irreversible"}}, Coverage: "N/A"}},
		{name: "gov/downgrade", records: govDowngrade, policies: map[string][]byte{govPolicyHash: govPolicyRaw}, expect: expect(1, "+R", map[string]string{"R": "PASS"}), govExpect: &govExpectation{Events: map[string]govEventExpect{"evt-1": {Status: "POLICY-BOUND", Class: "irreversible"}}, Coverage: "N/A"}},
		{name: "gov/hash_mismatch", records: govPolicyBound, policies: map[string][]byte{govPolicyHash: govTamperedPolicyRaw}, expect: expect(1, "fail", map[string]string{"R": "FAIL"}), govExpect: &govExpectation{Events: map[string]govEventExpect{"evt-1": {Status: "POLICY-INVALID", Class: "irreversible"}}, Coverage: "N/A"}},
		{name: "gov/missing_policy", records: govDowngrade, expect: expect(1, "fail", map[string]string{"R": "FAIL"}), govExpect: &govExpectation{Events: map[string]govEventExpect{"evt-1": {Status: "POLICY-INVALID", Class: "irreversible"}}, Coverage: "N/A"}},
		{name: "gov/irreversible_scoped_out", recorderRecords: map[string][]signedRecord{"r1": govScopedR1, "r2": govScopedR2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"k": "PASS", "l": "PASS", "m": "PASS"}), govExpect: &govExpectation{Events: map[string]govEventExpect{"evt-1": {Status: "UNCLASSIFIED", Class: "irreversible"}, "evt-2": {Status: "DECLARED", Class: "irreversible"}}, Coverage: "GAP", Gaps: []string{"evt-2"}}},
		{
			name:            "gov/merge_worstcase",
			recorderRecords: map[string][]signedRecord{"r1": govMergeR1, "r2": govMergeR2},
			recorderKeys:    map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys,
			policies:      map[string][]byte{govPolicyHash: govPolicyRaw},
			manifestExtra: govMergeCorr, coverage: "enforced-total", custody: "same-operator",
			expect: expect(2, "pending", map[string]string{"k": "PASS", "l": "PASS", "m": "PASS", "R": "UV"}),
			readme: "<!-- SPDX-License-Identifier: Apache-2.0 -->\n\n# gov/merge_worstcase\n\n" +
				"Two independent recorders report the same event. One classifies it as POLICY-BOUND " +
				"reversible; the other leaves it UNCLASSIFIED and therefore irreversible. The merged " +
				"result must keep the irreversible worst case and report a coverage GAP.\n",
			govExpect: &govExpectation{
				Events:   map[string]govEventExpect{"evt-1": {Status: "UNCLASSIFIED", Class: "irreversible"}},
				Coverage: "GAP", Gaps: []string{"evt-1"},
			},
		},
		{
			name:            "gov/declared_no_lower",
			recorderRecords: map[string][]signedRecord{"r1": govDeclaredNoLowerR1, "r2": govDeclaredNoLowerR2},
			recorderKeys:    map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys,
			manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator",
			expect: expect(2, "pending", map[string]string{"k": "PASS", "l": "PASS", "m": "PASS"}),
			govExpect: &govExpectation{
				Events:   map[string]govEventExpect{"evt-1": {Status: "DECLARED", Class: "reversible"}},
				Coverage: "GAP", Gaps: []string{"evt-1"},
			},
		},
		{
			name: "gov/policy_silent", records: govPolicySilent, policies: map[string][]byte{govSilentHash: govSilentRaw},
			expect: expect(1, "+R", map[string]string{"R": "PASS"}),
			govExpect: &govExpectation{
				Events:   map[string]govEventExpect{"evt-1": {Status: "POLICY-SILENT", Class: "irreversible"}},
				Coverage: "N/A",
			},
		},
		{
			name: "gov/policy_invalid_value", records: govPolicyInvalidValue, policies: map[string][]byte{govInvalidHash: govInvalidRaw},
			expect: expect(1, "+R", map[string]string{"R": "PASS"}),
			govExpect: &govExpectation{
				Events:   map[string]govEventExpect{"evt-1": {Status: "POLICY-INVALID", Class: "irreversible"}},
				Coverage: "N/A",
			},
		},
		{
			name:            "gov/unassessable_recoverable",
			recorderRecords: map[string][]signedRecord{"r1": govUnassessableRecoverable},
			recorderKeys:    map[string]string{"r1": fp}, keys: map[string]ed25519.PublicKey{fp: pub},
			manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator",
			expect: expect("ungraded", "pending", map[string]string{"w": "FAIL"}),
			govExpect: &govExpectation{
				Events:   map[string]govEventExpect{"evt-1": {Status: "UNASSESSABLE", Class: "irreversible"}},
				Coverage: "GAP", Gaps: []string{"evt-1"},
			},
		},
		{
			name:            "gov/unassessable_unrecoverable",
			recorderRecords: map[string][]signedRecord{"r1": govUnassessableUnrecoverable},
			recorderKeys:    map[string]string{"r1": fp}, keys: map[string]ed25519.PublicKey{fp: pub},
			manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator",
			expect: expect("ungraded", "pending", map[string]string{"w": "FAIL"}),
			govExpect: &govExpectation{
				Events:   map[string]govEventExpect{"evt-1": {Status: "UNASSESSABLE", Class: "irreversible"}},
				Coverage: "UNASSESSABLE",
			},
		},
		{
			name:            "gov/dup_id_class_conflict",
			recorderRecords: map[string][]signedRecord{"r1": govConflictR1, "r2": govConflictR2},
			recorderKeys:    map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys,
			manifestExtra: govConflictCorr, coverage: "enforced-total", custody: "same-operator",
			expect: expect(2, "pending", map[string]string{"k": "PASS", "l": "PASS", "m": "PASS"}),
			govExpect: &govExpectation{
				Events:    map[string]govEventExpect{"evt-1": {Status: "UNCLASSIFIED", Class: "irreversible"}},
				Coverage:  "OK",
				Anomalies: []string{"DUPLICATE-ID-CLASS-CONFLICT: evt-1"},
			},
		},
	}, nil
}

func expect(grade any, r string, must map[string]string) expected {
	return expected{Grade: grade, R: r, Must: must, Note: ""}
}

func expectRuns(runs []runExpected) expected {
	return expected{Runs: runs, Note: ""}
}

// writeCaseManifest records the exact set of cases the generator emitted. The
// conformance suite asserts the on-disk corpus matches this list, so a case can
// never leave the corpus without the removal showing up as a diff here.
func writeCaseManifest(root string, cases []caseDef) error {
	names := make([]string, 0, len(cases))
	govNames := make([]string, 0)
	for _, c := range cases {
		names = append(names, c.name)
		if c.govExpect != nil {
			govNames = append(govNames, c.name)
		}
	}
	if err := writeManifest(root, "CASES.txt", names); err != nil {
		return err
	}
	return writeManifest(root, "GOV-CASES.txt", govNames)
}

func writeManifest(root, filename string, names []string) error {
	sort.Strings(names)
	body := strings.Join(names, "\n") + "\n"
	return os.WriteFile(filepath.Join(root, filename), []byte(body), 0o644)
}

func writeCase(root string, c caseDef, pub ed25519.PublicKey, fp string) error {
	caseDir := filepath.Join(root, filepath.FromSlash(c.name))
	if err := os.MkdirAll(filepath.Join(caseDir, "recorders"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(caseDir, "keys"), 0o755); err != nil {
		return err
	}
	if len(c.policies) > 0 {
		if err := os.MkdirAll(filepath.Join(caseDir, "policy"), 0o755); err != nil {
			return err
		}
		for hash, raw := range c.policies {
			if err := os.WriteFile(filepath.Join(caseDir, "policy", hash+".json"), raw, 0o644); err != nil {
				return err
			}
		}
	}
	if len(c.anchors) > 0 {
		if err := os.WriteFile(filepath.Join(caseDir, "anchors.json"), c.anchors, 0o644); err != nil {
			return err
		}
	}
	if len(c.counterparty) > 0 {
		var lines []string
		for _, stmt := range c.counterparty {
			lines = append(lines, stmt.line())
		}
		if err := os.WriteFile(filepath.Join(caseDir, "counterparty.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}

	keys := c.keys
	if len(keys) == 0 {
		keys = map[string]ed25519.PublicKey{fp: pub}
	}
	publishKeys := c.publishKeys || c.name != "ael0/unpublished_key"
	if publishKeys {
		keyFPs := make([]string, 0, len(keys))
		for keyFP := range keys {
			keyFPs = append(keyFPs, keyFP)
		}
		sort.Strings(keyFPs)
		for _, keyFP := range keyFPs {
			if c.omitKeys[keyFP] {
				continue
			}
			raw := []byte(base64.StdEncoding.EncodeToString(keys[keyFP]) + "\n")
			if override, ok := c.badKeyFiles[keyFP]; ok {
				raw = override
			}
			if err := os.WriteFile(filepath.Join(caseDir, "keys", keyFP+".pub"), raw, 0o644); err != nil {
				return err
			}
		}
	}

	recorderRecords := c.recorderRecords
	if len(recorderRecords) == 0 {
		recorderRecords = map[string][]signedRecord{"r1": c.records}
	}
	recorderIDs := make([]string, 0, len(recorderRecords))
	for recorderID := range recorderRecords {
		recorderIDs = append(recorderIDs, recorderID)
	}
	sort.Strings(recorderIDs)
	for _, recorderID := range recorderIDs {
		var lines []string
		for _, rec := range recorderRecords[recorderID] {
			lines = append(lines, rec.line())
		}
		if err := os.WriteFile(filepath.Join(caseDir, "recorders", recorderID+".jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}

	defaultRun := "run-" + strings.ReplaceAll(strings.ReplaceAll(c.name, "/", "-"), "_", "-")
	recorderRuns := map[string]string{}
	var runs []any
	seenRuns := map[string]bool{}
	for _, recorderID := range recorderIDs {
		records := recorderRecords[recorderID]
		run := defaultRun
		if len(records) == 0 {
			recorderRuns[recorderID] = run
		} else {
			var payload ael.Payload
			_ = json.Unmarshal(records[0].payload, &payload)
			if payload.Run != "" {
				run = payload.Run
			}
			recorderRuns[recorderID] = run
		}
		if !seenRuns[run] {
			seenRuns[run] = true
			runs = append(runs, run)
		}
	}

	recorderEntries := make([]any, 0, len(recorderIDs))
	for _, recorderID := range recorderIDs {
		keyFP, ok := c.recorderKeys[recorderID]
		if !ok {
			keyFP = fp
		}
		recorderEntries = append(recorderEntries, map[string]any{
			"id": recorderID, "run": recorderRuns[recorderID], "key": keyFP, "file": "recorders/" + recorderID + ".jsonl",
		})
	}
	coverage := c.coverage
	if coverage == "" {
		coverage = "declared-only"
	}
	custody := c.custody
	if custody == "" {
		custody = "same-process"
	}
	manifestMap := map[string]any{
		"ael_format":   ael.ArtifactFormatVersion,
		"claimed_rung": claimedExpectedRung(c.expect),
		"coverage":     coverage,
		"custody":      custody,
		"retention":    map[string]any{"period_days": 30, "custody": "fixture"},
		"runs":         runs,
		"recorders":    recorderEntries,
	}
	for k, v := range c.manifestExtra {
		manifestMap[k] = v
	}
	manifest, err := canonicalValue(manifestMap)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(caseDir, "manifest.json"), manifest, 0o644); err != nil {
		return err
	}
	exp := c.expect
	if len(exp.Runs) == 0 {
		runID := ""
		if len(runs) > 0 {
			runID, _ = runs[0].(string)
		}
		exp.Runs = []runExpected{{ID: runID, Grade: exp.Grade, R: exp.R, Must: exp.Must}}
		exp.Grade = nil
		exp.R = ""
		exp.Must = nil
	}
	expectRaw, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(caseDir, "expect.json"), append(expectRaw, '\n'), 0o644); err != nil {
		return err
	}
	if c.govExpect != nil {
		govRaw, err := json.MarshalIndent(c.govExpect, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(caseDir, "expect_gov.json"), append(govRaw, '\n'), 0o644); err != nil {
			return err
		}
	}
	if c.limitScenario != nil {
		scenarioRaw, err := json.MarshalIndent(c.limitScenario, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(caseDir, "scenario.json"), append(scenarioRaw, '\n'), 0o644); err != nil {
			return err
		}
	}
	if c.readme != "" {
		if err := os.WriteFile(filepath.Join(caseDir, "README.md"), []byte(c.readme), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func buildRecords(priv ed25519.PrivateKey, run, recorder, fp string, plans []recordPlan) ([]signedRecord, error) {
	var out []signedRecord
	prev := zeroHash()
	for i, plan := range plans {
		seq := i
		if plan.seq != nil {
			seq = *plan.seq
		}
		payload := map[string]any{
			"v":        1,
			"type":     plan.typ,
			"run":      run,
			"recorder": recorder,
			"key":      fp,
			"seq":      seq,
			"prev":     prev,
			"ts":       plan.ts,
		}
		for k, v := range plan.extra {
			payload[k] = v
		}
		if plan.typ == "close" {
			if _, ok := payload["count"]; !ok {
				payload["count"] = len(plans)
			}
			if _, ok := payload["head"]; !ok {
				payload["head"] = prev
			}
		}
		raw, err := canonicalValue(payload)
		if err != nil {
			return nil, err
		}
		if plan.rawPatch != nil {
			raw = plan.rawPatch(raw)
		}
		sig := ed25519.Sign(priv, raw)
		out = append(out, signedRecord{payload: raw, sig: sig})
		prev = shaHex(raw)
	}
	return out, nil
}

func open(ts string, hmax, htol int) recordPlan {
	return recordPlan{typ: "open", ts: ts, extra: map[string]any{"hmax": hmax, "htol": htol}}
}

func openNonce(ts string, hmax, htol int, nonce string) recordPlan {
	return recordPlan{typ: "open", ts: ts, extra: map[string]any{"hmax": hmax, "htol": htol, "cp_nonce": nonce}}
}

func activity(ts, class, id, dir string, decision map[string]any, patch func([]byte) []byte) recordPlan {
	return recordPlan{typ: "activity", ts: ts, extra: eventExtra(class, id, dir, decision), rawPatch: patch}
}

func fixtureActivity(ts, class, id, dir string, fixture map[string]any) recordPlan {
	extra := eventExtra(class, id, dir, nil)
	extra["ext"] = map[string]any{"fixture": fixture}
	return recordPlan{typ: "activity", ts: ts, extra: extra}
}

func heartbeat(ts string) recordPlan {
	return recordPlan{typ: "heartbeat", ts: ts}
}

func closePlan(ts string, count *int, head string) recordPlan {
	extra := map[string]any{}
	if count != nil {
		extra["count"] = *count
	}
	if head != "" {
		extra["head"] = head
	}
	return recordPlan{typ: "close", ts: ts, extra: extra}
}

func eventExtra(class, id, dir string, decision map[string]any) map[string]any {
	extra := map[string]any{"event": map[string]any{"class": class, "id": id, "dir": dir}}
	if decision != nil {
		extra["decision"] = decision
	}
	return extra
}

func policyFixture() (string, []byte, error) {
	raw, err := canonicalValue(map[string]any{
		"v": 1,
		"rules": []any{map[string]any{
			"when":    map[string]any{"field": "risk", "op": "gte", "value": 5},
			"verdict": "block",
		}},
		"default": "allow",
	})
	if err != nil {
		return "", nil, err
	}
	return shaHex(raw), raw, nil
}

// govPolicyFixture is a policy that also carries a reversibility map keyed by
// event class. The base checker ignores the extra field (R still re-derives from
// rules/default); the governability duty reads the map and reports POLICY-BOUND,
// because the map is part of the signed, hash-referenced policy bytes.
func govPolicyFixture() (string, []byte, error) {
	raw, err := canonicalValue(map[string]any{
		"v":       1,
		"rules":   []any{},
		"default": "allow",
		"reversibility": map[string]any{
			"pay": "irreversible",
			"net": "reversible",
		},
	})
	if err != nil {
		return "", nil, err
	}
	return shaHex(raw), raw, nil
}

// govActivity is an activity plan that also carries an agent-declared
// reversibility class under the reserved, signed ext.gov namespace.
func govActivity(ts, class, id, dir string, decision map[string]any, declared string) recordPlan {
	extra := eventExtra(class, id, dir, decision)
	extra["ext"] = map[string]any{"gov": map[string]any{"declared_reversibility": declared}}
	return recordPlan{typ: "activity", ts: ts, extra: extra}
}

// govSilentPolicyFixture is a hash-verified policy that carries a reversibility
// map, but one that is silent on the event class used by the POLICY-SILENT
// fixture (it maps only "pay", while that fixture's event class is "dns"). The
// governability duty must report POLICY-SILENT and gate irreversible.
func govSilentPolicyFixture() (string, []byte, error) {
	raw, err := canonicalValue(map[string]any{
		"v":             1,
		"rules":         []any{},
		"default":       "allow",
		"reversibility": map[string]any{"pay": "reversible"},
	})
	if err != nil {
		return "", nil, err
	}
	return shaHex(raw), raw, nil
}

// govInvalidValuePolicyFixture is a hash-verified policy whose reversibility map
// assigns an out-of-vocabulary value to the event class. The class is already
// irreversible; the status must be POLICY-INVALID, not a mislabeled POLICY-BOUND.
func govInvalidValuePolicyFixture() (string, []byte, error) {
	raw, err := canonicalValue(map[string]any{
		"v":             1,
		"rules":         []any{},
		"default":       "allow",
		"reversibility": map[string]any{"net": "maybe-reversible"},
	})
	if err != nil {
		return "", nil, err
	}
	return shaHex(raw), raw, nil
}

// schemaInvalidActivity is an activity plan carrying an unknown top-level key.
// The bytes are still signed and canonical, so the record verifies at the rung
// (signature + canonical) but fails schema validation. The event id and class
// remain recoverable, so the governability duty reports UNASSESSABLE gated
// irreversible rather than dropping the record.
func schemaInvalidActivity(ts, class, id, dir string) recordPlan {
	extra := eventExtra(class, id, dir, nil)
	extra["surprise"] = "unknown-top-level-key"
	return recordPlan{typ: "activity", ts: ts, extra: extra}
}

// schemaInvalidNoClassActivity is a schema-invalid activity record whose event
// object omits the required class. Neither schema validation nor class recovery
// can succeed, so the run's coverage becomes UNASSESSABLE.
func schemaInvalidNoClassActivity(ts, id, dir string) recordPlan {
	extra := map[string]any{"event": map[string]any{"id": id, "dir": dir}}
	return recordPlan{typ: "activity", ts: ts, extra: extra}
}

func buildAnchors(logID string, logPriv ed25519.PrivateKey, logs map[string][]signedRecord) ([]byte, error) {
	var recorderIDs []string
	for recorderID := range logs {
		recorderIDs = append(recorderIDs, recorderID)
	}
	sort.Strings(recorderIDs)
	var entries []ael.AnchorEntry
	var leaves [][]byte
	index := 0
	for _, recorderID := range recorderIDs {
		for seq, rec := range logs[recorderID] {
			leaf := merkleLeaf(rec.payload)
			leaves = append(leaves, leaf)
			entries = append(entries, ael.AnchorEntry{
				Recorder: recorderID,
				Run:      recordRun(rec),
				Seq:      seq,
				Leaf:     hex.EncodeToString(leaf),
				Index:    index,
			})
			index++
		}
	}
	root := merkleRoot(leaves)
	proofs := merkleProofs(leaves)
	for i := range entries {
		for _, node := range proofs[i] {
			entries[i].Proof = append(entries[i].Proof, hex.EncodeToString(node))
		}
	}
	headMsg, err := canonicalValue(map[string]any{"log": logID, "root": hex.EncodeToString(root), "size": len(leaves)})
	if err != nil {
		return nil, err
	}
	anchors := map[string]any{
		"log": logID,
		"tree_head": map[string]any{
			"size":   len(leaves),
			"root":   hex.EncodeToString(root),
			"signed": base64.StdEncoding.EncodeToString(headMsg),
			"sig":    base64.StdEncoding.EncodeToString(ed25519.Sign(logPriv, headMsg)),
		},
		"entries": anchorEntriesValue(entries),
	}
	return canonicalValue(anchors)
}

func noncanonicalTreeHeadSigned(raw []byte, logPriv ed25519.PrivateKey) ([]byte, error) {
	var anchors ael.Anchors
	if err := json.Unmarshal(raw, &anchors); err != nil {
		return nil, err
	}
	headMsg := []byte(fmt.Sprintf("{\n  \"log\": %q,\n  \"root\": %q,\n  \"size\": %d\n}", anchors.Log, anchors.TreeHead.Root, anchors.TreeHead.Size))
	return canonicalValue(map[string]any{
		"log": anchors.Log,
		"tree_head": map[string]any{
			"size":   anchors.TreeHead.Size,
			"root":   anchors.TreeHead.Root,
			"signed": base64.StdEncoding.EncodeToString(headMsg),
			"sig":    base64.StdEncoding.EncodeToString(ed25519.Sign(logPriv, headMsg)),
		},
		"entries": anchorEntriesValue(anchors.Entries),
	})
}

func anchorEntriesValue(entries []ael.AnchorEntry) []any {
	out := make([]any, 0, len(entries))
	for _, entry := range entries {
		proof := make([]any, 0, len(entry.Proof))
		for _, item := range entry.Proof {
			proof = append(proof, item)
		}
		out = append(out, map[string]any{
			"recorder": entry.Recorder,
			"run":      entry.Run,
			"seq":      entry.Seq,
			"leaf":     entry.Leaf,
			"index":    entry.Index,
			"proof":    proof,
		})
	}
	return out
}

func corruptFirstProof(raw []byte) ([]byte, error) {
	var anchors ael.Anchors
	if err := json.Unmarshal(raw, &anchors); err != nil {
		return nil, err
	}
	if len(anchors.Entries) == 0 || len(anchors.Entries[0].Proof) == 0 {
		return nil, fmt.Errorf("anchor has no proof to corrupt")
	}
	anchors.Entries[0].Proof[0] = strings.Repeat("f", 64)
	return canonicalValue(map[string]any{
		"log":       anchors.Log,
		"tree_head": map[string]any{"size": anchors.TreeHead.Size, "root": anchors.TreeHead.Root, "signed": anchors.TreeHead.Signed, "sig": anchors.TreeHead.Sig},
		"entries":   anchorEntriesValue(anchors.Entries),
	})
}

func buildCounterparty(priv ed25519.PrivateKey, run, nonce, flow, eventID string) ([]signedRecord, error) {
	raw, err := canonicalValue(map[string]any{
		"v":        1,
		"type":     "received",
		"run":      run,
		"flow":     flow,
		"nonce":    nonce,
		"received": map[string]any{"event_id": eventID},
	})
	if err != nil {
		return nil, err
	}
	return []signedRecord{{payload: raw, sig: ed25519.Sign(priv, raw)}}, nil
}

func buildCounterpartyNone(priv ed25519.PrivateKey, run, nonce, flow string) ([]signedRecord, error) {
	raw, err := canonicalValue(map[string]any{
		"v":     1,
		"type":  "received",
		"run":   run,
		"flow":  flow,
		"nonce": nonce,
		"none":  true,
	})
	if err != nil {
		return nil, err
	}
	return []signedRecord{{payload: raw, sig: ed25519.Sign(priv, raw)}}, nil
}

func buildCounterpartyEmpty(priv ed25519.PrivateKey, run, nonce, flow string) ([]signedRecord, error) {
	raw, err := canonicalValue(map[string]any{
		"v":     1,
		"type":  "received",
		"run":   run,
		"flow":  flow,
		"nonce": nonce,
	})
	if err != nil {
		return nil, err
	}
	return []signedRecord{{payload: raw, sig: ed25519.Sign(priv, raw)}}, nil
}

func canonicalValue(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return ael.Canonicalize(raw)
}

func prettyPatch(raw []byte) []byte {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return raw
	}
	return buf.Bytes()
}

func dupVPatch(raw []byte) []byte {
	out := append([]byte(nil), raw[:len(raw)-1]...)
	out = append(out, []byte(`,"v":1}`)...)
	return out
}

func cloneRecords(in []signedRecord) []signedRecord {
	out := make([]signedRecord, len(in))
	for i, rec := range in {
		out[i] = signedRecord{payload: append([]byte(nil), rec.payload...), sig: append([]byte(nil), rec.sig...)}
	}
	return out
}

func cloneMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAnyMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func labeledKey(label string) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	seed := sha256.Sum256([]byte("AEL-FIXTURE-TEST-SEED-v1:" + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, fingerprint(pub)
}

func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func shaHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func zeroHash() string {
	return strings.Repeat("0", 64)
}

func recordRun(rec signedRecord) string {
	var payload ael.Payload
	_ = json.Unmarshal(rec.payload, &payload)
	return payload.Run
}

func merkleLeaf(raw []byte) []byte {
	sum := sha256.Sum256(append([]byte{0x00}, raw...))
	return sum[:]
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		sum := sha256.Sum256(nil)
		return sum[:]
	}
	if len(leaves) == 1 {
		return append([]byte(nil), leaves[0]...)
	}
	split := largestPowerOfTwoLessThan(len(leaves))
	return merkleNode(merkleRoot(leaves[:split]), merkleRoot(leaves[split:]))
}

func merkleProofs(leaves [][]byte) [][][]byte {
	proofs := make([][][]byte, len(leaves))
	for i := range leaves {
		proofs[i] = merkleProof(leaves, i)
	}
	return proofs
}

func merkleProof(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	split := largestPowerOfTwoLessThan(len(leaves))
	if index < split {
		return append(merkleProof(leaves[:split], index), merkleRoot(leaves[split:]))
	}
	return append(merkleProof(leaves[split:], index-split), merkleRoot(leaves[:split]))
}

func merkleNode(left, right []byte) []byte {
	buf := make([]byte, 0, 1+len(left)+len(right))
	buf = append(buf, 0x01)
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

func largestPowerOfTwoLessThan(n int) int {
	p := 1
	for p<<1 < n {
		p <<= 1
	}
	return p
}

func claimedRung(grade any) int {
	if n, ok := grade.(int); ok {
		return n
	}
	return 0
}

func claimedExpectedRung(exp expected) int {
	if len(exp.Runs) == 0 {
		return claimedRung(exp.Grade)
	}
	max := 0
	for _, run := range exp.Runs {
		if n := claimedRung(run.Grade); n > max {
			max = n
		}
	}
	return max
}

// CorpusReport is the machine-readable conformance result. A package carries
// this file as its conformance evidence, so it has to state the outcome in the
// artifact itself rather than only on the terminal.
type CorpusReport struct {
	CorpusFormat int          `json:"corpus_format"`
	Total        int          `json:"total"`
	Matched      int          `json:"matched"`
	Mismatched   int          `json:"mismatched"`
	Cases        []CorpusCase `json:"cases"`
}

type CorpusCase struct {
	Name     string          `json:"name"`
	Match    bool            `json:"match"`
	Expected string          `json:"expected"`
	Runs     []CorpusCaseRun `json:"runs"`
}

type CorpusCaseRun struct {
	Run   string `json:"run"`
	Grade string `json:"grade"`
	R     string `json:"r"`
}

// ExitStatus separates a corpus that disagrees with its expectations from a
// reporter that could not run. They are different findings and they need
// different responses, so they must not share a status.
func (r CorpusReport) ExitStatus() int {
	if r.Mismatched > 0 {
		return exitCorpusMismatch
	}
	return 0
}

const exitCorpusMismatch = 3

type reportOptions struct {
	JSON bool
	Out  io.Writer
}

// reportCases grades every corpus case against its expectation.
//
// It returns an error only when the report could not be produced. A case that
// disagrees with its expectation is a RESULT, carried in the returned report
// and its exit status. Previously this function computed that verdict, printed
// it, and returned nil either way, so a corpus with a failing case exited 0 and
// any automation reading the status saw success.
func reportCases(root string, cases []caseDef, options reportOptions) (CorpusReport, error) {
	out := options.Out
	if out == nil {
		out = os.Stdout
	}
	result := CorpusReport{CorpusFormat: 1}
	for _, c := range cases {
		caseDir := filepath.Join(root, filepath.FromSlash(c.name))
		art, err := ael.LoadArtifact(caseDir, filepath.Join(caseDir, "keys"))
		if err != nil {
			return CorpusReport{}, err
		}
		report := ael.Evaluate(art)
		ok := compareExpected(report, c.expect)

		entry := CorpusCase{Name: c.name, Match: ok, Expected: reportExpected(c.expect)}
		for _, res := range report.Runs {
			entry.Runs = append(entry.Runs, CorpusCaseRun{Run: res.Run, Grade: reportGrade(res), R: res.R})
		}
		result.Cases = append(result.Cases, entry)
		result.Total++
		if ok {
			result.Matched++
		} else {
			result.Mismatched++
		}

		if !options.JSON {
			// A failed write is a reporter failure, not a corpus verdict.
			// Discarding it let a broken output stream present as either a
			// clean corpus or a mismatching one, depending on nothing.
			if _, err := fmt.Fprintf(out, "%s: %s expected: %s [%s]\n",
				c.name, reportSummary(report), reportExpected(c.expect), okLabel(ok)); err != nil {
				return CorpusReport{}, fmt.Errorf("write corpus report: %w", err)
			}
		}
	}

	if options.JSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return CorpusReport{}, fmt.Errorf("encode corpus report: %w", err)
		}
	}
	return result, nil
}

func compareExpected(report ael.Report, exp expected) bool {
	runExps := expectedRuns(exp)
	if len(report.Runs) != len(runExps) {
		return false
	}
	byRun := map[string]ael.Result{}
	for _, res := range report.Runs {
		byRun[res.Run] = res
	}
	for _, runExp := range runExps {
		res, ok := byRun[runExp.ID]
		if !ok && runExp.ID == "" && len(report.Runs) == 1 {
			res, ok = report.Runs[0], true
		}
		if !ok || reportGrade(res) != expectedGrade(runExp.Grade) || res.R != runExp.R {
			return false
		}
		for id, want := range runExp.Must {
			got, ok := res.Checks[id]
			if !ok || string(got.Status) != want {
				return false
			}
		}
	}
	return true
}

func reportSummary(report ael.Report) string {
	var parts []string
	for _, res := range report.Runs {
		parts = append(parts, fmt.Sprintf("run=%s grade=%s r=%s | %s", res.Run, reportGrade(res), res.R, reportChecks(res)))
	}
	return strings.Join(parts, " || ")
}

func reportChecks(res ael.Result) string {
	var parts []string
	for _, id := range []string{"a", "b", "c", "d", "e", "w", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "u", "r", "s", "t", "v", "R"} {
		if out, ok := res.Checks[id]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", id, out.Status))
		}
	}
	return strings.Join(parts, " ")
}

func reportExpected(exp expected) string {
	var parts []string
	for _, runExp := range expectedRuns(exp) {
		runID := runExp.ID
		if runID == "" {
			runID = "<single>"
		}
		var keys []string
		for k := range runExp.Must {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var checks []string
		for _, k := range keys {
			checks = append(checks, fmt.Sprintf("%s=%s", k, runExp.Must[k]))
		}
		parts = append(parts, fmt.Sprintf("run=%s grade=%s r=%s %s", runID, expectedGrade(runExp.Grade), runExp.R, strings.Join(checks, " ")))
	}
	return strings.Join(parts, " || ")
}

func expectedRuns(exp expected) []runExpected {
	if len(exp.Runs) > 0 {
		return exp.Runs
	}
	return []runExpected{{ID: "", Grade: exp.Grade, R: exp.R, Must: exp.Must}}
}

func reportGrade(res ael.Result) string {
	if res.Ungraded {
		return "ungraded"
	}
	return fmt.Sprintf("AEL%d", res.Grade)
}

func expectedGrade(v any) string {
	switch t := v.(type) {
	case int:
		return fmt.Sprintf("AEL%d", t)
	case float64:
		return fmt.Sprintf("AEL%d", int(t))
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func okLabel(ok bool) string {
	if ok {
		return "OK"
	}
	return "MISMATCH"
}
