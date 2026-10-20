<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Agent Evidence Level (AEL)

**A measurement standard for AI-agent audit evidence.**
Version 0.1 (draft for publication). Specification: CC BY 4.0. Reference checker and fixtures: Apache-2.0.

The Agent Evidence Level grades a record of AI-agent activity, from AEL-0 to AEL-4, by what an independent party can verify, and what omission they can detect, without trusting the vendor or the operator.

## 1. Terms

| Term | Meaning |
|---|---|
| Subject | The agent system whose actions are recorded. |
| Recorder | The component that observes the subject's actions and emits records. |
| Operator | The party that deploys the recorder and holds its signing keys. |
| Run | One bounded recording session with a declared start and end. |
| Artifact | The bundle a verifier receives: records, key references, proofs, declarations. |
| Checker | A runnable program, independent of the producer, that evaluates an artifact against this standard. |
| Verifier | The party that runs the checker. A verifier supporting a public AEL grade is neither the producer nor the operator; other relationships remain relying-policy decisions. |
| Conformance claim | A public statement that a particular run earned an AEL grade. It is valid only when bound to a verification record produced by a verifier that is neither the producer nor the operator. |
| Capability declaration | A producer's machine-readable statement about the artifact formats and export operations its product supports. It is not a grade. |
| Verification record | A versioned, signed verification package that binds one exact run artifact and its verification inputs to the checker result and the checker's conformance-corpus result, and carries the required content-addressed material for replay. |

## 2. Grade semantics

1. **Rungs are cumulative.** AEL-n is earned only when every criterion of AEL-0 through AEL-n holds.
2. **Minimum rule.** A grade is the minimum over the required sub-dimensions (section 4). Nothing averages. The weakest required dimension is the grade.
3. **Three outcomes per check: PASS, FAIL, UNABLE-TO-VERIFY (UV).** FAIL means the checker ran and the property was violated: affirmative evidence of tampering or nonconformance. UV means the check could not be completed (no published key, undocumented format, missing artifact, no runnable checker). UV caps the grade exactly as FAIL does, but it impeaches the verification, not the artifact. Checkers and reports MUST keep the two distinct; rounding UV to either PASS or FAIL is nonconforming.
4. **No portable verification, no grade.** A mechanism whose records only its own producer can check is Ungraded, whatever its cryptography.
5. **Reporting format.** A published grade MUST be per run and carry its annotations: `run <id>: AEL-n [+R | R-pending] (coverage: ...; custody: ...; anchor: ...; retention: ...)`. A bare "AEL-3" is a nonconforming claim, and a single headline number for a multi-run artifact is nonconforming.
6. **R suffix.** Decision-reproducibility (section 3.6) is orthogonal to the rungs and is reported as `+R` or `R-pending` at every rung.
7. **A producer or operator does not award a grade.** Live process state, configuration, feature flags, a producer-run or operator-run checker, and a producer's manifest declaration MAY be reported as operational or capability facts. A producer-run or operator-run evaluation MAY publish an authenticated evaluation result, but that result MUST NOT support a public AEL grade. These facts and results MUST NOT be labeled `AEL-n`, `AEL level`, `AEL grade`, `AEL verified`, or any equivalent numeric AEL claim. Adding `self-assessed`, `self-asserted`, `capable of`, `target`, or another qualifier does not make a first-party rung conforming.
8. **Lifecycle and verification are separate.** A run is `OPEN`, `CLOSED`, or `ABNORMAL-END` based on signed run records and checker findings. Verification is absent or is established by a verification record trusted by the relying party. `CLOSED-PENDING-VERIFICATION` and `VERIFIED` MAY be displayed as derived combinations, but MUST NOT be producer-set run fields. An open artifact can earn at most AEL-0 after independent checking; an in-memory view of an open run has no grade.
9. **A grade is bound, not portable.** A verification record applies only to the exact run, artifact bytes, out-of-band verification inputs, specification version and digest, checker source revision and executable digest, and corpus identity it names. It MUST NOT be promoted into a product-wide grade, a current-running grade, a fleet-wide grade, or a grade for another run.
10. **Historical results and current acceptability are separate.** A verification record is an immutable statement about an evaluation that occurred. Time alone does not change what the exact artifact demonstrated. A relying policy MAY stop accepting the result because of an expiry, compromised key, withdrawn checker revision, specification change, verifier revocation, or other named reason. If current status cannot be obtained from the declared status authority, the result is `STATUS-UNKNOWN`, not current and not revoked.
11. **Independence has a hard floor and a policy layer.** A producer-run or operator-run evaluation cannot support a public AEL grade. Beyond that exclusion, a signature proves control of a verifier key, not organizational independence. A published result MUST identify the verifier and disclose its relationship to the producer and operator. The relying party or registry decides whether an affiliate, customer, consultant, recognized individual, accredited lab, or other eligible verifier satisfies its independence policy.

## 3. The rungs

Per rung: what the artifact MUST contain; what the checker MUST demonstrate (every demonstration is falsifiable: a conforming fixture that passes, and a perturbed fixture the checker must reject); the claims the grade MAY make; the claims it MUST NOT make.

### AEL-0: Authentic and ordered

**Artifact MUST contain:** (a) every record signed, individually or through a signed commitment covering each record, under a verification key published out-of-band from the artifact; (b) a per-record order commitment: each record binds its predecessor's hash, or its position in a signed append-only structure; (c) a byte-precise, documented canonical form for signed payloads, sufficient for an independent implementation.

**Checker MUST demonstrate:** offline verification of every signature from the artifact plus the published key alone; rejection when any byte of any record changes; rejection when two records are transposed; rejection when an interior record is removed.

**MAY assert:** "These records were signed by the holder of key K. Their relative order is tamper-evident. Modification or interior deletion within the presented sequence is detectable."

**MUST NOT assert:** completeness in any form. "Tamper-proof," "complete audit trail," "every action recorded," "nothing bypassed the boundary." At this rung, tail truncation is silent: cut the sequence at any point and the remainder verifies. The keyholder can also fabricate an entire sequence that verifies end to end.

### AEL-1: Gap- and truncation-evident within a run

**Artifact MUST add:** (a) a signed run-open record carrying run identity; (b) contiguous per-run sequence numbers with no legitimate gaps; (c) signed heartbeat records at a declared maximum interval H, so an interval without activity is itself a signed statement; (d) a signed run-close record committing to the run's total record count and final chain head.

**Checker MUST demonstrate:** all AEL-0 demonstrations; rejection on any sequence gap; rejection when spacing between consecutive records exceeds H plus a declared tolerance; rejection when the close record's committed count differs from the presented count (fixture: remove the tail record); classification of a run with no close record as OPEN / ABNORMAL-END, a first-class outcome distinct from both PASS and FAIL.

**MAY assert:** "Within this run, interior omission, silence longer than H, and tail truncation are each detectable."

**MUST NOT assert:** cross-run completeness (deleting an entire run is silent at this rung); any property against a dishonest keyholder, who can fabricate a clean run, heartbeats and close included; bypass claims.

### AEL-2: Cross-domain omission-evident

**Artifact MUST add:** (a) records from a second recorder observing the same boundary, itself meeting AEL-1, with every recorder's records signed under a verified recorder signing key and the custody separation declared by the operator (different process and host at minimum; different operator where claimed); (b) a correspondence rule: the event classes that must appear in all recorder records, and the identifiers that match them; (c) all record sets in the artifact.

**Checker MUST demonstrate:** AEL-1 on each record set independently; that each recorder identity is bound to the records' verified signatures, including rejection when a non-empty manifest recorder key disagrees with the key that actually signed that recorder's records; that every pair of verified recorder signing keys differs; and a cross-audit that reports every covered event present on one recorder and absent from another (fixture: delete one side's copy of an event; the checker must flag the discrepancy). If no covered event classes are declared, omission detection is unverifiable and AEL-2 is not earned.

This is the first rung at which "did anything cross the boundary unrecorded" becomes a checkable question, and only for the covered event classes, and only where mediation coverage is enforced-total, so that a second observer at a lower layer (for example, a kernel-level egress observer) sees attempts the mediating recorder never saw.

**MAY assert:** "Omission of a covered event from any recorder's record is detectable, unless the verified recorder keyholders collude or the observers share the same blind spot."

**MUST NOT assert:** an unqualified "no bypass occurred" (the correct form: "no recorder observed a covered event that another recorder omitted"); anything about uncovered event classes; organizational independence beyond the declared custody. Two recorders under one operator detect a compromised or misbehaving recorder; they do not constrain the operator who controls both keyholders.

### AEL-3: Externally anchored

**Artifact MUST add:** (a) chain heads and run-close commitments registered, at a declared cadence, in an append-only log declared by the operator as externally operated, where the log supports inclusion proofs and consistency proofs; (b) the inclusion proofs; (c) the log's identity and verification key, published.

v0.1 carries and verifies inclusion proofs only. It carries no consistency proof between signed tree heads and does not verify that one signed tree head is an append-only extension of another. A verifier MUST NOT conclude append-only extension between signed tree heads from an AEL-3 artifact alone. A future artifact-format version that exercises the consistency-proof requirement MUST carry the earlier and later signed tree heads and a consistency proof, and its checker MUST verify that proof.

**Checker MUST demonstrate:** AEL-2 demonstrations; that `anchor.log_key` actually signed the tree head; that this verified log key differs from every verified recorder signing key; verification of every inclusion proof against the log's signed tree head; rejection of an internally-valid alternative history that conflicts with an anchored head (fixture: a re-signed variant chain); labeling of records newer than the latest anchor as UNANCHORED-WINDOW, graded at the mechanism's unanchored rung until the next anchor lands.

**MAY assert:** "History up to the anchored head a verifier holds cannot be rewritten or retroactively edited without detection by that verifier."

**MUST NOT assert:** real-time honesty (a recorder that lies at record time anchors its lie); anything about events never recorded (absence anchors as faithfully as presence); protection inside the anchor-lag window; that an AEL-3 artifact detects log equivocation, in which a log presents different tree heads to different parties.

### AEL-4: Counterparty-confirmed

**Artifact MUST add:** (a) for a declared set of confirmed flows, signed statements from the destination party, or from an observer at the destination boundary, stating what it received, including "nothing," under a declared counterparty key; (b) run binding: each statement carries the run identifier or nonce it answers, so an all-clear cannot be replayed across runs; (c) a correspondence rule mapping recorded outbound decisions to confirmations.

**Checker MUST demonstrate:** AEL-3 demonstrations; that `counterparty.key` actually signed the counterparty statements; that this verified counterparty key differs from every verified recorder signing key; rejection of a statement bound to a different run (fixture: substitute another run's confirmation); a two-way cross-audit flagging recorded-but-unconfirmed and confirmed-but-unrecorded deliveries. If no confirmed flows are declared, counterparty confirmation is unverifiable and AEL-4 is not earned.

**MAY assert:** "For the confirmed flows, what the destination received is attested under a declared counterparty key that is different from the recorder signing keys. Fabricating a clean history for those flows requires cooperation from that counterparty keyholder."

**MUST NOT assert:** anything beyond the confirmed flows; content judgments (receipt of bytes is confirmed; harmlessness is not); confirmation where the counterparty does not participate; organizational independence beyond the counterparty declaration.

### 3.6 The R suffix: decision-reproducibility

**Earned when** each record captures the complete input set of the recorded decision (policy identity, request material, and every element of runtime state the decision consulted) such that the checker re-derives the identical verdict from the record alone, with no access to the live system.

**Checker MUST demonstrate:** re-derivation of every fixture verdict; a verdict-mismatch report when any captured input is perturbed.

**With R, MAY assert:** "The recorded verdict is the deterministic output of the recorded inputs under the recorded policy; the decision itself is auditable from the record." **Without R, MUST NOT assert** that a verdict can be independently re-derived, or that the decision, as opposed to its occurrence, is auditable.

**MUST NOT assert:** that a reproducible decision was an authorized action. R establishes that the recorded verdict follows from the recorded inputs under the recorded policy. It establishes nothing about which principal was permitted to act, under whose authority and which policy version that permission was granted, or on which resource and within what scope. A verifier that re-derives a verdict has learned that the decision was computed as recorded, not that the actor was entitled to the outcome. Whether the record identifies the acting principal, and how strongly that identity was established, is a property of the record's content and of the producer's identity handling, and is outside every rung in this specification. R also makes no statement about whether the policy itself was correct.

### 3.7 Retention: a mandatory annotation, never a grade

Retention is the operator's policy for how long records are intended to remain available for verification, and under whose storage custody. It is a mandatory annotation on every published grade. It is **not** a rung and **not** scored as proof, because it is a promise about the future and about storage that no checker can verify from an artifact presented today.

**Artifact MAY declare** `manifest.retention` (a period and a storage custody). The declaration is the operator's stated policy. It is not signed evidence of actual past retention, future availability, storage durability, or legal compliance.

**Checker MUST** report the declared retention value with every per-run grade, and MUST label it as an operator declaration. The v0.1 artifact format defines no stronger, verifiable retention proof.

**Checker MUST NOT** raise, lower, or otherwise award a rung based on the declared retention period or storage custody. It MUST NOT treat a declared period as proof that records were retained, will remain available, were stored on durable media, or were held by the declared custodian.

**Retention MUST NOT excuse in-artifact nonconformance.** Within a presented artifact, a sequence gap, heartbeat gap, missing close, anchor mismatch, cross-recorder discrepancy, or counterparty discrepancy stays PASS / FAIL / UV per its own check. A declared retention period never converts an in-artifact failure into an "aged-out absence."

**Absence is not cleanliness.** When a verifier asks about a run or interval for which no artifact exists and, by an externally supplied evaluation time, the material falls outside the declared retention period, the honest result is `OUTSIDE-DECLARED-RETENTION / UV`: "not available for verification under the declared policy." It MUST NOT be reported as evidence that the run was clean, complete, or properly disposed of. (v0.1's checker grades presented artifacts and does not consume an external evaluation time, so this outcome is a defined reporting principle, not yet a checker behavior.)

**Timestamps are not trusted time.** Recorder-signed `ts` values are evidence only of the recorder's signed timeline, not trusted wall-clock time. In v0.1 they support monotonicity and declared heartbeat-spacing checks; they do not prove a record's real-world age. Binding to real time would require an independent time proof (for example an RFC 3161 timestamp token or a time-bearing external log proof), which v0.1 does not define.

## 4. Sub-dimensions

A single flat grade decomposes into these dimensions. Each rung sets required minimums; the grade is the minimum across them; the remainder annotate every published grade and bound what it may claim.

| Dimension | Question it answers | Values (weakest first) | Effect |
|---|---|---|---|
| Mediation coverage | How much of the subject's action surface is forced through the recorded boundary? | declared-only / partial / mediated-only / enforced-total | Bounds claim scope. Bypass-evidence claims require enforced-total plus AEL-2. |
| Recorder custody | Whose keys sign, relative to subject and operator? | same-process / same-host / same-operator / independent | AEL-2 requires verified recorder signing keys to differ and custody separation to be declared; AEL-4 requires the declared counterparty key to differ from recorder signing keys. |
| Chain continuity | Are omission, silence, and truncation visible? | none / linked / contiguous + heartbeat + close | Gates AEL-0 and AEL-1. |
| External anchoring | Can history be rewritten or forked? | none / operator-run log / independent append-only log | Gates AEL-3. |
| Counterparty independence | Does the far end attest what arrived? | none / partial flows / declared confirmed set | Gates AEL-4. |
| Retention / durability | How long does the operator intend records to stay available? | declared period and storage custody | Mandatory annotation only (§3.7). Never gates a rung, never excuses an in-artifact failure. Absent-and-past-retention is `OUTSIDE-DECLARED-RETENTION / UV`, never proof of cleanliness. |
| Verifier portability | Can a stranger check this offline? | vendor-only / published key and format / independent implementations exist | Required at every rung. Vendor-only means Ungraded. |
| Decision-reproducibility | Can the verdict be re-derived from the record? | R-pending / +R | Suffix at every rung. |

## 5. Conformance: earned, not asserted

A public grade is earned when a verifier that is neither the producer nor the operator evaluates a real artifact and publishes the verification record required by section 5.2. The checker used for that evaluation MUST pass the published conformance corpus, including every valid fixture and every required failing fixture through the reported rung. The corpus supplies the rung-specific negative controls. Its purpose-built signed fixtures MUST exercise each protection class and MUST produce the expected diagnostic outcome. A checker that accepts a required failing fixture is nonconforming, whatever its vendor says.

The real-artifact evaluation demonstrates that the submitted run passes. A verifier MAY add mutations of the submitted artifact as corroboration where the mutation is publicly constructible without the recorder's signing key and the expected rejection is unambiguous. Such mutations are not required and MUST NOT replace the corpus controls. Failure to construct an optional real-artifact mutation is not UV for the underlying protection class.

A vendor statement, however detailed, earns nothing. AEL v0.1 therefore ships as three deliverables in one release: this specification, the reference checker, and a per-rung fixture corpus holding at least one valid artifact plus the required failing perturbations. A standard whose bar is "earned, not asserted" that ships without a runnable checker is the same attestation it criticizes; the checker and fixtures are part of v0.1, not a follow-up.

### 5.1 Capability declarations

An AEL artifact capability declaration MAY identify:

- its own schema and version;
- the producer, product build, and configuration profile to which it applies;
- AEL artifact format versions the product can export;
- supported run-open, run-close, crash-preservation, export, and verification-result import operations;
- known limits, including concurrency and custody limits; and
- issue and update times.

The declaration MUST NOT contain a current, maximum, target, supported, or self-assessed AEL rung. It MUST NOT contain a producer-set `verified` state. Format version `1` means artifact format version 1; it does not mean AEL-1. A producer MAY sign this declaration to authenticate its origin, but that signature does not turn any field into independently verified evidence.

### 5.2 Publishing a verified result

A conforming published grade MUST be backed by a verification record whose signed manifest contains:

- a verification-package format version, stable record identifier, and run identifier;
- a content-addressed file manifest for every file in the submitted artifact and every out-of-band key or other verification input, with each entry naming its normalized relative path, size, digest algorithm, and digest;
- the AEL specification version and digest;
- the checker implementation name, source revision, and executable digest, without treating any of them as an authorization decision;
- an artifact-evaluation result blob containing the exact argument vector, exit status, machine-readable checker output, standard output, and standard error;
- a conformance-corpus result blob containing the corpus version or manifest digest, exact command, exit status, and machine-readable result;
- the full per-run grade line, annotations, and PASS / FAIL / UV outcomes;
- the verifier's identity, verification key, and declared relationship to the producer and operator;
- the evaluation time and any relying-policy expiry; and
- the status authority identifier and stable record identifier that bind separately signed status statements for supersession or revocation.

Every required file and result MUST travel with the package as a content-addressed blob covered by the signed manifest. The record is invalid if a required blob is absent, if its size or digest does not match, or if a path escapes the package. A network URL MAY be included as a retrieval hint, but it MUST NOT be the only copy of required material.

The verifier MUST sign the manifest under a separately trusted verifier key. Copying a verifier's text into a producer-controlled field or registry is not authentication. A consumer displays `VERIFIED` only after it validates the manifest signature and every required blob, matches every binding to the artifact and run being shown, confirms that the verifier is neither the producer nor the operator, and accepts the verifier and checker under its own policy. Otherwise the honest state is pending, untrusted, invalid, revoked, expired, or status unknown, as applicable. The executable digest and source revision identify what ran; they do not make that checker trusted. Replay with a checker the consumer trusts is the stronger check.

Revocation and supersession do not edit the historical record. They are separate authenticated statements bound to the original record identifier and the declared status authority, naming the state, the reason, the effective time, and, for supersession, the replacement. Revocation and supersession are terminal for the original record; a replacement is a different verification record with its own identifier. A `revoked` or `superseded` statement takes effect at its `effective_at`. A consumer evaluating at or after that time MUST report the named terminal state. A consumer evaluating BEFORE it MUST report status unknown and MUST NOT display `VERIFIED`, because the authority has published a withdrawal it cannot yet apply and treating the record as current in that window would be the fail-open reading.

A status statement that supports a `VERIFIED` display MUST be canonical, MUST be separately signed by the declared status authority, and MUST carry its format version, the record identifier, the authority identifier, the state, `issued_at`, and `next_update`. A `current` statement MUST carry a finite `next_update` strictly later than its `issued_at`. The manifest names the status authority; it does not confer trust in it. A consumer MUST resolve the authority's verification key from its own trust configuration, keyed by the authority identifier, and MUST NOT accept a key carried by the package or by the status statement, because a package that supplied its own status key would be attesting to its own withdrawal. An identifier the consumer has no configured key for is not a validated authority, so the outcome is status unknown. Rotation and revocation of an authority key are relying-party policy and are outside this specification.

A consumer MUST evaluate status against an evaluation time supplied by its own relying policy, and MUST NOT treat a recorder timestamp, a verifier evaluation time, or the presence of a signature as a trusted clock. A consumer MUST NOT accept a `current` statement when its evaluation time is earlier than `issued_at`, at or after `next_update`, or outside any stricter freshness interval its policy requires. A consumer MAY require a shorter interval than the authority chose; it MUST NOT extend one.

A consumer displays `VERIFIED` only when it validates the verification record under this section and accepts a fresh `current` statement under the preceding paragraph. If the status statement or its signature is absent, if the declared status authority cannot be validated, if no evaluation time can be established, or if the statement falls outside the accepted freshness interval, the consumer MUST report status unknown and MUST NOT display `VERIFIED`. Revoked, superseded, and expired remain distinct outcomes and are never success.

Status acquisition is outside offline validation. A consumer MUST decide status only from status bytes and a detached signature supplied to it, and MUST NOT require network retrieval during validation. A URL MAY be a retrieval hint and MUST NOT be the only material used to decide status. A consumer MAY retain a valid historical verification record and report the time-bounded status evidence it observed; it MUST NOT present that record as currently verified once freshness is unavailable.

This contract bounds replay rather than eliminating it. An authenticated `current` statement can be replayed until its signed `next_update`, and no offline mechanism can do better, because a static package cannot prove that no later revocation exists. AEL does not claim that a withdrawn result can never be presented again. It claims only that the window in which it can be presented as current is finite, chosen by the status authority, and visible to the consumer.

## 6. Limits: what no rung can prove

**The completeness limit.** A record produced inside one trust domain cannot prove its own completeness to anyone outside that domain, against the party holding the domain's signing keys. The keyholder can construct an alternative history, shorter, different, or empty, sign every element of it, heartbeats and close included, and the result passes every internal check. Signed silence proves the silence was signed; it cannot prove the silence was true. AEL is a ladder rather than a checkbox for exactly this reason: rungs 0 and 1 measure internal consistency, which a keyholder can counterfeit wholesale; omission-evidence is bought only with additional signed evidence, one keyholder at a time (a second verified recorder signing key at AEL-2, a signed log tree head at AEL-3, a signed counterparty statement at AEL-4), while organizational independence remains declared by the operator rather than proven by the checker. Each purchase covers only what that signer can see. No rung is named "complete."

**The verification limit.** A signed package proves that the verifier signed its manifest; it cannot prove that the named command ran or that the verifier reported it truthfully. Carrying the artifact, inputs, results, and corpus result makes the claim replayable and therefore falsifiable. A relying party still chooses which verifier identity, checker implementation, and status authority to trust. Replay can expose a false result; packaging cannot make dishonesty impossible.

**Open question: detection latency.** AEL does not currently bound the time between forgery or omission and its detection. Defining such a bound would require checkpoint cadence and an explicit checking obligation, within the detection limits of the applicable rung. This remains an open question; existing rungs carry no detection-time guarantee, including eventual detection of events they cannot observe.

**Per-rung limits, restated plainly:**

- **AEL-0** does not see tail truncation, does not see fabrication, and says nothing about completeness.
- **AEL-1** does not see whole-run deletion, and holds nothing against a dishonest keyholder.
- **AEL-2** fails against collusion of the recorder keyholders, and is blind outside the covered event classes and inside shared blind spots.
- **AEL-3** does not detect a recorder that lied at record time, never sees never-recorded events, and leaves the window since the last anchor unprotected.
- **AEL-4** covers only confirmed flows with cooperating counterparties, and confirms receipt, never meaning.
- **No rung** grades whether decisions were good, whether policy was right, or whether the subject behaved well. AEL grades the evidence, never the conduct.

## 7. The field, graded

Mechanisms, never vendors. Grades assume the mechanism as commonly shipped; a specific deployment may grade higher or lower under the checker, which is the point of having one.

| Mechanism | Grade | Basis |
|---|---|---|
| Plain logs (files, JSON lines, syslog, SIEM forwarding) | Ungraded | Mutable in place; no signature, no order commitment. Forwarding to a SIEM moves a copy; the record arrives pre-trusted and stays unverifiable. |
| Local self-attested records (vendor-verifiable signatures or hash chains; no published key, format, or checker) | Ungraded (UV) | Fails verifier portability. A signature only its producer can check is attestation wearing math. |
| Operator-published signed chains (signed, hash-chained, offline-verifiable against a published key) | AEL-0 | The strongest mechanism in common circulation today. Authentic and ordered; interior deletion detectable. Tail truncation, deleted runs, and fabricated histories remain silent, because one keyholder produced everything. |
| Externally-anchored chains (heads in a transparency log; single recorder; no heartbeats or signed close) | AEL-0 (anchor: independent) | Anchoring freezes what was recorded and says nothing about what was not, so it earns the anchoring sub-dimension but not completeness. Rungs 1 and 2 are missing, so rung 3 is not earned. |
| Independently-confirmed delivery (counterparty receipts, with no graded record behind them) | Ungraded to AEL-0 overall; rung-4 property on confirmed flows only | Confirms that specific deliveries happened. With no graded record to reconcile against, it cannot support run-level claims. |

### 7.1 Evidence registry

Concrete runs, including the editor's own, may be listed in `GRADES.md` under the same rule as every other row. A numeric grade appears only with a linked verification record satisfying section 5.2, signed by a verifier that is neither the producer nor the operator. A producer declaration with no such record is listed as a capability declaration with **no grade**. See `GRADES.md`.

## 8. Name, definition, and governance

**Name and collision check.** "Agent Evidence Level," abbreviated AEL, always expanded on first use. The acronym is established in unrelated fields (accessible emission limits in laser safety; exposure limits in industrial hygiene); no standard named "Agent Evidence Level" exists as of July 2026, and the nearest adjacent work grades evidence-process maturity rather than checker-verified artifacts. Graded levels are written AEL-0 through AEL-4; the search handle is the full phrase.

**One-sentence definition, for a procurement document:** "The Agent Evidence Level grades a vendor's records of AI-agent activity, from AEL-0 to AEL-4, by what an independent party can verify, and what omission they can detect, without trusting the vendor or the operator."

**Relationship to prior art.** AEL is not an audit-control framework and not a records-retention regime; it is a cryptographic evidence-grade lens for the artifacts that audit and logging mechanisms produce. It borrows established vocabulary rather than coining its own and consumes existing transparency logs at AEL-3 rather than competing with them. See `docs/PRIOR-ART.md` for the mapping (RFC 5848 signed syslog, RFC 6962/9162 and SCITT transparency, RFC 3161 trusted time, NIST SP 800-92 and SP 800-53 AU-11 for the retention neighborhood).

**Home.** The specification lives in a standalone, vendor-neutral repository: spec under CC BY 4.0, reference checker and fixtures under Apache-2.0, no product marks in the specification. Product sites point at the repository; the repository points at no product.

**GRADES.md.** The repository carries an evidence registry. Any mechanism owner may open a pull request adding a row. Numeric grades require the signed verification package in section 5.2 from a verifier that is neither the producer nor the operator. Capability declarations may be listed, but carry no grade. The editor's row is held to the same rule as everyone else's.

**Endgame.** Once the vocabulary has usage independent of its editor, editorship is donated to a neutral foundation of the OpenSSF or OWASP class, with the reference checker maintained through the transition.

**Non-normative material.** Positioning and adoption guidance (including the questions a buyer should ask and how to read common marketing claims) live in `docs/RATIONALE.md`, outside the normative specification.
