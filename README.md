# exactzk-verification-guards

Three small, standalone Python scripts for checking that a zkML-gated escrow
deployment's on-chain artifacts are internally consistent, and that two
independent deployments of the same system haven't silently drifted apart.
Each one exists because a specific, real failure mode was found in
production and needed a repeatable check, not a one-off manual comparison.

All three are read-only. None of them needs a private key against any real
chain — the one exception (a well-known, publicly documented local test
key) is explained below.

## What's here

```
scripts/
  verifier_freshness_guard.py       library + CLI: is an on-disk verifier .sol
                                     still built from the current vk.key?
  stack_drift_canary.py             CLI: do two deployments of the same
                                     system still agree on every invariant
                                     that should be identical between them?
  selftest_drift_canary_invariant.py CLI: checks the checker — proves the
                                     canary's pass/fail logic actually
                                     tracks its inputs, using real chain data
                                     plus controlled perturbations, including
                                     both directions of the one-sided
                                     ("asymmetric") expectation case
abi/
  PassportAnchorV2.json             ABI only — no bytecode, no NatSpec,
  ZkInferenceEscrowV2.json          no metadata. Nothing here beyond what
  MockValidationRegistry.json       you'd get from the contracts' own
                                     public interfaces.
config.example.json                 the public reference deployment's
                                     addresses — safe to publish, safe to
                                     run against as-is
examples/
  config.altered-modelid.json        the same config with one field changed,
                                     used only to produce the failing run below
  run-pass.txt                      captured output: canary passing
  run-fail.txt                      captured output: canary failing
  run-selftest.txt                  captured output: selftest
  run-freshness-guard-noop.txt      captured output: freshness guard, no verifier on disk yet
  run-freshness-guard-real.txt      captured output: freshness guard, real circuit artifacts
```

## Prerequisites

- Python 3 with `web3` (v7+) and `eth_abi` installed.
- `stack_drift_canary.py` and `selftest_drift_canary_invariant.py` only need network access to a Base Sepolia RPC endpoint (the public one is the default). No private key, no local chain.
- `verifier_freshness_guard.py` additionally needs:
  - a local [Foundry](https://getfoundry.sh/) install, specifically the `anvil` binary (default expected at `~/.foundry/bin/anvil`, override by editing `FOUNDRY_BIN` or invoking anvil separately),
  - the `ezkl` Python package,
  - and your own `vk.key` / `settings.json` / `srs.bin` / verifier `.sol` file — this script checks *your* circuit's artifacts, so it needs them supplied as arguments; none are shipped here.
  - It funds its throwaway local chain with **Anvil's documented default dev account #0 private key** (`ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`) — this is Anvil's own well-known, publicly published test key, not a secret, and it only ever touches a scratch Anvil instance this script starts and kills itself. It is never used against a real network.

## What each script checks, and what a pass does/doesn't establish

### `verifier_freshness_guard.py`

**The defect it exists for:** an EZKL-generated `Halo2Verifier.sol` bakes a verification key's curve-point constants into literal bytecode at generation time. If `vk.key`/`settings.json`/`srs.bin` are ever regenerated without also regenerating the `.sol`, the stale `.sol` keeps silently accepting proofs "successfully" in local testing — an in-process verify call and a test suite with its own separately-regenerated fixture can both keep passing — while a real on-chain `verifyProof()` call against the *actual* stale bytecode reverts. This happened in production: a deployed verifier turned out to have been built from an earlier VK state than the vk.key it was supposed to match, because one deploy path regenerated the `.sol` before deploying and another silently reused whatever was already on disk. Nothing forced the second path to check first.

**What it does:** regenerates the verifier from the *current* `vk.key`/`settings.json`/`srs.bin` on a throwaway local Anvil chain it starts and tears down itself, deploys both the freshly-regenerated copy and the on-disk file there, and compares their metadata-stripped runtime bytecode hashes. Metadata must be stripped first because `solc`'s default metadata mode encodes the compile-time filesystem path, which differs across machines even for byte-identical contracts.

**A pass establishes:** the on-disk `.sol` you're about to deploy produces byte-identical bytecode (modulo compiler metadata) to what would be generated fresh from the vk.key/settings/srs sitting next to it right now.

**A pass does not establish:** that the vk.key itself is correct, that the circuit it was built from matches any particular model, or anything about what's already deployed on a real chain — it only compares two things you have locally.

**Captured runs:**
- `examples/run-freshness-guard-noop.txt` — invoked against an empty directory with no `.sol` file present. This is the safe early-exit path (`assert_verifier_matches_current_vk` returns immediately when there's nothing on disk yet to compare against) — it demonstrates the CLI runs, not the regenerate/compare logic.
- `examples/run-freshness-guard-real.txt` — a genuine end-to-end run: invoked read-only against a real solo circuit's canonical artifacts (`vk.key`, `settings.json`, `srs.bin`, `Halo2Verifier.sol`), which are not shipped here. It regenerated the verifier, deployed both copies to a real scratch Anvil, and confirmed the stripped bytecode hashes match (`0xf60aad67ed7b...`) — a live PASS on real circuit artifacts, not a mock.

### `stack_drift_canary.py`

**The defect it exists for:** two deployments of the same system are supposed to stay identical in every way that describes "the same model, correctly deployed" — but nothing enforces that automatically. They drift the moment only one of the two is redeployed, re-attested, or re-registered, and nothing else notices. A simpler approach — hardcoding an absolute count per circuit (e.g. "the batch circuit has exactly four attestations on both stacks, solo has zero on both") — cannot tell an intended, declared asymmetry (an attestation that's only ever supposed to exist on one of the two deployments) apart from an actual defect; it just fails in both cases, with no way to distinguish them short of reading the diff by hand.

**What it checks, between stack A and stack B:**
1. Live, metadata-stripped bytecode hash of each verifier (solo, batch), re-derived from `eth_getCode` right now, not a value recorded at deploy time.
2. `numOutputs` / `hDummy` from `escrow.models(modelId)` — structural facts about the model.
3. `vkHashFile` / `bundleDigest` per circuit label, from `PassportAnchorV2.getCircuits(modelId)`.
4. Every attestation resolved on either registry against an explicit, dated `REAL_ATTESTATIONS` catalog (the real-filings subset of `EXPECTED_ATTESTATIONS` — see below). Discovery is exhaustive **for the filer key named in each config** — it calls `getValidatorRequests(filerAddress)` and reads every hash that key has ever answered, rather than guessing at known attesters/tags, so an attestation under a tag or attester this script has never heard of is still caught as "unrecognized" as long as it was filed under that key. It is NOT exhaustive across the registry as a whole: an attestation filed under some other key — one that isn't named as either config's `filerAddress` — is invisible to this check entirely, whether or not it's a legitimate filing.

**What it deliberately does NOT check** (permanent, expected differences, not drift): contract addresses themselves, deployer/filer addresses, gas/nonces/tx hashes, or `artifactsURI`/`predicateVersion` strings.

**A pass establishes:** the two stacks you pointed it at agree on every structural fact that describes "the same model, correctly deployed" — same verifier bytecode, same model parameters, same circuit digests, and an attestation record that matches your stated expectations exactly (no missing filing, no undeclared filing, no unrecognized filing).

**A pass does NOT establish:** that either deployment is *correct* in any absolute sense (it has no independent notion of "correct" — only "do these two agree"), that the `vk.key`/circuit itself is sound, or that the `EXPECTED_ATTESTATIONS` catalog you're checking against is itself accurate — a stale catalog that nobody updated could theoretically agree with two equally-stale deployments. Nor does it establish that no other key has filed anything relevant on either registry: attestation discovery only covers the filer key named as `filerAddress` in each config, not the registry's full history — a filing under a different key is simply invisible to this check. It also cannot detect drift in anything it doesn't compare (see the "does NOT check" list above).

**The self-comparison caveat, made real, not just documented:** the shipped `config.example.json` describes one real, publicly checkable deployment on Base Sepolia. Running with `--config-a config.example.json --config-b config.example.json` compares that one deployment against itself — which will always agree, by construction, and demonstrates the mechanism rather than performing a live drift check between two independent things. To actually use this as a drift check, point `--config-b` (or `--config-a`) at your own second deployment's config instead.

To point it at your own deployment: write a second JSON file with the same five keys as `config.example.json` (`filerAddress`, `registryV2`, `escrow`, `anchorV2`, `modelId`) describing your deployment, and pass it as the other `--config-*` argument. If your two deployments have a genuinely different filing history (e.g. an attestation intentionally filed on only one of them), add an entry to `EXPECTED_ATTESTATIONS` in `stack_drift_canary.py` with `expected_stacks` set to `{"stackA"}` or `{"stackB"}` rather than both.

**The catalog and the one synthetic entry in it.** `EXPECTED_ATTESTATIONS` is the full catalog; `REAL_ATTESTATIONS` (what `main()` actually checks live state against) is `EXPECTED_ATTESTATIONS` minus anything marked `"synthetic": True`. There is exactly one such entry, `SYNTH-A`: a fictitious attestation, declared expected on `stackA` only, that was never filed anywhere and never will be. It exists purely so the asymmetric-expectation mechanism — an attestation legitimately expected on only one of the two stacks — is exercised by something other than reading the code and trusting it. `main()` excludes it from the live comparison it reports (a real run has no reason to expect a made-up filing to exist), but `selftest_drift_canary_invariant.py`'s Scenario 4 reads it directly to prove the mechanism works in both directions: see that section below.

**Captured runs, both real, both against live Base Sepolia state:**

Passing (`examples/run-pass.txt` — `--config-a config.example.json --config-b config.example.json`, exit code 0):

```
Comparing stackA (reference deployment (Base Sepolia, chainId 84532)) vs stackB (reference deployment (Base Sepolia, chainId 84532)) on chainId 84532

[1] Live bytecode hash, both circuits, both stacks...
  solo: stackA=f60aad67ed7bf1b55c...  stackB=f60aad67ed7bf1b55c...  match=True
  batch: stackA=d0cab4041caaf77ea9...  stackB=d0cab4041caaf77ea9...  match=True

[2] numOutputs / hDummy (escrow.models)...
  numOutputs: stackA=10  stackB=10  match=True
  hDummy: stackA=18011215629618843187546360138924333852267046068989450163396537537950511394632  stackB=18011215629618843187546360138924333852267046068989450163396537537950511394632  match=True

[3] Per-circuit vkHashFile / bundleDigest (PassportAnchorV2.getCircuits)...
  solo.vkHashFile: match=True
  solo.bundleDigest: match=True
  batchK8.vkHashFile: match=True
  batchK8.bundleDigest: match=True

[4] Attestations, both circuits, against the REAL_ATTESTATIONS catalog...
    (excludes the catalog's one "synthetic": True demo entry — see EXPECTED_ATTESTATIONS)
  stackA: 7 resolved requestHash(es) discovered via getValidatorRequests(0x944E3Cbf...)
  stackB: 7 resolved requestHash(es) discovered via getValidatorRequests(0x944E3Cbf...)
  001 (batchK8/pp-repro-v2) present on stackA — expected
  002 (batchK8/pp-repro-v2) present on stackA — expected
  003 (batchK8/pp-repro-v2) present on stackA — expected
  004 (batchK8/pp-bytecode-v1) present on stackA — expected
  005 (solo/pp-repro-v2) present on stackA — expected
  006a (solo/pp-repro-docker-v1) present on stackA — expected
  006b (batchK8/pp-repro-docker-v1) present on stackA — expected
  001 (batchK8/pp-repro-v2) present on stackB — expected
  002 (batchK8/pp-repro-v2) present on stackB — expected
  003 (batchK8/pp-repro-v2) present on stackB — expected
  004 (batchK8/pp-bytecode-v1) present on stackB — expected
  005 (solo/pp-repro-v2) present on stackB — expected
  006a (solo/pp-repro-docker-v1) present on stackB — expected
  006b (batchK8/pp-repro-docker-v1) present on stackB — expected

============================================================
NO DRIFT — both stacks agree on every checked invariant.
pass exit: 0
```

Failing (`examples/run-fail.txt` — `--config-a config.example.json --config-b examples/config.altered-modelid.json`, exit code 1): `config.altered-modelid.json` is byte-identical to `config.example.json` except its `modelId` was changed to a value never registered on that escrow. This is not a fabricated failure — every one of these 13 findings is a real live RPC read: the unregistered `modelId` genuinely returns a zeroed model record and an empty circuit list, and the real attestations discovered on the registry (unrelated to `modelId`) genuinely match no catalog entry once the circuit digests needed to compute expected hashes are unavailable for that model. A tool that has never been seen to fail is not known to work — this is that demonstration.

```
Comparing stackA (reference deployment (Base Sepolia, chainId 84532)) vs stackB (reference deployment (Base Sepolia) — DELIBERATELY ALTERED for the README's failing-run demo) on chainId 84532

[1] Live bytecode hash, both circuits, both stacks...
  solo: stackA=f60aad67ed7bf1b55c...  stackB=c5d2460186f7233c92...  match=False
  batch: stackA=d0cab4041caaf77ea9...  stackB=c5d2460186f7233c92...  match=False

[2] numOutputs / hDummy (escrow.models)...
  numOutputs: stackA=10  stackB=0  match=False
  hDummy: stackA=18011215629618843187546360138924333852267046068989450163396537537950511394632  stackB=0  match=False

[3] Per-circuit vkHashFile / bundleDigest (PassportAnchorV2.getCircuits)...

[4] Attestations, both circuits, against the REAL_ATTESTATIONS catalog...
    (excludes the catalog's one "synthetic": True demo entry — see EXPECTED_ATTESTATIONS)
  stackA: 7 resolved requestHash(es) discovered via getValidatorRequests(0x944E3Cbf...)
  stackB: 7 resolved requestHash(es) discovered via getValidatorRequests(0x944E3Cbf...)
  001 (batchK8/pp-repro-v2) present on stackA — expected
  002 (batchK8/pp-repro-v2) present on stackA — expected
  003 (batchK8/pp-repro-v2) present on stackA — expected
  004 (batchK8/pp-bytecode-v1) present on stackA — expected
  005 (solo/pp-repro-v2) present on stackA — expected
  006a (solo/pp-repro-docker-v1) present on stackA — expected
  006b (batchK8/pp-repro-docker-v1) present on stackA — expected

============================================================
DRIFT DETECTED (13 finding(s)):
  - solo verifier bytecode diverged: stackA=f60aad67ed7bf1b55cc6cb097b1997036617c161fbaa7f0fd80661c3bfc7b17c stackB=c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
  - batch verifier bytecode diverged: stackA=d0cab4041caaf77ea95fe45a29d14950be503ce26eb982af11026634112d8c67 stackB=c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
  - numOutputs diverged: stackA=10 stackB=0
  - hDummy diverged: stackA=18011215629618843187546360138924333852267046068989450163396537537950511394632 stackB=0
  - circuit 'solo' missing on one stack: stackA_has=True stackB_has=False
  - circuit 'batchK8' missing on one stack: stackA_has=True stackB_has=False
  - unrecognized attestation discovered on stackB: requestHash=0x13438e920fb01c027d03124ccfeba66d03791d5222543a989b1d730db68e1e0b — matches no EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; add a dated catalog entry (or investigate as unauthorized) before this can pass
  - unrecognized attestation discovered on stackB: requestHash=0x4d87885096b12fb4f3de5fa0a8b5d672509c2c5b23022cf34a2b08bd95ce3feb — matches no EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; add a dated catalog entry (or investigate as unauthorized) before this can pass
  - unrecognized attestation discovered on stackB: requestHash=0x68d1df98131f830a1c7da8adf2e650cd6f9f4ff7a97a617ba0404ae5aab50741 — matches no EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; add a dated catalog entry (or investigate as unauthorized) before this can pass
  - unrecognized attestation discovered on stackB: requestHash=0xa3dc42ae06fbfcce79568a7c7cc77e41b61bc7a9edbfda11c8cc7bd718383c44 — matches no EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; add a dated catalog entry (or investigate as unauthorized) before this can pass
  - unrecognized attestation discovered on stackB: requestHash=0xb08400452442b732ee32faed555dfe266bd88bba0027d0b35bb687fab737c931 — matches no EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; add a dated catalog entry (or investigate as unauthorized) before this can pass
  - unrecognized attestation discovered on stackB: requestHash=0xb2522032623b7069eb893b81f1c9746f4a46ca0986a9758422306f4bf7ca1a31 — matches no EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; add a dated catalog entry (or investigate as unauthorized) before this can pass
  - unrecognized attestation discovered on stackB: requestHash=0xc2ca8b33ff84c4200f62275925d5e09587e20e1c076d4a8bbddd8f32b968be22 — matches no EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; add a dated catalog entry (or investigate as unauthorized) before this can pass
fail exit: 1
```

### `selftest_drift_canary_invariant.py`

**The defect it exists for:** `evaluate_attestations()` — the pure function that decides pass/fail for the attestation-catalog check — could in principle look correct on a single real run while actually ignoring its inputs (e.g. a bug that always reports "no findings"), because on a real run the expected and actual data usually agree by construction. This selftest closes that gap by perturbing a copy of real discovered data in two specific, adversarial ways and asserting the evaluator's verdict changes exactly as it should.

**What it does:** reads real, live on-chain data once (same catalog-hash computation `main()` uses), then runs five scenarios against it. Scenarios 1–3 check against `REAL_ATTESTATIONS` (the same real-filings-only catalog `main()` uses live): (1) the real data passes as-is; (2) a real, currently-present attestation is removed from one stack's discovered set in Python only, and the evaluator must fail, naming that attestation and that stack; (3) a fabricated, uncatalogued hash is injected into a stack's discovered set, and the evaluator must fail, naming that hash and that stack.

Scenarios 4a/4b are the asymmetric-expectation coverage: they read `EXPECTED_ATTESTATIONS`' one `"synthetic": True` entry (`SYNTH-A`, expected on `stackA` only, never actually filed anywhere — see the catalog's own comment in `stack_drift_canary.py`) and prove the mechanism in both directions. **4a**, no perturbation: since `SYNTH-A` was genuinely never filed, it is already absent from both stacks' real discovered sets — that absence must be a finding on `stackA` (where it's expected) and must produce *no finding whatsoever* on `stackB` (where it's not). **4b**, one perturbation: `SYNTH-A`'s hash is inserted into `stackA`'s discovered set only, simulating it having actually been filed there — the finding from 4a must become a note ("declared asymmetry"), and `stackB`, still untouched, must remain silent. Together these establish that a one-sided expectation produces the right verdict on both the side it applies to and the side it doesn't — not just one of the two.

**Watching this coverage actually matter:** before trusting Scenario 4, we broke it on purpose — changed `evaluate_attestations()`'s `expected_here = stack in entry["expected_stacks"]` to a hardcoded `expected_here = True` (i.e. treat every entry as expected on every stack) and re-ran the selftest. Scenarios 1–3 kept passing unaffected, because every entry they touch is already symmetric — nothing about the mutation changes their behavior. Scenario 4a failed immediately:

```
--- Scenario: 4a. asymmetric entry (SYNTH-A), absent everywhere (its natural, unperturbed state) ---
  finding: attestation SYNTH-A (solo/pp-repro-v2) expected on stackA per catalog (dated SYNTHETIC — not a real filing, added to test the asymmetric-expectation mechanism) but MISSING there
  finding: attestation SYNTH-A (solo/pp-repro-v2) expected on stackB per catalog (dated SYNTHETIC — not a real filing, added to test the asymmetric-expectation mechanism) but MISSING there
Traceback (most recent call last):
  ...
  File "selftest_drift_canary_invariant.py", line 168, in main
    assert not any(asym_id in f and other_stack in f for f in findings), \
AssertionError: absence on stackB (where SYNTH-A is NOT expected) must not be a finding at all
EXIT: 1
```

The mutation was then reverted line-for-line and the restoration confirmed byte-for-byte against a SHA-256 taken before the mutation (`90acbe7cbf19e3d3b664069d3dff5e881040ea81dbb204c3446c1a713264f251`) before re-running anything.

**A pass establishes:** the evaluator's pass/fail logic actually responds to what it's given — it is not hardcoded, and it correctly attributes a finding to the specific attestation ID and stack responsible, in both the symmetric and the one-sided-expectation case.

**A pass does NOT establish:** anything about the deployments themselves — this only tests the checker, not the chain state (that's `stack_drift_canary.py`'s job).

Captured run (`examples/run-selftest.txt`, restored code, exit code 0):

```
Real discovered sets (live, read-only):
  stackA: 7 resolved hash(es)
  stackB: 7 resolved hash(es)

--- Scenario: 1. current state (real chain data) ---
  result: PASS  [OK]
  note: 001 (batchK8/pp-repro-v2) present on stackA — expected
  note: 002 (batchK8/pp-repro-v2) present on stackA — expected
  note: 003 (batchK8/pp-repro-v2) present on stackA — expected
  note: 004 (batchK8/pp-bytecode-v1) present on stackA — expected
  note: 005 (solo/pp-repro-v2) present on stackA — expected
  note: 006a (solo/pp-repro-docker-v1) present on stackA — expected
  note: 006b (batchK8/pp-repro-docker-v1) present on stackA — expected
  note: 001 (batchK8/pp-repro-v2) present on stackB — expected
  note: 002 (batchK8/pp-repro-v2) present on stackB — expected
  note: 003 (batchK8/pp-repro-v2) present on stackB — expected
  note: 004 (batchK8/pp-bytecode-v1) present on stackB — expected
  note: 005 (solo/pp-repro-v2) present on stackB — expected
  note: 006a (solo/pp-repro-docker-v1) present on stackB — expected
  note: 006b (batchK8/pp-repro-docker-v1) present on stackB — expected

--- Scenario: 2. present on one stack, missing on the other (expectation says both; using 001) ---
  finding: attestation 001 (batchK8/pp-repro-v2) expected on stackB per catalog (dated 2026-09-10) but MISSING there
  result: FAIL  [OK — names attestation 001 and stack 'stackB']

--- Scenario: 3. unexpected filing, no catalog entry anywhere ---
  finding: unrecognized attestation discovered on stackA: requestHash=0xabababababababababababababababababababababababababababababababab — matches no EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; add a dated catalog entry (or investigate as unauthorized) before this can pass
  result: FAIL  [OK — names the unrecognized requestHash and stack 'stackA']

--- Scenario: 4a. asymmetric entry (SYNTH-A), absent everywhere (its natural, unperturbed state) ---
  finding: attestation SYNTH-A (solo/pp-repro-v2) expected on stackA per catalog (dated SYNTHETIC — not a real filing, added to test the asymmetric-expectation mechanism) but MISSING there
  result: FAIL  [OK — MISSING on stackA (expected there); silent on stackB (not expected there)]

--- Scenario: 4b. asymmetric entry (SYNTH-A), simulated as filed on stackA ---
  note: SYNTH-A (solo/pp-repro-v2) present on stackA — EXPECTED (declared asymmetry: filed only on ['stackA'], dated SYNTHETIC — not a real filing, added to test the asymmetric-expectation mechanism)
  result: PASS  [OK — stackA presence is a note, not a finding; stackB stays silent]

============================================================
ALL 5 SCENARIOS BEHAVED AS EXPECTED.
selftest exit: 0
```

## Running it yourself

```bash
pip install web3 eth_abi

python3 scripts/stack_drift_canary.py \
    --config-a config.example.json --config-b config.example.json

python3 scripts/selftest_drift_canary_invariant.py \
    --config-a config.example.json --config-b config.example.json

# needs your own circuit artifacts — see Prerequisites above
python3 scripts/verifier_freshness_guard.py /path/to/your/artifacts YourVerifier.sol
```

`--config-a`/`--config-b`/`--rpc-url`/`--abi-dir` can each also be set via
`CANARY_CONFIG_A` / `CANARY_CONFIG_B` / `CANARY_RPC_URL` / `CANARY_ABI_DIR`
environment variables. Both canary scripts print a clear error and exit
if a required config path is missing or a config file lacks a required key —
they never silently fall back to any hardcoded deployment.

## License

MIT — see `LICENSE`.
