#!/usr/bin/env python3
"""
selftest_drift_canary_invariant.py — exercises evaluate_attestations()
(stack_drift_canary.py) against real chain data plus two
controlled perturbations, WITHOUT sending any transaction or needing a
private key.

The motivating concern: evaluate_attestations() is the function that
decides whether the catalog-based attestation check passes or fails. A
pure function like that can look correct by inspection while actually
ignoring its inputs — e.g. a bug that always returns "no findings"
regardless of what was actually discovered on chain would be invisible
from a single real run, because a real run's expected and actual data
usually agree by construction. This selftest closes that gap: it reads
real, live, on-chain data once, then perturbs a local copy of it in two
different ways to prove the evaluator's pass/fail behavior actually
tracks what it's given, not a hardcoded assumption about what it will be
given. Not itself part of the drift canary's normal run — this checks the
checker.

Scenario 1 uses the actual live requestHashes (computed the same way
main() does, over real on-chain circuit digests) and the actual
discovered sets from a real run against both stacks' registries — real
chain data, read live, not fabricated. Scenarios 2 and 3 take that same
real discovered data and perturb it in Python only (remove one hash /
inject a fake one) to prove evaluate_attestations() — a pure function, no
chain access — actually looks at what's discovered rather than
hardcoding a pass. Scenarios 1-3 all check against REAL_ATTESTATIONS —
the same real-filings-only subset main() checks live state against.

Scenario 4 covers the one thing 1-3 don't: a per-entry `expected_stacks`
declaring an attestation expected on only ONE stack, not both. It reads
EXPECTED_ATTESTATIONS' one "synthetic": True entry (see that dict's
comment in stack_drift_canary.py) — a fictitious attestation that
was never filed anywhere, kept only to exercise this branch — and proves
both directions of the asymmetric-expectation mechanism: absence on the
stack it IS expected on is a finding, absence on the stack it is NOT
expected on is correctly silent (4a, using real, unperturbed data, since
the synthetic entry's natural state already is "absent everywhere"), and
a simulated filing on the expected stack turns that finding into a note
without disturbing the still-silent other stack (4b, one perturbation).
"""
import argparse
import os
import sys

from web3 import Web3

sys.path.insert(0, os.path.dirname(__file__))
from stack_drift_canary import (  # noqa: E402
    DEFAULT_ABI_DIR, DEFAULT_RPC_URL, EXPECTED_ATTESTATIONS, REAL_ATTESTATIONS,
    STACKS, compute_catalog_hashes, discover_filed, evaluate_attestations,
    get_circuits, load_stack_config,
)


def run(label, catalog, req_hash_by_id_stack, discovered, expect_pass):
    findings, notes = evaluate_attestations(catalog, req_hash_by_id_stack, discovered)
    passed = len(findings) == 0
    verdict = "PASS" if passed else "FAIL"
    ok = "OK" if passed == expect_pass else "**WRONG** (expected {})".format("PASS" if expect_pass else "FAIL")
    print(f"\n--- Scenario: {label} ---")
    print(f"  result: {verdict}  [{ok}]")
    if notes:
        for n in notes:
            print(f"  note: {n}")
    if findings:
        for f in findings:
            print(f"  finding: {f}")
    assert passed == expect_pass, f"scenario {label!r} did not behave as expected"


def parse_args():
    p = argparse.ArgumentParser(description="Selftest for stack_drift_canary.py's evaluate_attestations().")
    p.add_argument("--config-a", default=os.environ.get("CANARY_CONFIG_A"))
    p.add_argument("--config-b", default=os.environ.get("CANARY_CONFIG_B"))
    p.add_argument("--rpc-url", default=os.environ.get("CANARY_RPC_URL", DEFAULT_RPC_URL))
    p.add_argument("--abi-dir", default=os.environ.get("CANARY_ABI_DIR", DEFAULT_ABI_DIR))
    return p.parse_args()


def main():
    args = parse_args()
    configs = {"stackA": load_stack_config(args.config_a), "stackB": load_stack_config(args.config_b)}

    w3 = Web3(Web3.HTTPProvider(args.rpc_url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to {args.rpc_url}")

    chain_id = w3.eth.chain_id
    model_id_bytes = {stack: bytes.fromhex(configs[stack]["modelId"][2:]) for stack in STACKS}

    circuits_by_stack = {stack: get_circuits(w3, configs[stack]["anchorV2"], model_id_bytes[stack], args.abi_dir) for stack in STACKS}
    req_hash_by_id_stack = compute_catalog_hashes(EXPECTED_ATTESTATIONS, circuits_by_stack, chain_id)

    real_discovered = {
        stack: discover_filed(w3, configs[stack]["registryV2"], configs[stack]["filerAddress"], args.abi_dir)
        for stack in STACKS
    }
    print("Real discovered sets (live, read-only):")
    for stack in STACKS:
        print(f"  {stack}: {len(real_discovered[stack])} resolved hash(es)")

    # Scenario 1 — current state, real chain data, checked against the same
    # real-filings-only catalog main() uses: passes.
    run("1. current state (real chain data)", REAL_ATTESTATIONS, req_hash_by_id_stack,
        real_discovered, expect_pass=True)

    # Scenario 2 — a filing present on one stack and absent from the other, where the
    # expectation says both. Take a real entry expected on both stacks and drop it
    # from stackB's discovered set only.
    sample_id = next(aid for aid, entry in REAL_ATTESTATIONS.items() if entry["expected_stacks"] == set(STACKS))
    h_sample_b = req_hash_by_id_stack.get((sample_id, "stackB"))
    perturbed = {stack: set(real_discovered[stack]) for stack in STACKS}
    assert h_sample_b is not None and h_sample_b in perturbed["stackB"], \
        f"{sample_id} must actually be present on stackB in real data for this test to mean anything"
    perturbed["stackB"].discard(h_sample_b)
    findings, notes = evaluate_attestations(REAL_ATTESTATIONS, req_hash_by_id_stack, perturbed)
    print(f"\n--- Scenario: 2. present on one stack, missing on the other (expectation says both; using {sample_id}) ---")
    for f in findings:
        print(f"  finding: {f}")
    assert findings, f"removing {sample_id} from stackB's discovered set must fail"
    assert any(sample_id in f and "stackB" in f and "MISSING" in f for f in findings), \
        f"the finding must name attestation {sample_id} and the stackB stack specifically"
    print(f"  result: FAIL  [OK — names attestation {sample_id} and stack 'stackB']")

    # Scenario 3 — an unexpected filing appearing where the expectation has none. Inject a
    # fabricated requestHash into stackA's discovered set that matches no catalog entry.
    fake_hash = ("ab" * 32)
    perturbed2 = {stack: set(real_discovered[stack]) for stack in STACKS}
    assert fake_hash not in perturbed2["stackA"]
    perturbed2["stackA"].add(fake_hash)
    findings, notes = evaluate_attestations(REAL_ATTESTATIONS, req_hash_by_id_stack, perturbed2)
    print("\n--- Scenario: 3. unexpected filing, no catalog entry anywhere ---")
    for f in findings:
        print(f"  finding: {f}")
    assert findings, "an uncatalogued discovered hash must fail"
    assert any("unrecognized attestation" in f and fake_hash in f and "stackA" in f for f in findings), \
        "the finding must name the offending requestHash and stack"
    print("  result: FAIL  [OK — names the unrecognized requestHash and stack 'stackA']")

    # Scenario 4 — an attestation declared expected on only ONE stack (a
    # deliberate, documented asymmetry). Found generically, the same way
    # Scenario 2 finds a symmetric entry generically — not hardcoded to an ID.
    # Uses the FULL EXPECTED_ATTESTATIONS catalog (the only scenario that does),
    # since this is exactly the entry REAL_ATTESTATIONS excludes.
    asym_id, asym_entry = next(
        (aid, entry) for aid, entry in EXPECTED_ATTESTATIONS.items()
        if entry["expected_stacks"] != set(STACKS)
    )
    expected_stack = next(iter(asym_entry["expected_stacks"]))
    other_stack = next(s for s in STACKS if s != expected_stack)
    h_asym_expected = req_hash_by_id_stack[(asym_id, expected_stack)]

    # 4a — natural state, NO perturbation: this entry was never filed anywhere
    # for real, so it is already absent from both stacks' real discovered sets.
    # That absence must be a finding on the stack it's expected on, and must
    # produce no finding at all on the stack it's not.
    assert h_asym_expected not in real_discovered[expected_stack], \
        f"{asym_id} must genuinely be absent from {expected_stack} in real data for this half of the test to mean anything"
    findings, notes = evaluate_attestations(EXPECTED_ATTESTATIONS, req_hash_by_id_stack, real_discovered)
    print(f"\n--- Scenario: 4a. asymmetric entry ({asym_id}), absent everywhere (its natural, unperturbed state) ---")
    for f in findings:
        if asym_id in f:
            print(f"  finding: {f}")
    assert any(asym_id in f and expected_stack in f and "MISSING" in f for f in findings), \
        f"absence on {expected_stack} (where {asym_id} IS expected) must be a finding"
    assert not any(asym_id in f and other_stack in f for f in findings), \
        f"absence on {other_stack} (where {asym_id} is NOT expected) must not be a finding at all"
    print(f"  result: FAIL  [OK — MISSING on {expected_stack} (expected there); silent on {other_stack} (not expected there)]")

    # 4b — one perturbation: simulate the attestation actually being filed on
    # the stack it's expected on. The finding above must become a note, and
    # the other stack — still untouched, still absent — must remain silent.
    perturbed3 = {stack: set(real_discovered[stack]) for stack in STACKS}
    perturbed3[expected_stack].add(h_asym_expected)
    findings, notes = evaluate_attestations(EXPECTED_ATTESTATIONS, req_hash_by_id_stack, perturbed3)
    print(f"\n--- Scenario: 4b. asymmetric entry ({asym_id}), simulated as filed on {expected_stack} ---")
    for n in notes:
        if asym_id in n:
            print(f"  note: {n}")
    for f in findings:
        if asym_id in f:
            print(f"  finding: {f}")
    assert not any(asym_id in f for f in findings), \
        f"a simulated filing on {expected_stack} (where it IS expected) must not produce any finding"
    assert any(asym_id in n and expected_stack in n and "declared asymmetry" in n for n in notes), \
        f"presence on {expected_stack} must be reported as a declared-asymmetry note, not silently absorbed"
    print(f"  result: PASS  [OK — {expected_stack} presence is a note, not a finding; {other_stack} stays silent]")

    print("\n" + "=" * 60)
    print("ALL 5 SCENARIOS BEHAVED AS EXPECTED.")


if __name__ == "__main__":
    main()
