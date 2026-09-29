#!/usr/bin/env python3
"""
stack_drift_canary.py — a drift canary for two deployments of the
same on-chain system that are supposed to stay cryptographically
equivalent.

The motivating defect: two deployments of the same system are supposed to
stay identical in every way that describes "the same model, correctly
deployed" — but nothing enforces that automatically. They drift the
moment only one of the two is redeployed, re-attested, or re-registered,
and nothing else notices — the two stacks just quietly stop agreeing,
and nobody finds out until someone happens to compare them by hand. This
script is that comparison, made repeatable and automatic.

A simpler approach — hardcoding an absolute count per circuit ("the
batch circuit has exactly four attestations on both stacks, solo has
zero on both") instead of an explicit catalog — cannot tell an intended,
declared asymmetry (an attestation that's only ever supposed to exist on
one of the two deployments) apart from an actual defect; it just fails
in both cases, with no way to tell the two apart short of reading the
diff by hand. The catalog below
(EXPECTED_ATTESTATIONS) replaces both absolute checks: every attestation
this script is willing to recognize is listed once, dated, with an
explicit statement of which of the two stacks it is expected on. An
attestation that shows up anywhere the catalog doesn't expect it, or is
missing anywhere the catalog does expect it, is a finding. An attestation
correctly present where the catalog says it should be is a note, not a
finding — including the (common, expected) case where it's declared for
only one of the two stacks.

Read-only. No private key of any kind is needed — every check here is a
public RPC read plus locally-computed hashes from small ABI files
checked into this repo. Safe to run at any time, by anyone, against
public state.

What this DOES compare between "stack A" and "stack B" (things that must
be identical because they describe the same real model, not because the
two stacks are the same deployment):
  - Live, metadata-stripped bytecode hash of each verifier (solo, batch)
    on BOTH stacks, re-derived from eth_getCode right now — not a value
    recorded at deploy time. Catches either stack's verifier silently
    drifting from the canonical vk.key (redeploy, wrong artifact, etc.)
  - vkHashFile and bundleDigest per circuit label, as recorded in each
    stack's PassportAnchorV2 CircuitRecord — must match because both are
    keccak256/sha256 digests of the same source build artifacts,
    independent of which stack reads them.
  - numOutputs and hDummy in escrow.models(modelId) — structural facts
    about the model, not about the deployment.
  - Every attestation actually resolved on either registry, for either
    circuit, against an explicit REAL_ATTESTATIONS catalog below (the
    real-filings subset of EXPECTED_ATTESTATIONS — see that dict's own
    comment for the one "synthetic": True demo entry it also carries,
    which main() deliberately excludes from this live check).
    Divergence from the catalog fails; an asymmetry the catalog declares
    does not. Discovery of "what's actually resolved" is NOT a guessed
    sweep of known attesters/tags (that was the old absolute check's
    blind spot — a filing under an attester or tag this script had never
    heard of would have gone undetected). It calls
    getValidatorRequests(filerAddress) on each stack's own registry,
    i.e. every requestHash that stack's own filing key has ever written
    a response for, full stop. That is complete by construction, as long
    as that project's registries are only ever resolved by that stack's
    own filer key — nothing filed under it can be missed regardless of
    which attester/tag/circuit it turns out to encode.

What this deliberately does NOT compare (expected, permanent differences,
not drift):
  - Contract addresses (escrow/registry/anchor/verifier) — different by
    design; comparing them would be checking that the separation the two
    stacks exist for has failed.
  - Deployer/filer addresses — a different key per stack, by design.
  - Gas costs, nonces, balances, tx hashes — bookkeeping with no
    correctness meaning across stacks.
  - artifactsURI / predicateVersion strings — a policy choice about where
    documentation lives, not a cryptographic invariant. Not checked here
    on purpose.

Configuration: this script never hardcodes which two deployments it is
comparing. Point it at two JSON config files shaped like
config.example.json — one per stack — via --config-a/--config-b or the
CANARY_CONFIG_A/CANARY_CONFIG_B environment variables. The shipped
config.example.json describes one real, publicly checkable deployment;
running with --config-a config.example.json --config-b config.example.json
compares that one deployment against itself, which is a
self-consistency check (it will always agree with itself) and a
demonstration of the mechanism, not a live drift check. Real use requires
a second config file pointing at your own second deployment. The bundled
EXPECTED_ATTESTATIONS catalog reflects what is actually filed on the
deployment config.example.json describes; if you point stack B at your
own deployment with a different filing history, edit this catalog to
match what you expect to be true of it.

Usage:
    python3 stack_drift_canary.py --config-a A.json --config-b B.json
Exit code 0 = no drift found. Exit code 1 = drift found (details printed).
"""
import argparse
import json
import os
import sys

from eth_abi import encode as abi_encode
from web3 import Web3

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_ABI_DIR = os.path.join(PROJECT_ROOT, "abi")
DEFAULT_RPC_URL = "https://sepolia.base.org"

PASSPORT_DOMAIN_STR = "zkml-passport-v1"
TAG_REPRO = "pp-repro-v2"
TAG_BYTECODE = "pp-bytecode-v1"
TAG_DOCKER = "pp-repro-docker-v1"

ATTESTER_MAHA = Web3.to_checksum_address("0x74780848E8b8c89Cf00a3294df6051ed2Ab019A9")
ATTESTER_BITSANITY = Web3.to_checksum_address("0x5b953A66Eb0826c13Ca2aF80E0C36557cC6a1a96")
ATTESTER_NSGOODS = Web3.to_checksum_address("0x57fF0F084Cba33e6761503f90eEF0Da9F159350c")

# Ethereum's conventional "burn address" pattern — used here only as an
# obviously-fake attester for the SYNTHETIC catalog entry below. It is not
# a real attester and was never used to file anything.
ATTESTER_SYNTHETIC_DEMO = Web3.to_checksum_address("0x000000000000000000000000000000000000dEaD")

STACKS = ("stackA", "stackB")

REQUIRED_STACK_KEYS = ("filerAddress", "registryV2", "escrow", "anchorV2", "modelId")

# EXPECTED_ATTESTATIONS — the one place this canary's notion of "expected"
# lives. Editing this dict is a separate act from filing an attestation,
# and nothing forces the two to happen together — that gap is what makes
# staleness possible, and the reason discovery below never consults this
# dict to decide what to look for. Discovery reads every requestHash a
# stack's own filer key has ever resolved, in full, via
# getValidatorRequests() (see main()). This dict is only consulted AFTER
# discovery, to classify what was found. The consequence: filing a new
# attestation without adding a dated entry here does not make the canary
# quietly keep passing — the next run finds a requestHash matching
# nothing in this catalog and fails with "unrecognized attestation
# discovered," naming the stack and the hash. The catalog can go stale;
# it cannot go stale silently.
#
# The entries below are the real attestations filed against the
# deployment config.example.json describes (see README). They are declared
# expected on BOTH stack roles here because the shipped reference
# config points both roles at that same deployment — so for the
# reference run, "expected on both" is simply true. The per-entry
# `expected_stacks` field can name just one role (see the module
# docstring / README): that is how you would declare a real, deliberate
# asymmetry once stack B is your own separate deployment with its own
# filing history.
#
# entry: {circuit, tag, attester, expected_stacks, declared}
#   circuit         "solo" | "batchK8"
#   tag             pp-repro-v2 | pp-bytecode-v1 | pp-repro-docker-v1
#   attester        the address baked into the requestHash preimage
#   expected_stacks which of STACKS this attestation is filed on
#   declared        date this entry was added, so a human skimming the
#                   catalog can see how fresh it is
#
# One entry below, "SYNTH-A", is marked "synthetic": True. It does not
# describe any real filing — it was never filed on any registry, on
# either stack, and never will be. It exists purely so the asymmetric
# branch of this catalog's logic (an attestation declared expected on
# only one stack) is exercised by something other than eyeballing the
# code: see selftest_drift_canary_invariant.py's Scenario 4, which reads
# this exact entry to prove that (a) an attestation genuinely absent from
# the stack it's expected on is a finding, (b) the same absence on the
# stack it's NOT expected on is correctly silent, and (c) a simulated
# filing on the expected stack turns the finding into a note. Because it
# is fictitious, main() below excludes any "synthetic": True entry from
# the real chain comparison it reports — a live run has no reason to
# expect a made-up attestation to exist, and would otherwise report a
# permanent, meaningless "MISSING" finding for it forever.
EXPECTED_ATTESTATIONS = {
    "001": {"circuit": "batchK8", "tag": TAG_REPRO,    "attester": ATTESTER_MAHA,      "expected_stacks": {"stackA", "stackB"}, "declared": "2026-09-10"},
    "002": {"circuit": "batchK8", "tag": TAG_REPRO,    "attester": ATTESTER_BITSANITY, "expected_stacks": {"stackA", "stackB"}, "declared": "2026-09-10"},
    "003": {"circuit": "batchK8", "tag": TAG_REPRO,    "attester": ATTESTER_NSGOODS,   "expected_stacks": {"stackA", "stackB"}, "declared": "2026-09-10"},
    "004": {"circuit": "batchK8", "tag": TAG_BYTECODE, "attester": ATTESTER_NSGOODS,   "expected_stacks": {"stackA", "stackB"}, "declared": "2026-09-10"},
    "005": {"circuit": "solo",    "tag": TAG_REPRO,    "attester": ATTESTER_NSGOODS,   "expected_stacks": {"stackA", "stackB"}, "declared": "2026-09-15"},
    "006a": {"circuit": "solo",    "tag": TAG_DOCKER,  "attester": ATTESTER_NSGOODS,   "expected_stacks": {"stackA", "stackB"}, "declared": "2026-09-17"},
    "006b": {"circuit": "batchK8", "tag": TAG_DOCKER,  "attester": ATTESTER_NSGOODS,   "expected_stacks": {"stackA", "stackB"}, "declared": "2026-09-17"},
    "SYNTH-A": {
        "circuit": "solo", "tag": TAG_REPRO, "attester": ATTESTER_SYNTHETIC_DEMO,
        "expected_stacks": {"stackA"}, "declared": "SYNTHETIC — not a real filing, added to test the asymmetric-expectation mechanism",
        "synthetic": True,
    },
}

# The subset of EXPECTED_ATTESTATIONS that describes real, actually-filed
# attestations — i.e. everything except "synthetic": True entries. This is
# what main() below checks against live chain state.
REAL_ATTESTATIONS = {aid: entry for aid, entry in EXPECTED_ATTESTATIONS.items() if not entry.get("synthetic")}


def load_stack_config(path: str) -> dict:
    if not path:
        raise SystemExit(
            "Missing stack config path. Pass --config-a/--config-b, or set "
            "CANARY_CONFIG_A/CANARY_CONFIG_B, to a JSON file shaped like "
            "config.example.json."
        )
    if not os.path.exists(path):
        raise SystemExit(f"Stack config file not found: {path}")
    with open(path) as f:
        cfg = json.load(f)
    missing = [k for k in REQUIRED_STACK_KEYS if k not in cfg]
    if missing:
        raise SystemExit(f"Stack config {path} is missing required key(s): {', '.join(missing)}")
    return cfg


def load_artifact(name: str, abi_dir: str = DEFAULT_ABI_DIR) -> dict:
    with open(os.path.join(abi_dir, f"{name}.json")) as f:
        return json.load(f)


def strip_cbor_metadata(code_hex: str) -> str:
    h = code_hex[2:] if code_hex.startswith("0x") else code_hex
    if len(h) < 4:
        return code_hex
    meta_len_bytes = int(h[-4:], 16)
    meta_len_hexchars = meta_len_bytes * 2
    cut = len(h) - 4 - meta_len_hexchars
    if cut <= 0 or cut > len(h):
        return code_hex
    return "0x" + h[:cut]


def live_bytecode_hash(w3: Web3, addr: str) -> str:
    code = w3.eth.get_code(Web3.to_checksum_address(addr))
    code_hex = "0x" + code.hex() if not code.hex().startswith("0x") else code.hex()
    stripped = strip_cbor_metadata(code_hex)
    return Web3.keccak(bytes.fromhex(stripped[2:])).hex()


def compute_request_hash(chain_id: int, slot_a: bytes, slot_b: bytes, tag: str, attester: str) -> bytes:
    domain = bytes(Web3.keccak(text=PASSPORT_DOMAIN_STR))
    tag_hash = bytes(Web3.keccak(text=tag))
    packed = abi_encode(
        ["bytes32", "uint256", "bytes32", "bytes32", "bytes32", "address"],
        [domain, chain_id, slot_a, slot_b, tag_hash, Web3.to_checksum_address(attester)],
    )
    return bytes(Web3.keccak(packed))


def get_circuits(w3, anchor_addr, model_id_bytes, abi_dir: str = DEFAULT_ABI_DIR):
    artifact = load_artifact("PassportAnchorV2", abi_dir)
    anchor = w3.eth.contract(address=Web3.to_checksum_address(anchor_addr), abi=artifact["abi"])
    records = anchor.functions.getCircuits(model_id_bytes).call()
    return {r[0]: {"verifierAddr": r[1], "vkHashFile": r[2].hex(), "vkHashBytecode": r[3].hex(), "bundleDigest": r[4].hex()} for r in records}


def get_model(w3, escrow_addr, model_id_bytes, abi_dir: str = DEFAULT_ABI_DIR):
    artifact = load_artifact("ZkInferenceEscrowV2", abi_dir)
    escrow = w3.eth.contract(address=Web3.to_checksum_address(escrow_addr), abi=artifact["abi"])
    vk_solo, vk_batch, num_outputs, h_dummy, registered = escrow.functions.models(model_id_bytes).call()
    return {"vkSolo": vk_solo, "vkBatch": vk_batch, "numOutputs": num_outputs, "hDummy": h_dummy, "registered": registered}


def discover_filed(w3, registry_addr: str, filer_addr: str, abi_dir: str = DEFAULT_ABI_DIR) -> set:
    """Every requestHash `filer_addr` has ever gotten a response written for,
    on this one registry. Complete by construction (no attester/tag/circuit
    guessing): getValidatorRequests returns every hash ever filed naming
    filer_addr as validatorAddress, and validationResponse can only be
    written by that same validatorAddress — so a resolved (lastUpdate != 0)
    entry here was necessarily written by filer_addr itself, never by a
    third party permissionlessly calling validationRequest against this
    (access-control-free, per the contract's own docstring) registry."""
    artifact = load_artifact("MockValidationRegistry", abi_dir)
    registry = w3.eth.contract(address=Web3.to_checksum_address(registry_addr), abi=artifact["abi"])
    candidate_hashes = registry.functions.getValidatorRequests(Web3.to_checksum_address(filer_addr)).call()
    resolved = set()
    for h in candidate_hashes:
        status = registry.functions.getValidationStatus(h).call()
        if status[5] != 0:  # lastUpdate != 0 -> a response was actually written
            resolved.add(h.hex().lower().replace("0x", ""))
    return resolved


def compute_catalog_hashes(catalog: dict, circuits_by_stack: dict, chain_id: int) -> dict:
    """requestHash for every (catalog id, stack) pair, using that STACK's own
    live vkHashFile/bundleDigest/vkHashBytecode for the entry's circuit —
    not assumed equal across stacks, even though checks [1]-[3] above
    already confirm they are today."""
    out = {}
    for aid, entry in catalog.items():
        circuit, tag, attester = entry["circuit"], entry["tag"], entry["attester"]
        for stack in STACKS:
            c = circuits_by_stack[stack].get(circuit)
            if c is None:
                continue
            slot_a = bytes.fromhex(c["vkHashFile"])
            if tag in (TAG_REPRO, TAG_DOCKER):
                slot_b = bytes.fromhex(c["bundleDigest"])
            elif tag == TAG_BYTECODE:
                slot_b = bytes.fromhex(c["vkHashBytecode"])
            else:
                raise ValueError(f"catalog entry {aid} has unknown tag {tag!r}")
            h = compute_request_hash(chain_id, slot_a, slot_b, tag, attester)
            out[(aid, stack)] = h.hex().lower().replace("0x", "")
    return out


def evaluate_attestations(catalog: dict, req_hash_by_id_stack: dict, discovered: dict) -> tuple:
    """Pure comparison: no chain access, no filesystem access. Takes
    - catalog: the EXPECTED_ATTESTATIONS-shaped dict
    - req_hash_by_id_stack: {(id, stack): hex-no-0x} from compute_catalog_hashes
    - discovered: {stack: set(hex-no-0x)} from discover_filed, one entry per
      stack in STACKS
    Returns (findings, notes)."""
    findings = []
    notes = []
    for stack in STACKS:
        disc = set(discovered.get(stack, set()))
        matched = set()
        for aid, entry in sorted(catalog.items()):
            if (aid, stack) not in req_hash_by_id_stack:
                continue
            h = req_hash_by_id_stack[(aid, stack)]
            expected_here = stack in entry["expected_stacks"]
            present = h in disc
            if present:
                matched.add(h)
            if expected_here and present:
                if entry["expected_stacks"] != set(STACKS):
                    notes.append(
                        f"{aid} ({entry['circuit']}/{entry['tag']}) present on {stack} — "
                        f"EXPECTED (declared asymmetry: filed only on {sorted(entry['expected_stacks'])}, "
                        f"dated {entry['declared']})"
                    )
                else:
                    notes.append(f"{aid} ({entry['circuit']}/{entry['tag']}) present on {stack} — expected")
            elif expected_here and not present:
                findings.append(
                    f"attestation {aid} ({entry['circuit']}/{entry['tag']}) expected on {stack} "
                    f"per catalog (dated {entry['declared']}) but MISSING there"
                )
            elif (not expected_here) and present:
                findings.append(
                    f"attestation {aid} ({entry['circuit']}/{entry['tag']}) present on {stack} but "
                    f"catalog expects it only on {sorted(entry['expected_stacks'])} — undeclared filing"
                )
        unrecognized = disc - matched
        for h in sorted(unrecognized):
            findings.append(
                f"unrecognized attestation discovered on {stack}: requestHash=0x{h} — matches no "
                f"EXPECTED_ATTESTATIONS entry for either circuit/tag/attester combination on this stack; "
                f"add a dated catalog entry (or investigate as unauthorized) before this can pass"
            )
    return findings, notes


def parse_args():
    p = argparse.ArgumentParser(description="Drift canary comparing two deployments of the same escrow/passport stack.")
    p.add_argument("--config-a", default=os.environ.get("CANARY_CONFIG_A"), help="JSON config for stack A (or set CANARY_CONFIG_A)")
    p.add_argument("--config-b", default=os.environ.get("CANARY_CONFIG_B"), help="JSON config for stack B (or set CANARY_CONFIG_B)")
    p.add_argument("--rpc-url", default=os.environ.get("CANARY_RPC_URL", DEFAULT_RPC_URL), help="RPC endpoint both stacks live on (or set CANARY_RPC_URL)")
    p.add_argument("--abi-dir", default=os.environ.get("CANARY_ABI_DIR", DEFAULT_ABI_DIR), help="Directory containing PassportAnchorV2.json / ZkInferenceEscrowV2.json / MockValidationRegistry.json")
    return p.parse_args()


def main():
    args = parse_args()
    configs = {"stackA": load_stack_config(args.config_a), "stackB": load_stack_config(args.config_b)}
    abi_dir = args.abi_dir

    w3 = Web3(Web3.HTTPProvider(args.rpc_url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to {args.rpc_url}")

    chain_id = w3.eth.chain_id
    model_id_bytes = {stack: bytes.fromhex(configs[stack]["modelId"][2:]) for stack in STACKS}

    findings = []

    print(f"Comparing stackA ({configs['stackA'].get('label', args.config_a)}) vs "
          f"stackB ({configs['stackB'].get('label', args.config_b)}) on chainId {chain_id}\n")

    print("[1] Live bytecode hash, both circuits, both stacks...")
    model_by_stack = {stack: get_model(w3, configs[stack]["escrow"], model_id_bytes[stack], abi_dir) for stack in STACKS}

    for label, field in [("solo", "vkSolo"), ("batch", "vkBatch")]:
        addr_a, addr_b = model_by_stack["stackA"][field], model_by_stack["stackB"][field]
        hash_a, hash_b = live_bytecode_hash(w3, addr_a), live_bytecode_hash(w3, addr_b)
        match = hash_a == hash_b
        print(f"  {label}: stackA={hash_a[:18]}...  stackB={hash_b[:18]}...  match={match}")
        if not match:
            findings.append(f"{label} verifier bytecode diverged: stackA={hash_a} stackB={hash_b}")

    print("\n[2] numOutputs / hDummy (escrow.models)...")
    for field in ("numOutputs", "hDummy"):
        val_a, val_b = model_by_stack["stackA"][field], model_by_stack["stackB"][field]
        match = val_a == val_b
        print(f"  {field}: stackA={val_a}  stackB={val_b}  match={match}")
        if not match:
            findings.append(f"{field} diverged: stackA={val_a} stackB={val_b}")

    print("\n[3] Per-circuit vkHashFile / bundleDigest (PassportAnchorV2.getCircuits)...")
    circuits_by_stack = {stack: get_circuits(w3, configs[stack]["anchorV2"], model_id_bytes[stack], abi_dir) for stack in STACKS}
    for label in ("solo", "batchK8"):
        have_a = label in circuits_by_stack["stackA"]
        have_b = label in circuits_by_stack["stackB"]
        if not (have_a and have_b):
            findings.append(f"circuit '{label}' missing on one stack: stackA_has={have_a} stackB_has={have_b}")
            continue
        for field in ("vkHashFile", "bundleDigest"):
            val_a = circuits_by_stack["stackA"][label][field]
            val_b = circuits_by_stack["stackB"][label][field]
            match = val_a == val_b
            print(f"  {label}.{field}: match={match}")
            if not match:
                findings.append(f"{label}.{field} diverged: stackA={val_a} stackB={val_b}")

    print("\n[4] Attestations, both circuits, against the REAL_ATTESTATIONS catalog...")
    print("    (excludes the catalog's one \"synthetic\": True demo entry — see EXPECTED_ATTESTATIONS)")
    req_hash_by_id_stack = compute_catalog_hashes(EXPECTED_ATTESTATIONS, circuits_by_stack, chain_id)

    discovered = {}
    for stack in STACKS:
        disc = discover_filed(w3, configs[stack]["registryV2"], configs[stack]["filerAddress"], abi_dir)
        discovered[stack] = disc
        print(f"  {stack}: {len(disc)} resolved requestHash(es) discovered via getValidatorRequests({configs[stack]['filerAddress'][:10]}...)")

    attestation_findings, attestation_notes = evaluate_attestations(REAL_ATTESTATIONS, req_hash_by_id_stack, discovered)
    for n in attestation_notes:
        print(f"  {n}")
    findings.extend(attestation_findings)

    print("\n" + "=" * 60)
    if findings:
        print(f"DRIFT DETECTED ({len(findings)} finding(s)):")
        for f in findings:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("NO DRIFT — both stacks agree on every checked invariant.")
        sys.exit(0)


if __name__ == "__main__":
    main()
