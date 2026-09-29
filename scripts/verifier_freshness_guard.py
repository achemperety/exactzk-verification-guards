#!/usr/bin/env python3
"""
Drift canary for EZKL-generated Halo2Verifier .sol files.

The motivating defect: a Halo2Verifier.sol bakes the verification key's
curve-point constants in as literal bytecode at generation time. If the
underlying vk.key/srs.bin/settings.json are ever regenerated later
without regenerating the .sol alongside them, the on-disk .sol silently
keeps verifying proofs against a VK that no longer matches the one
actually used for proving. This is the kind of failure that specifically
does not show up where you'd expect it to: an in-process verify call and
a test suite that separately re-derives its own fixture can both keep
passing, while every real on-chain verifyProof() call reverts, because
they're not actually exercising the same bytecode as the stale .sol
would be. This exact failure mode was found in production once: a
deployed verifier had been built from an earlier VK state than the one
the canonical vk.key now represented, and it turned out two different
deploy scripts disagreed about whether to regenerate the .sol before
deploying — one did, one silently reused whatever was already on disk.

This module closes the gap: it regenerates the verifier from the CURRENT
vk.key/settings.json/srs.bin, deploys both the regenerated copy and the
on-disk file to a throwaway local Anvil instance it starts itself (never
the real deploy target — safe to call before any real deploy), and
compares their metadata-stripped runtime bytecode hashes. Metadata must
be stripped first: solc's default bytecodeHash=ipfs mode encodes the
compile-time filesystem path into the trailing CBOR metadata blob, so raw
eth_getCode output diverges across build hosts even for two genuinely
byte-identical deployments of the same source.
"""
import asyncio
import os
import subprocess
import tempfile
import time

FOUNDRY_BIN = os.path.expanduser("~/.foundry/bin")
_SCRATCH_ANVIL_PORT = 8999
# Anvil's well-known, publicly documented default dev account 0 private
# key — used only to fund throwaway deploys to the scratch Anvil this
# module starts and tears down itself. Never used against any real chain.
_SCRATCH_PRIVATE_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def strip_cbor_metadata(code_hex: str) -> str:
    """Strip solc's trailing CBOR metadata blob from deployed bytecode so two
    genuinely identical contracts compiled on different machines/paths hash
    the same. Keep any other copy of this function in this project in sync —
    do not fork the algorithm."""
    h = code_hex[2:] if code_hex.startswith("0x") else code_hex
    if len(h) < 4:
        return code_hex
    meta_len_bytes = int(h[-4:], 16)
    meta_len_hexchars = meta_len_bytes * 2
    cut = len(h) - 4 - meta_len_hexchars
    if cut <= 0 or cut > len(h):
        return code_hex
    return "0x" + h[:cut]


async def _regen_sol(vk_path, settings_path, srs_path, out_sol_path, out_abi_path):
    import ezkl

    result = ezkl.create_evm_verifier(
        vk_path=vk_path,
        settings_path=settings_path,
        sol_code_path=out_sol_path,
        abi_path=out_abi_path,
        srs_path=srs_path,
        reusable=False,
    )
    if asyncio.iscoroutine(result) or asyncio.isfuture(result):
        result = await result


async def _deploy_and_hash(sol_path, rpc_url, private_key):
    import ezkl
    from web3 import Web3

    addr_path = tempfile.mktemp(suffix=".addr")
    result = ezkl.deploy_evm(
        addr_path=addr_path,
        rpc_url=rpc_url,
        sol_code_path=sol_path,
        optimizer_runs=1,
        private_key=private_key,
    )
    if asyncio.iscoroutine(result) or asyncio.isfuture(result):
        result = await result
    await asyncio.sleep(1)

    with open(addr_path) as f:
        addr = f.read().strip()

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    code = w3.eth.get_code(Web3.to_checksum_address(addr))
    code_hex = code.hex()
    if not code_hex.startswith("0x"):
        code_hex = "0x" + code_hex
    stripped = strip_cbor_metadata(code_hex)
    return Web3.keccak(bytes.fromhex(stripped[2:])).hex()


def assert_verifier_matches_current_vk(
    artifacts_dir: str,
    sol_filename: str,
    vk_name: str = "vk.key",
    settings_name: str = "settings.json",
    srs_name: str = "srs.bin",
    label: str = "verifier",
    fail_closed: bool = True,
) -> None:
    """Raise RuntimeError if the on-disk <sol_filename> doesn't match a fresh
    regeneration from the current vk.key/settings.json/srs.bin. Call this
    immediately before deploying any Halo2Verifier .sol — local or testnet.

    Starts and tears down its own scratch Anvil on port 8999; never touches
    the real deploy target.

    Defaults to fail-closed for every caller: keeping the invariant "no
    deploy script ever ships a stale verifier" unconditional, rather than
    dependent on which script someone happens to run, is exactly what
    would have caught the production incident this module was written
    after — one deploy path regenerated the .sol itself and would never
    have been affected either way, but the other silently reused whatever
    was on disk, and there was nothing forcing it to check first. Pass
    fail_closed=False explicitly only for a caller that has an equally
    strong, documented reason not to block.
    """
    on_disk_sol = os.path.join(artifacts_dir, sol_filename)
    if not os.path.exists(on_disk_sol):
        return  # nothing to compare against yet — caller's own deploy path will generate it

    vk_path = os.path.join(artifacts_dir, vk_name)
    settings_path = os.path.join(artifacts_dir, settings_name)
    srs_path = os.path.join(artifacts_dir, srs_name)

    with tempfile.TemporaryDirectory() as tmpdir:
        regen_sol = os.path.join(tmpdir, sol_filename)
        regen_abi = os.path.join(tmpdir, sol_filename.replace(".sol", ".abi"))

        print(f"  [freshness guard] regenerating {label} from current {vk_name} ...", flush=True)
        loop = asyncio.new_event_loop()
        loop.run_until_complete(_regen_sol(vk_path, settings_path, srs_path, regen_sol, regen_abi))
        loop.run_until_complete(asyncio.sleep(1))
        loop.close()

        anvil = subprocess.Popen(
            [os.path.join(FOUNDRY_BIN, "anvil"), "--port", str(_SCRATCH_ANVIL_PORT),
             "--block-time", "1", "--silent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        try:
            rpc_url = f"http://localhost:{_SCRATCH_ANVIL_PORT}"

            print(f"  [freshness guard] deploying regenerated {label} to scratch Anvil ...", flush=True)
            loop = asyncio.new_event_loop()
            regen_hash = loop.run_until_complete(_deploy_and_hash(regen_sol, rpc_url, _SCRATCH_PRIVATE_KEY))
            loop.run_until_complete(asyncio.sleep(1))
            loop.close()

            print(f"  [freshness guard] deploying on-disk {label} to scratch Anvil ...", flush=True)
            loop = asyncio.new_event_loop()
            ondisk_hash = loop.run_until_complete(_deploy_and_hash(on_disk_sol, rpc_url, _SCRATCH_PRIVATE_KEY))
            loop.run_until_complete(asyncio.sleep(1))
            loop.close()
        finally:
            anvil.terminate()
            anvil.wait()

    if regen_hash != ondisk_hash:
        message = (
            f"STALE VERIFIER: on-disk file does not match the current "
            f"{vk_name}/{settings_name}/{srs_name}.\n"
            f"  on-disk file                      : {on_disk_sol}\n"
            f"  on-disk stripped bytecode hash    : 0x{ondisk_hash}\n"
            f"  regenerated stripped bytecode hash: 0x{regen_hash}\n"
            f"Regenerate {sol_filename} (and any downstream fixture that embeds its "
            f"bytecode) before deploying."
        )
        if fail_closed:
            raise RuntimeError("STALE VERIFIER — refusing to deploy.\n" + message)
        print(f"  [freshness guard] WARNING (non-fatal — this deploy regenerates "
              f"{sol_filename} itself): {message}", flush=True)
        return
    print(f"  [freshness guard] {label} matches current {vk_name} "
          f"(stripped hash 0x{regen_hash[:12]}...)", flush=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Regenerate a Halo2Verifier.sol from its canonical vk.key/settings.json/srs.bin "
            "on a throwaway local Anvil, and fail if its bytecode does not match the on-disk copy."
        )
    )
    parser.add_argument("artifacts_dir", help="Directory containing the .sol file and vk.key/settings.json/srs.bin")
    parser.add_argument("sol_filename", help="Filename of the on-disk verifier .sol to check, e.g. Halo2Verifier.sol")
    parser.add_argument("--vk-name", default="vk.key")
    parser.add_argument("--settings-name", default="settings.json")
    parser.add_argument("--srs-name", default="srs.bin")
    parser.add_argument("--label", default="verifier")
    parser.add_argument("--no-fail-closed", action="store_true", help="Warn instead of raising on a mismatch")
    args = parser.parse_args()

    assert_verifier_matches_current_vk(
        args.artifacts_dir,
        args.sol_filename,
        vk_name=args.vk_name,
        settings_name=args.settings_name,
        srs_name=args.srs_name,
        label=args.label,
        fail_closed=not args.no_fail_closed,
    )
    print("OK")
