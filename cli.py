#!/usr/bin/env python3
"""
Command-Line Interface (CLI) for Crypto-StreamCipher-Engine
==========================================================
Interactive command-line tool for symmetric stream cipher operations,
LFSR keystream inspection, and cryptographic verification suites.

Module: cli.py
Project: Crypto-StreamCipher-Engine
"""

import sys
import os
import argparse
import binascii
from typing import Optional

from lfsr import LFSR, MAXIMAL_PRIMITIVE_TAPS
from cipher import (
    StreamCipher,
    derive_seed_from_key,
    calculate_entropy,
    calculate_avalanche_effect
)


# Terminal styling helpers
USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")

def _cyan(text: str) -> str:
    return f"\033[36m{text}\033[0m" if USE_COLOR else text

def _green(text: str) -> str:
    return f"\033[32m{text}\033[0m" if USE_COLOR else text

def _yellow(text: str) -> str:
    return f"\033[33m{text}\033[0m" if USE_COLOR else text

def _red(text: str) -> str:
    return f"\033[31m{text}\033[0m" if USE_COLOR else text

def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m" if USE_COLOR else text


BANNER = f"""
{_bold('┌────────────────────────────────────────────────────────┐')}
{_bold('│')}  {_cyan('CRYPTO-STREAMCIPHER-ENGINE')} :: {_yellow('Discrete Bitwise System')}  {_bold('│')}
{_bold('│')}  Deterministic LFSR PRNG & Symmetric Vernam Stream     {_bold('│')}
{_bold('└────────────────────────────────────────────────────────┘')}
"""


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Execute encryption command."""
    if not args.message and not args.file:
        print(_red("Error: Must provide either --message (-m) or --file (-f) to encrypt."), file=sys.stderr)
        return 1

    if not args.key:
        print(_red("Error: Encryption requires a key (--key / -k)."), file=sys.stderr)
        return 1

    cipher = StreamCipher(
        key=args.key,
        bit_length=args.bits,
        mode=args.mode,
        use_nonlinear_filter=not args.raw_linear
    )

    seed = cipher.seed
    print(BANNER)
    print(f"[*] Configuration: {_cyan(f'{args.bits}-bit LFSR')} (Mode: {args.mode}, Non-linear Filter: {not args.raw_linear})")
    print(f"[*] Derived Seed:  {_yellow(f'0x{seed:0{args.bits//4}X}')} ({seed})")

    # Read data
    if args.file:
        if not os.path.exists(args.file):
            print(_red(f"Error: Input file '{args.file}' not found."), file=sys.stderr)
            return 1
        with open(args.file, "rb") as f:
            plaintext_bytes = f.read()
        print(f"[*] Input Source:  File '{args.file}' ({len(plaintext_bytes)} bytes)")
    else:
        plaintext_bytes = args.message.encode("utf-8")
        print(f"[*] Input Message: \"{args.message}\" ({len(plaintext_bytes)} bytes)")

    # Execute XOR encryption
    ciphertext_bytes = cipher.encrypt(plaintext_bytes)
    hex_output = ciphertext_bytes.hex()
    entropy = calculate_entropy(ciphertext_bytes)

    print(f"[*] Ciphertext Entropy: {_green(f'{entropy:.3f}')} / 8.000 bits/byte")
    print("-" * 58)
    print(f"{_bold('CIPHERTEXT (Hex):')}")
    print(_cyan(hex_output))
    print("-" * 58)

    # Optional file output
    if args.out:
        if args.raw_binary:
            with open(args.out, "wb") as f:
                f.write(ciphertext_bytes)
            print(f"[+] Saved raw binary ciphertext to '{args.out}'.")
        else:
            with open(args.out, "w") as f:
                f.write(hex_output)
            print(f"[+] Saved hexadecimal ciphertext to '{args.out}'.")

    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Execute decryption command."""
    if not args.ciphertext and not args.file:
        print(_red("Error: Must provide either --ciphertext (-c) or --file (-f) to decrypt."), file=sys.stderr)
        return 1

    if not args.key:
        print(_red("Error: Decryption requires a key (--key / -k)."), file=sys.stderr)
        return 1

    cipher = StreamCipher(
        key=args.key,
        bit_length=args.bits,
        mode=args.mode,
        use_nonlinear_filter=not args.raw_linear
    )

    seed = cipher.seed
    print(BANNER)
    print(f"[*] Configuration: {_cyan(f'{args.bits}-bit LFSR')} (Mode: {args.mode}, Non-linear Filter: {not args.raw_linear})")
    print(f"[*] Derived Seed:  {_yellow(f'0x{seed:0{args.bits//4}X}')} ({seed})")

    # Read ciphertext
    if args.file:
        if not os.path.exists(args.file):
            print(_red(f"Error: File '{args.file}' not found."), file=sys.stderr)
            return 1
        with open(args.file, "rb") as f:
            content = f.read()

        # Check if content is hex string or raw bytes
        try:
            text_str = content.decode("utf-8").strip()
            # If valid hex string of even length, decode hex
            if all(c in "0123456789abcdefABCDEF" for c in text_str) and len(text_str) % 2 == 0:
                ct_bytes = bytes.fromhex(text_str)
            else:
                ct_bytes = content
        except UnicodeDecodeError:
            ct_bytes = content
    else:
        cleaned = args.ciphertext.strip().replace(" ", "").replace("\n", "")
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        try:
            ct_bytes = bytes.fromhex(cleaned)
        except ValueError as err:
            print(_red(f"Error: Invalid hex input: {err}"), file=sys.stderr)
            return 1

    # Execute XOR decryption
    decrypted_bytes = cipher.decrypt(ct_bytes)

    print(f"[*] Processed {len(decrypted_bytes)} bytes.")
    print("-" * 58)

    # Attempt UTF-8 decoding
    try:
        recovered_text = decrypted_bytes.decode("utf-8")
        print(f"{_bold('RECOVERED PLAINTEXT (UTF-8):')}")
        print(_green(recovered_text))
    except UnicodeDecodeError:
        print(f"{_yellow('[!] Decrypted bytes are not valid UTF-8 text (Binary data).')}")
        print(f"{_bold('RECOVERED BYTES (Hex):')}")
        print(_yellow(decrypted_bytes.hex()))

    print("-" * 58)

    if args.out:
        with open(args.out, "wb") as f:
            f.write(decrypted_bytes)
        print(f"[+] Saved recovered data to '{args.out}'.")

    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Step-by-step bitwise LFSR execution inspector."""
    seed = derive_seed_from_key(args.seed or args.key or "alpha", bit_length=args.bits)
    lfsr = LFSR(
        seed=seed,
        bit_length=args.bits,
        mode=args.mode,
        use_nonlinear_filter=not args.raw_linear
    )

    print(BANNER)
    print(f"[*] Inspecting LFSR: {_cyan(f'{args.bits}-bit')} (Taps: {lfsr.taps}, Mode: {args.mode})")
    print(f"[*] Initial Seed:   {_yellow(f'0x{seed:0{args.bits//4}X}')} ({lfsr.get_state_bits()})")
    print("=" * 64)
    print(f"{'Cycle':>5} | {'State (Hex)':<12} | {'LSB':<3} | {'MSB':<3} | {'Out Bit':<7} | {'New State (Binary)':<25}")
    print("-" * 64)

    steps = max(1, min(args.steps, 64))
    for i in range(1, steps + 1):
        prev_hex = lfsr.get_state_hex()
        lsb = lfsr.state & 1
        msb = (lfsr.state >> (lfsr.bit_length - 1)) & 1
        out_bit = lfsr.clock_bit()
        new_bits = lfsr.get_state_bits()
        # Truncate binary display if > 24 bits for clean table formatting
        disp_bits = new_bits if len(new_bits) <= 24 else f"...{new_bits[-20:]}"
        print(f"{i:5d} | {prev_hex:<12} | {lsb:<3} | {msb:<3} | {out_bit:<7} | {disp_bits:<25}")

    print("=" * 64)
    sample_byte = lfsr.clock_byte()
    print(f"[+] Accumulated next 8 bits into byte: {_green(f'{sample_byte}')} (0x{sample_byte:02X}, char: {repr(chr(sample_byte)) if 32 <= sample_byte <= 126 else 'non-printable'})")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Execute automated cryptographic verification test suite."""
    import unittest
    from test_cipher import TestLFSR, TestStreamCipher, TestAvalancheAndEntropy

    print(BANNER)
    print(_cyan("[*] Running automated cryptographic integrity verification suite...\n"))

    suite = unittest.TestSuite()
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestLFSR))
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestStreamCipher))
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestAvalancheAndEntropy))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if result.wasSuccessful():
        print("\n" + _green("=" * 60))
        print(_green(f"[SUCCESS] All {result.testsRun} cryptographic tests passed!"))
        print(_green("=" * 60))
        return 0
    else:
        print("\n" + _red("=" * 60))
        print(_red(f"[FAILURE] {len(result.failures)} test(s) failed, {len(result.errors)} error(s)."))
        print(_red("=" * 60))
        return 1


def main() -> None:
    """Main CLI entry point with argparse command router."""
    parser = argparse.ArgumentParser(
        prog="crypto-streamcipher",
        description="Crypto-StreamCipher-Engine: Custom symmetric stream cipher and LFSR keystream utility.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt plaintext using symmetric stream cipher")
    enc_parser.add_argument("-m", "--message", type=str, help="Plaintext message string")
    enc_parser.add_argument("-f", "--file", type=str, help="Input plaintext file path")
    enc_parser.add_argument("-k", "--key", type=str, required=True, help="Secret key or passphrase")
    enc_parser.add_argument("-b", "--bits", type=int, default=32, choices=[8, 16, 24, 32, 64], help="LFSR bit length (default: 32)")
    enc_parser.add_argument("--mode", type=str, default="fibonacci", choices=["fibonacci", "galois"], help="LFSR topology")
    enc_parser.add_argument("--raw-linear", action="store_true", help="Disable non-linear Boolean filter (use raw linear LFSR)")
    enc_parser.add_argument("-o", "--out", type=str, help="Output destination file")
    enc_parser.add_argument("--raw-binary", action="store_true", help="Write raw binary bytes instead of hex string")

    # Command: decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt hex ciphertext back to original plaintext")
    dec_parser.add_argument("-c", "--ciphertext", type=str, help="Ciphertext in hexadecimal format")
    dec_parser.add_argument("-f", "--file", type=str, help="Input ciphertext file path")
    dec_parser.add_argument("-k", "--key", type=str, required=True, help="Secret key or passphrase")
    dec_parser.add_argument("-b", "--bits", type=int, default=32, choices=[8, 16, 24, 32, 64], help="LFSR bit length (default: 32)")
    dec_parser.add_argument("--mode", type=str, default="fibonacci", choices=["fibonacci", "galois"], help="LFSR topology")
    dec_parser.add_argument("--raw-linear", action="store_true", help="Disable non-linear Boolean filter")
    dec_parser.add_argument("-o", "--out", type=str, help="Output destination file")

    # Command: inspect
    insp_parser = subparsers.add_parser("inspect", help="Step-by-step trace of LFSR clock cycles and register state")
    insp_parser.add_argument("-k", "--key", type=str, default="demo_key", help="Key or seed string")
    insp_parser.add_argument("-s", "--seed", type=int, help="Direct numeric seed (overrides key)")
    insp_parser.add_argument("-b", "--bits", type=int, default=16, choices=[8, 16, 24, 32, 64], help="LFSR bit length (default: 16)")
    insp_parser.add_argument("--steps", type=int, default=16, help="Number of clock cycles to step through")
    insp_parser.add_argument("--mode", type=str, default="fibonacci", choices=["fibonacci", "galois"], help="LFSR topology")
    insp_parser.add_argument("--raw-linear", action="store_true", help="Disable non-linear filter")

    # Command: test
    test_parser = subparsers.add_parser("test", help="Run automated cryptographic verification tests")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "inspect": cmd_inspect,
        "test": cmd_test
    }

    exit_code = dispatch[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
