"""
Cryptographic Integrity Verification Test Suite
================================================
Comprehensive unit tests verifying discrete bitwise operations,
LFSR state transitions, XOR symmetry, key derivation, and avalanche behavior.

Module: test_cipher.py
Project: Crypto-StreamCipher-Engine
"""

import os
import tempfile
import unittest

from lfsr import LFSR, MAXIMAL_PRIMITIVE_TAPS
from cipher import (
    StreamCipher,
    derive_seed_from_key,
    calculate_entropy,
    calculate_avalanche_effect
)


class TestLFSR(unittest.TestCase):
    """Verifies LFSR mathematical invariants, period, and bit manipulation."""

    def test_zero_seed_rejection(self):
        """Zero seed is an absorbing state and must be rejected with ValueError."""
        with self.assertRaises(ValueError):
            LFSR(seed=0, bit_length=16)

        # Also when masked to bit_length
        with self.assertRaises(ValueError):
            LFSR(seed=0x10000, bit_length=16)  # 0x10000 & 0xFFFF == 0

    def test_invalid_parameters(self):
        """Invalid bit length or tap coordinates must raise ValueError."""
        with self.assertRaises(ValueError):
            LFSR(seed=42, bit_length=1)

        with self.assertRaises(ValueError):
            LFSR(seed=42, bit_length=8, taps=(9, 4))  # 9 is out of bounds for 8-bit

        with self.assertRaises(ValueError):
            LFSR(seed=42, bit_length=8, mode="invalid_mode")

    def test_determinism(self):
        """Two identical LFSR configurations must yield identical bitstreams."""
        lfsr_a = LFSR(seed=0xDEADBEEF, bit_length=32)
        lfsr_b = LFSR(seed=0xDEADBEEF, bit_length=32)

        bits_a = [lfsr_a.clock_bit() for _ in range(256)]
        bits_b = [lfsr_b.clock_bit() for _ in range(256)]

        self.assertEqual(bits_a, bits_b)

    def test_reset(self):
        """Resetting an LFSR must restore the initial seed and reproduce the stream."""
        lfsr = LFSR(seed=0x1234, bit_length=16)
        stream_first = [lfsr.clock_bit() for _ in range(128)]

        lfsr.reset()
        stream_second = [lfsr.clock_bit() for _ in range(128)]

        self.assertEqual(stream_first, stream_second)

    def test_maximal_period_8bit(self):
        """
        Verify that an 8-bit primitive LFSR (taps: 8, 6, 5, 4) in raw linear mode
        cycles through all 2^8 - 1 = 255 non-zero states before repeating.
        """
        lfsr = LFSR(seed=1, bit_length=8, taps=(8, 6, 5, 4), use_nonlinear_filter=False)
        seen_states = set()
        initial_state = lfsr.state

        for cycle in range(255):
            self.assertNotIn(lfsr.state, seen_states, f"Cycle repeated prematurely at step {cycle}")
            seen_states.add(lfsr.state)
            lfsr.clock_bit()

        self.assertEqual(len(seen_states), 255)
        # Next state must return to initial_state
        self.assertEqual(lfsr.state, initial_state)

    def test_byte_clocking_alignment(self):
        """Ensure clock_byte accurately shifts 8 bits into an integer in [0, 255]."""
        lfsr = LFSR(seed=0xABCD, bit_length=16)
        for _ in range(32):
            val = lfsr.clock_byte()
            self.assertIsInstance(val, int)
            self.assertTrue(0 <= val <= 255)


class TestStreamCipher(unittest.TestCase):
    """Verifies stream cipher XOR symmetry, input handling, and round-trip fidelity."""

    def test_xor_involution_property(self):
        """
        Mathematical proof of symmetric XOR cipher:
        (Plaintext ^ Keystream) ^ Keystream == Plaintext
        """
        key = "SuperSecretCryptographicKey_2026!"
        cipher = StreamCipher(key=key, bit_length=32)

        test_payloads = [
            b"The quick brown fox jumps over the lazy dog.",
            "Cryptography with custom bitwise shifts over GF(2)".encode("utf-8"),
            "Universal characters: 密码, chiffrement, Verschlüsselung, 🔐 ⚡".encode("utf-8"),
            bytes([i % 256 for i in range(1024)]),  # Binary payload
            b"",  # Empty boundary
            b"A"  # 1-byte boundary
        ]

        for pt in test_payloads:
            ct = cipher.encrypt(pt)
            recovered = cipher.decrypt(ct)
            self.assertEqual(recovered, pt, f"Failed roundtrip for payload: {pt[:30]!r}")

    def test_hex_encryption_decryption(self):
        """Test hex-encoded string encryption and recovery."""
        message = "Autonomous Keystream Engine with Non-Linear Filtering"
        key = "QuantumResistantSeed99"
        cipher = StreamCipher(key=key, bit_length=32)

        hex_ct = cipher.encrypt_to_hex(message)
        self.assertIsInstance(hex_ct, str)
        self.assertTrue(all(c in "0123456789abcdef" for c in hex_ct.lower()))

        recovered_text = cipher.decrypt_from_hex(hex_ct)
        self.assertEqual(recovered_text, message)

    def test_key_sensitivity(self):
        """Two different keys must yield completely different ciphertexts."""
        message = "Confidential financial ledger data payload."
        cipher_1 = StreamCipher(key="CorrectPassphraseAlpha", bit_length=32)
        cipher_2 = StreamCipher(key="CorrectPassphraseBeta", bit_length=32)

        ct_1 = cipher_1.encrypt(message)
        ct_2 = cipher_2.encrypt(message)

        self.assertNotEqual(ct_1, ct_2)

        # Attempting decryption with the wrong key must not recover the original message
        bad_recovery = cipher_2.decrypt(ct_1)
        self.assertNotEqual(bad_recovery, message.encode("utf-8"))

    def test_file_encryption_roundtrip(self):
        """Verify on-disk file encryption and decryption roundtrip."""
        test_data = b"Arbitrary disk file payload with \x00\x01\xFF\xFE control bytes.\n" * 20

        with tempfile.NamedTemporaryFile(delete=False) as f_in:
            src_path = f_in.name
            f_in.write(test_data)

        enc_path = src_path + ".enc"
        dec_path = src_path + ".dec"

        try:
            cipher = StreamCipher(key="FileSecretSeed42", bit_length=32)
            bytes_enc = cipher.encrypt_file(src_path, enc_path)
            self.assertEqual(bytes_enc, len(test_data))

            bytes_dec = cipher.decrypt_file(enc_path, dec_path)
            self.assertEqual(bytes_dec, len(test_data))

            with open(dec_path, "rb") as f_recovered:
                recovered_data = f_recovered.read()

            self.assertEqual(recovered_data, test_data)
        finally:
            for p in (src_path, enc_path, dec_path):
                if os.path.exists(p):
                    os.remove(p)


class TestAvalancheAndEntropy(unittest.TestCase):
    """Verifies statistical properties: entropy and key avalanche behavior."""

    def test_keystream_shannon_entropy(self):
        """Keystream must exhibit high Shannon entropy (approaching 8 bits/byte)."""
        cipher = StreamCipher(key="EntropyAuditKey_8877", bit_length=32)
        keystream = cipher._create_generator().generate_keystream(4096)
        entropy = calculate_entropy(keystream)

        # A good PRNG keystream of 4096 bytes should exceed 7.8 bits/byte
        self.assertGreater(entropy, 7.8, f"Shannon entropy too low: {entropy:.3f}")

    def test_key_avalanche_effect(self):
        """A 1-bit difference in input key should cause significant divergence in keystream."""
        # Key 1 and Key 2 differ by a single character / bit
        cipher_a = StreamCipher(key="SensitiveKeyA", bit_length=32)
        cipher_b = StreamCipher(key="SensitiveKeyB", bit_length=32)

        diff_bits, total_bits, pct = calculate_avalanche_effect(cipher_a, cipher_b, sample_len=256)

        # Divergence should be close to 50% (ideal random bit flipping), typically between 40% and 60%
        self.assertTrue(
            35.0 <= pct <= 65.0,
            f"Avalanche divergence {pct:.2f}% is outside expected range [35%, 65%]"
        )


if __name__ == "__main__":
    unittest.main()
