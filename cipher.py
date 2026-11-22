"""
Symmetric Stream Cipher Pipeline
================================
Implements bitwise XOR stream encryption and decryption powered by
deterministic LFSR pseudo-random keystream generation.

Module: cipher.py
Project: Crypto-StreamCipher-Engine
"""

import binascii
from typing import Union, Tuple, Optional
from lfsr import LFSR


def derive_seed_from_key(key: Union[str, bytes, int], bit_length: int = 32) -> int:
    """
    Derive a deterministic, non-zero initial seed integer from an arbitrary key.
    Uses bitwise XOR folding, cyclic shifts (rotations), and FNV-1a 64-bit mixing
    without external dependencies.

    :param key: String passphrase, raw bytes, or integer seed.
    :param bit_length: Target register bit width (e.g. 16, 24, 32, 64).
    :return: Non-zero positive integer bounded by (2^bit_length - 1).
    """
    if isinstance(key, int):
        seed = abs(key) & ((1 << bit_length) - 1)
        # Avoid absorbing all-zero state
        return seed if seed != 0 else 0x5A5A5A5A & ((1 << bit_length) - 1)

    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        key_bytes = bytes(key)
    else:
        raise TypeError(f"Key must be str, bytes, or int, got {type(key).__name__}")

    if len(key_bytes) == 0:
        raise ValueError("Key cannot be empty.")

    # 64-bit FNV-1a offset basis and prime
    fnv_offset = 0xCBF29CE484222325
    fnv_prime = 0x100000001B3
    mask_64 = 0xFFFFFFFFFFFFFFFF

    hash_val = fnv_offset
    for byte in key_bytes:
        hash_val ^= byte
        hash_val = (hash_val * fnv_prime) & mask_64
        # Bitwise cyclic left rotation by 7 bits
        hash_val = ((hash_val << 7) | (hash_val >> (64 - 7))) & mask_64

    # Fold 64-bit hash into the target bit_length
    target_mask = (1 << bit_length) - 1
    if bit_length <= 32:
        high = (hash_val >> 32) & 0xFFFFFFFF
        low = hash_val & 0xFFFFFFFF
        folded = high ^ low
        seed = folded & target_mask
    else:
        seed = hash_val & target_mask

    # Guaranteed non-zero seed (LFSR zero state lock-out prevention)
    if seed == 0:
        seed = 0x5A5A5A5A5A5A5A5A & target_mask
        if seed == 0:
            seed = 1

    return seed


class StreamCipher:
    """
    Production-grade Symmetric Stream Cipher Engine.

    Encapsulates keystream generation and byte-level bitwise XOR encryption/decryption.
    Since bitwise XOR is an involution (A ^ B ^ B == A), the encryption and decryption
    transformations are duals of one another under identical keystream synchronization.
    """

    def __init__(
        self,
        key: Union[str, bytes, int],
        bit_length: int = 32,
        taps: Optional[Tuple[int, ...]] = None,
        mode: str = "fibonacci",
        use_nonlinear_filter: bool = True
    ) -> None:
        """
        Initialize the Stream Cipher with key or seed configuration.

        :param key: Passphrase string, raw bytes, or numeric seed.
        :param bit_length: LFSR register width (default 32).
        :param taps: Custom feedback polynomial tap positions.
        :param mode: LFSR architecture ('fibonacci' or 'galois').
        :param use_nonlinear_filter: Resist linear cryptanalysis.
        """
        self.raw_key = key
        self.bit_length = bit_length
        self.taps = taps
        self.mode = mode
        self.use_nonlinear_filter = use_nonlinear_filter

        self.seed = derive_seed_from_key(key, bit_length=bit_length)

    def _create_generator(self) -> LFSR:
        """Instantiate a fresh LFSR generator reset to the initial seed."""
        return LFSR(
            seed=self.seed,
            bit_length=self.bit_length,
            taps=self.taps,
            mode=self.mode,
            use_nonlinear_filter=self.use_nonlinear_filter
        )

    def process_bytes(self, data: bytes) -> bytes:
        """
        Core bitwise XOR processing engine.
        Transforms each input byte via bitwise XOR with the corresponding keystream byte:
            Ciphertext[i] = Plaintext[i] ^ Keystream[i]
            Plaintext[i]  = Ciphertext[i] ^ Keystream[i]

        :param data: Input byte sequence.
        :return: Transformed byte sequence.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"Data must be bytes or bytearray, got {type(data).__name__}")

        if len(data) == 0:
            return b""

        # Fresh keystream generator starting at the synchronized key/seed
        generator = self._create_generator()
        keystream = generator.generate_keystream(len(data))

        # Perform byte-by-byte bitwise XOR
        output = bytearray(len(data))
        for i in range(len(data)):
            output[i] = data[i] ^ keystream[i]

        return bytes(output)

    def encrypt(self, plaintext: Union[str, bytes]) -> bytes:
        """
        Encrypt plaintext string or bytes into ciphertext bytes.

        :param plaintext: Unicode string or raw bytes.
        :return: Encrypted ciphertext bytes.
        """
        if isinstance(plaintext, str):
            data = plaintext.encode("utf-8")
        elif isinstance(plaintext, (bytes, bytearray)):
            data = bytes(plaintext)
        else:
            raise TypeError("Plaintext must be str or bytes.")

        return self.process_bytes(data)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext bytes back into the original plaintext bytes.

        :param ciphertext: Encrypted bytes.
        :return: Decrypted bytes.
        """
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes or bytearray.")

        return self.process_bytes(bytes(ciphertext))

    def encrypt_to_hex(self, plaintext: Union[str, bytes]) -> str:
        """
        Encrypt plaintext and encode the resulting ciphertext as a hex string.
        """
        ct_bytes = self.encrypt(plaintext)
        return ct_bytes.hex()

    def decrypt_from_hex(self, hex_ciphertext: str) -> str:
        """
        Decode a hex-encoded ciphertext, decrypt it, and decode to UTF-8 plaintext string.

        :param hex_ciphertext: Hexadecimal representation of ciphertext.
        :return: Decoded plaintext string.
        :raises ValueError: If hex string is malformed or invalid UTF-8.
        """
        cleaned = hex_ciphertext.strip().replace(" ", "").replace("\n", "")
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]

        if len(cleaned) == 0:
            return ""

        try:
            ct_bytes = bytes.fromhex(cleaned)
        except ValueError as err:
            raise ValueError(f"Invalid hexadecimal ciphertext: {err}") from err

        pt_bytes = self.decrypt(ct_bytes)
        try:
            return pt_bytes.decode("utf-8")
        except UnicodeDecodeError as err:
            # Fall back to repr or error description if binary payload
            raise ValueError(
                f"Decrypted bytes could not be decoded as UTF-8: {err}. "
                f"Raw bytes (hex): {pt_bytes.hex()}"
            ) from err

    def encrypt_file(self, source_path: str, destination_path: str) -> int:
        """
        Encrypt an entire file from disk and write ciphertext to destination.

        :param source_path: Input file path.
        :param destination_path: Output encrypted file path.
        :return: Number of bytes processed.
        """
        with open(source_path, "rb") as f_in:
            data = f_in.read()

        encrypted = self.encrypt(data)

        with open(destination_path, "wb") as f_out:
            f_out.write(encrypted)

        return len(encrypted)

    def decrypt_file(self, source_path: str, destination_path: str) -> int:
        """
        Decrypt an encrypted file from disk and write recovered plaintext to destination.

        :param source_path: Input encrypted file path.
        :param destination_path: Output decrypted file path.
        :return: Number of bytes recovered.
        """
        with open(source_path, "rb") as f_in:
            data = f_in.read()

        decrypted = self.decrypt(data)

        with open(destination_path, "wb") as f_out:
            f_out.write(decrypted)

        return len(decrypted)


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy H(X) of a byte sequence in bits per byte [0.0, 8.0].
    Uniform random data approaches 8.0 bits/byte.
    """
    import math
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    return entropy


def calculate_avalanche_effect(cipher_a: StreamCipher, cipher_b: StreamCipher, sample_len: int = 128) -> Tuple[int, int, float]:
    """
    Measure the bit divergence (Hamming distance) between two keystreams
    generated from two slightly different keys (e.g. 1-bit difference).

    :return: (differing_bits, total_bits, percentage_divergence)
    """
    stream_a = cipher_a._create_generator().generate_keystream(sample_len)
    stream_b = cipher_b._create_generator().generate_keystream(sample_len)

    total_bits = sample_len * 8
    differing_bits = 0

    for byte_a, byte_b in zip(stream_a, stream_b):
        diff = byte_a ^ byte_b
        # Count set bits in diff byte
        while diff > 0:
            differing_bits += diff & 1
            diff >>= 1

    percentage = (differing_bits / total_bits) * 100.0
    return differing_bits, total_bits, percentage
