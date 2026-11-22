"""
Linear Feedback Shift Register (LFSR) Keystream Engine
======================================================
Implements deterministic pseudo-random bit and byte stream generation
using custom bitwise shifts and primitive feedback polynomials over GF(2).

Module: lfsr.py
Project: Crypto-StreamCipher-Engine
"""

from typing import List, Tuple, Optional


# Standard primitive polynomials over GF(2) yielding maximal length periods (2^n - 1)
# Tap indices use 1-based indexing from the most significant bit (n down to 1).
MAXIMAL_PRIMITIVE_TAPS = {
    8:  (8, 6, 5, 4),               # x^8 + x^6 + x^5 + x^4 + 1  (Period: 255)
    16: (16, 14, 13, 11),           # x^16 + x^14 + x^13 + x^11 + 1  (Period: 65,535)
    24: (24, 23, 22, 17),           # x^24 + x^23 + x^22 + x^17 + 1  (Period: 16,777,215)
    32: (32, 22, 2, 1),             # x^32 + x^22 + x^2 + x^1 + 1  (Period: 4,294,967,295)
    64: (64, 63, 61, 60),           # x^64 + x^63 + x^61 + x^60 + 1 (Period: ~1.84 x 10^19)
}


class LFSR:
    """
    Deterministic Linear Feedback Shift Register (LFSR) Key Stream Generator.

    Operates in either Fibonacci configuration (external XOR feedback)
    or Galois configuration (internal XOR taps), supporting custom bit lengths
    and primitive feedback polynomials.
    """

    def __init__(
        self,
        seed: int,
        bit_length: int = 32,
        taps: Optional[Tuple[int, ...]] = None,
        mode: str = "fibonacci",
        use_nonlinear_filter: bool = True
    ) -> None:
        """
        Initialize the LFSR.

        :param seed: Initial non-zero integer state.
        :param bit_length: Width of the shift register in bits (e.g. 8, 16, 32, 64).
        :param taps: Tap positions as 1-based exponents in feedback polynomial.
        :param mode: 'fibonacci' or 'galois'.
        :param use_nonlinear_filter: Apply non-linear Boolean filtering to resist
                                     Berlekamp-Massey linear cryptanalysis.
        :raises ValueError: If seed is zero, bit_length is invalid, or taps are out of bounds.
        """
        if bit_length < 2:
            raise ValueError(f"Bit length must be at least 2, got {bit_length}")

        self.bit_length = bit_length
        self.mask = (1 << bit_length) - 1

        # Resolve feedback polynomial taps
        if taps is None:
            if bit_length in MAXIMAL_PRIMITIVE_TAPS:
                self.taps = MAXIMAL_PRIMITIVE_TAPS[bit_length]
            else:
                raise ValueError(
                    f"No default primitive taps for bit_length={bit_length}. "
                    f"Available presets: {list(MAXIMAL_PRIMITIVE_TAPS.keys())}. "
                    "Please supply custom taps."
                )
        else:
            self._validate_taps(taps, bit_length)
            self.taps = tuple(sorted(taps, reverse=True))

        # Validate non-zero seed (0 is an absorbing all-zero dead state in LFSR)
        initial_state = seed & self.mask
        if initial_state == 0:
            raise ValueError(
                "LFSR seed cannot be 0. An all-zero state produces an infinite stream of 0s."
            )

        self.initial_seed = initial_state
        self.state = initial_state
        self.mode = mode.lower()
        self.use_nonlinear_filter = use_nonlinear_filter
        self.total_clock_cycles = 0

        if self.mode not in ("fibonacci", "galois"):
            raise ValueError(f"Unsupported mode '{mode}'. Choose 'fibonacci' or 'galois'.")

    @staticmethod
    def _validate_taps(taps: Tuple[int, ...], bit_length: int) -> None:
        if not taps:
            raise ValueError("Taps tuple cannot be empty.")
        for tap in taps:
            if not isinstance(tap, int) or tap < 1 or tap > bit_length:
                raise ValueError(
                    f"Invalid tap position {tap}. Taps must be integers between 1 and {bit_length}."
                )

    def reset(self) -> None:
        """Reset the internal register state back to the original seed."""
        self.state = self.initial_seed
        self.total_clock_cycles = 0

    def clock_fibonacci_bit(self) -> int:
        """
        Clock a single bit using the Fibonacci LFSR topology:
        1. Extract the least significant bit (LSB) as the raw output.
        2. Calculate the feedback bit by XOR-ing the state bits at each tap position.
        3. Shift the register right by 1 bit.
        4. Place the feedback bit at the most significant bit (MSB).

        :return: 0 or 1 bit.
        """
        # Raw output is the bit being shifted out at LSB
        raw_output_bit = self.state & 1

        # Calculate feedback bit via bitwise XOR of tap positions
        feedback = 0
        for tap in self.taps:
            # tap is 1-based index from MSB: tap position corresponds to bit (tap - 1)
            # or from LSB convention: if taps are exponents x^t, bit is (tap - 1)
            bit = (self.state >> (tap - 1)) & 1
            feedback ^= bit

        # Shift right by 1 and insert feedback bit at MSB (bit_length - 1)
        self.state = (self.state >> 1) | (feedback << (self.bit_length - 1))
        self.state &= self.mask
        self.total_clock_cycles += 1

        if self.use_nonlinear_filter:
            return self._apply_nonlinear_filter(raw_output_bit)
        return raw_output_bit

    def clock_galois_bit(self) -> int:
        """
        Clock a single bit using the Galois LFSR topology:
        1. Extract the output bit at LSB.
        2. If output bit == 1, shift right and XOR the tap mask directly into the state.
        3. If output bit == 0, simply shift right.

        :return: 0 or 1 bit.
        """
        output_bit = self.state & 1
        self.state >>= 1

        if output_bit == 1:
            # XOR feedback polynomial mask (excluding the highest bit since it shifts in naturally)
            galois_mask = 0
            for tap in self.taps:
                if tap != self.bit_length:
                    galois_mask |= (1 << (tap - 1))
            self.state ^= galois_mask
            # Set the MSB to 1
            self.state |= (1 << (self.bit_length - 1))

        self.state &= self.mask
        self.total_clock_cycles += 1

        if self.use_nonlinear_filter:
            return self._apply_nonlinear_filter(output_bit)
        return output_bit

    def _apply_nonlinear_filter(self, raw_bit: int) -> int:
        """
        Apply a non-linear Boolean filtering function to the register state.
        This dramatically increases linear complexity and defeats Berlekamp-Massey
        attacks that easily reconstruct purely linear LFSRs in 2*N bits.

        Filter: f(s) = raw_bit ^ (s_a & s_b) ^ (s_c & s_d) ^ s_e
        where s_a, s_b, s_c, s_d, s_e are distinct internal state bits.
        """
        s = self.state
        n = self.bit_length
        s_a = (s >> (n // 4)) & 1
        s_b = (s >> (n // 2)) & 1
        s_c = (s >> (3 * n // 4)) & 1
        s_d = (s >> ((n - 1) % n)) & 1
        s_e = (s >> ((n // 3) % n)) & 1

        # Non-linear combination (algebraic degree 2)
        filtered = raw_bit ^ (s_a & s_b) ^ (s_c & s_d) ^ s_e
        return filtered & 1

    def clock_bit(self) -> int:
        """Advance the register by 1 clock cycle and return a single bit (0 or 1)."""
        if self.mode == "galois":
            return self.clock_galois_bit()
        return self.clock_fibonacci_bit()

    def clock_byte(self) -> int:
        """
        Clock the register 8 times to produce a full 8-bit byte.
        Bits are packed MSB-first into an unsigned integer [0, 255].
        """
        byte_val = 0
        for _ in range(8):
            bit = self.clock_bit()
            byte_val = (byte_val << 1) | bit
        return byte_val

    def generate_keystream(self, length_in_bytes: int) -> bytes:
        """
        Generate a deterministic continuous keystream of the requested byte length.

        :param length_in_bytes: Number of pseudo-random bytes to produce.
        :return: Immutable bytes sequence.
        """
        if length_in_bytes < 0:
            raise ValueError("Keystream length must be non-negative.")
        if length_in_bytes == 0:
            return b""

        keystream_bytes = bytearray(length_in_bytes)
        for i in range(length_in_bytes):
            keystream_bytes[i] = self.clock_byte()
        return bytes(keystream_bytes)

    def get_state_bits(self) -> str:
        """Return binary string representation of the current register state."""
        return f"{self.state:0{self.bit_length}b}"

    def get_state_hex(self) -> str:
        """Return hexadecimal string representation of the current register state."""
        hex_len = (self.bit_length + 3) // 4
        return f"0x{self.state:0{hex_len}X}"

    def step_info(self) -> dict:
        """
        Return snapshot information useful for debugging and visual inspection.
        """
        return {
            "clock_cycle": self.total_clock_cycles,
            "state_int": self.state,
            "state_hex": self.get_state_hex(),
            "state_bits": self.get_state_bits(),
            "bit_length": self.bit_length,
            "taps": self.taps,
            "mode": self.mode,
            "nonlinear_filter": self.use_nonlinear_filter
        }
