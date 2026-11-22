# Crypto-StreamCipher-Engine

A modular Python stream cipher and keystream utility built with standard library modules, Linear Feedback Shift Register (LFSR) logic, and byte-level XOR operations.

## Overview

`Crypto-StreamCipher-Engine` implements symmetric stream encryption from first principles using bitwise arithmetic (`^`, `<<`, `>>`, `&`, `|`). Rather than wrapping high-level third-party cryptography packages, it constructs its own deterministic pseudo-random keystream generator and byte-masking pipeline.

## Project Structure

- `lfsr.py`: Deterministic bit and byte keystream generator using configurable seed states, tap positions, and bitwise shifts.
- `cipher.py`: Byte-level encryption and decryption routines using XOR masking, hex encoding/decoding, and input validation.
- `cli.py`: Command-line interface built with `argparse` for encrypting, decrypting, and running built-in integrity checks.
- `test_cipher.py`: Automated unit tests verifying LFSR keystream determinism, edge cases, and symmetric encryption/decryption round-trips.

## Getting Started

### Prerequisites

- Python 3.8 or higher (uses Python standard library modules only)

### Installation

```bash
git clone [https://github.com/eshatahir279/Crypto-StreamCipher-Engine.git](https://github.com/eshatahir279/Crypto-StreamCipher-Engine.git)
cd Crypto-StreamCipher-Engine