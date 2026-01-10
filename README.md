# s33d - Solana HD Wallet Generator

A secure command-line tool for generating multiple Solana wallets from a single BIP39 mnemonic using hierarchical deterministic (HD) key derivation.

## Features

- **Single Mnemonic, Multiple Wallets**: Generate multiple wallets from one master seed phrase
- **BIP39 Mnemonic Generation**: Supports 12 or 24-word seed phrases
- **HD Key Derivation**: Derives wallets using paths `m/44'/501'/0'/0'`, `m/44'/501'/1'/0'`, etc.
- **Ed25519 Cryptography**
- **Secure Memory Handling**: Automatic zeroization of sensitive data
- **Batch Generation**: Create multiple wallets from the same mnemonic
- **Base58 Encoding**: Solana-compatible address format
- **Organized File Export**: Clean, structured output with master mnemonic header

## Prerequisites

- Rust (latest stable version)
- Cargo

## Installation

1. Clone the repository:
```bash
git clone https://github.com/owlpharoah/s33d.git
cd s33d
```

2. Build the project:
```bash
cargo build --release
```

## Usage

### Basic Syntax

```bash
cargo run -- <word_count> <number_of_wallets> <file_path>
```

### Parameters

- `word_count`: Number of words in the mnemonic (12 or 24)
- `number_of_wallets`: Number of wallets to derive from the master mnemonic
- `file_path`: Path where wallet information will be saved

### Examples

Generate 5 wallets from a single 12-word mnemonic:
```bash
cargo run -- 12 5 wallets.txt
```

Generate 10 wallets from a 24-word mnemonic:
```bash
cargo run -- 24 10 /path/to/my_wallets.txt
```

Generate 3 wallets and save to current directory:
```bash
cargo run -- 12 3 solana_wallets.txt
```

## Output

The tool creates a single file containing:
1. **Master mnemonic** (displayed once at the top)
2. **Multiple derived wallets** (each with its own keys)

Each wallet entry includes:
- Wallet number
- Public key (Base58 encoded)
- Private key (Base58 encoded)
- Raw Ed25519 keypair (64 bytes)

### Example Output Format

```
================================================================================
SOLANA HD WALLET EXPORT
================================================================================

MASTER MNEMONIC (KEEP SECRET • DO NOT SHARE)
-------------------------------------------
word1 word2 word3 ... word12
================================================================================

WALLET #1
-------------------------------------------
Public Key (Base58)
------------------
ABC123...XYZ789

Private Key (Base58)
-------------------
DEF456...UVW012

Raw Keypair (Ed25519 • 64 bytes)
--------------------------------
[1, 2, 3, ..., 64]

WALLET #2
-------------------------------------------
Public Key (Base58)
------------------
GHI789...MNO345

...
```

## How HD Derivation Works

This tool generates multiple wallets from a **single master mnemonic** using different derivation paths:

- Wallet #1: `m/44'/501'/0'/0'`
- Wallet #2: `m/44'/501'/1'/0'`
- Wallet #3: `m/44'/501'/2'/0'`
- And so on...


## Security Features

- **Automatic Zeroization**: The `Secret` struct implements `Drop` trait to automatically wipe sensitive data
- **Memory Safety**: All sensitive data (seeds, keys) is cleared from memory after use
- **Secure RNG**: Uses `OsRng` for cryptographically secure random number generation

## Derivation Path Structure

```
m/44'/501'/X'/0'
```

- `44'` - BIP44 purpose (hardened)
- `501'` - Solana coin type (hardened)
- `X'` - Account index (hardened, increments for each wallet)
- `0'` - Change index (hardened, always 0 for Solana)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
