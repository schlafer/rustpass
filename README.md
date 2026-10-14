# rustpass

[![CI](https://github.com/schlafer/rustpass/actions/workflows/ci.yml/badge.svg)](https://github.com/schlafer/rustpass/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A fast, cryptographically secure CLI password and memorable passphrase generator written in Rust.

---

## Features

- **Cryptographically Secure**: Powered by OS CSPRNG (`rand` crate) for high-entropy randomness.
- **Fair Character Distribution**: Guarantees characters across enabled groups and shuffles using Fisher–Yates.
- **Memorable Passphrases**: Diceware-style passphrases using the official EFF short wordlist (`-p` / `--passphrase`).
- **Granular Character Controls**: Disable symbols, numbers, uppercase, or lowercase; or restrict to alphanumeric only.
- **Exclude Ambiguous Characters**: Filter out confusing lookalikes like `0`, `O`, `1`, `l`, `I`, and `|`.
- **Clipboard Integration**: Seamlessly copy passwords via `-c` / `--copy` across Linux, macOS, and Windows with OSC 52 terminal fallback.
- **Strength & Entropy Analysis**: Real-time keyspace and Shannon entropy calculation with human-readable ratings (`-E` / `--entropy`).
- **Batch Generation**: Generate multiple passwords at once (`-n 5` / `--count 5`).
- **Script-Friendly**: Suppress trailing newlines (`-0` / `--no-newline`) for clean piping into commands, variables, or files.
- **Memory Zeroization**: Zeroes out sensitive password and clipboard buffers in memory immediately after use (`zeroize`).
- **Reusable Rust Crate**: Can be imported as a library into any Rust application.

---

## Installation

### Via `cargo install`

Install directly from the local repository directory:

```bash
cargo install --path .
```

### From Source

Clone the repository and build a release binary:

```bash
git clone https://github.com/schlafer/rustpass.git
cd rustpass
cargo build --release
```

The optimized binary will be located at `target/release/rustpass`.

Optionally move it to your system PATH:

```bash
sudo cp target/release/rustpass /usr/local/bin/
```

---

## Quick Start & Usage

### 1. Standard Passwords

Generate a default 12-character password:

```bash
rustpass
# Output: Aq#8Tz3LpR_4
```

Specify a custom length:

```bash
rustpass -l 24
# or: rustpass --length 24
```

Generate a batch of 5 passwords:

```bash
rustpass -n 5
# or: rustpass --count 5
```

### 2. Character Filtering

Exclude special symbols:

```bash
rustpass -l 16 -S
# or: rustpass -l 16 --no-symbols
```

Alphanumeric only (letters and numbers):

```bash
rustpass -l 16 -A
# or: rustpass -l 16 --only-alphanumeric
```

Exclude ambiguous/lookalike characters (`0`, `O`, `1`, `l`, `I`, `|`):

```bash
rustpass -l 16 -a
# or: rustpass -l 16 --exclude-ambiguous
```

Exclude specific characters (e.g. quotes or slashes):

```bash
rustpass -l 16 -e "\"'/\\"
# or: rustpass -l 16 --exclude "\"'/\\"
```

Use a custom symbol set:

```bash
rustpass -l 16 --symbols "!@#$%"
```

### 3. Memorable Passphrases (Diceware Style)

Generate a memorable 4-word passphrase:

```bash
rustpass -p
# Output: sleet-bony-cried-curse
```

Customize word count, separator, capitalization, and numbers:

```bash
rustpass -p -w 5 --sep "_" --capitalize --include-number
# Output: Sleet_Bony_Cried_Curse_Frost_42
```

### 4. Clipboard & Entropy

Generate and copy directly to system clipboard:

```bash
rustpass -c
# ✓ Copied to clipboard
```

Display password entropy and strength analysis:

```bash
rustpass -l 20 -E
# Output:
# Ksx5@R2O5iP_zE@a05_*
# Entropy:   121.7 bits (Very Strong)
# Shannon:   3.92 bits/char
# Pool Size: 68
```

Batch generation with entropy display:

```bash
rustpass -n 3 -E
# Output:
# Aq#8Tz3LpR_4             [Entropy: 73.0 bits, Strength: Very Strong]
# mK9$pL2#vR5@             [Entropy: 73.0 bits, Strength: Very Strong]
# xT1*bN7!qZ3_             [Entropy: 73.0 bits, Strength: Very Strong]
```

---

## Shell & Scripting Integration

Assign to a shell variable without trailing newline:

```bash
PASSWORD=$(rustpass -l 16 -0)
```

Pipe directly into `sha256sum` or files:

```bash
rustpass -l 32 -0 > secret.key
```

Batch generation into a text file:

```bash
rustpass -n 20 > passwords.txt
```

---

## CLI Flag Reference

| Flag | Shorthand | Description | Default |
| --- | --- | --- | --- |
| `--length <int>` | `-l` | Length of generated password | `12` |
| `--count <int>` | `-n` | Number of passwords to generate | `1` |
| `--no-symbols` | `-S` | Exclude special characters (`!@#$*_`) | `false` |
| `--no-digits` | `-D` | Exclude numeric digits (`0-9`) | `false` |
| `--no-upper` | `-U` | Exclude uppercase letters (`A-Z`) | `false` |
| `--no-lower` | `-L` | Exclude lowercase letters (`a-z`) | `false` |
| `--only-alphanumeric` | `-A` | Use only letters and numbers | `false` |
| `--symbols <str>` | | Custom symbol set | `"!@#$*_"` |
| `--exclude-ambiguous` | `-a` | Exclude lookalike characters (`0O1lI\|`) | `false` |
| `--exclude <str>` | `-e` | Exclude specific characters | `""` |
| `--passphrase` | `-p` | Generate memorable passphrase | `false` |
| `--words <int>` | `-w` | Word count for passphrase | `4` |
| `--separator <str>` | `--sep` | Word separator for passphrase | `"-"` |
| `--capitalize` | | Capitalize words in passphrase | `false` |
| `--include-number` | | Append random number to passphrase | `false` |
| `--copy` | `-c` | Copy result to system clipboard | `false` |
| `--entropy` | `-E` | Display entropy and strength | `false` |
| `--no-newline` | `-0` | Suppress trailing newline | `false` |
| `--version` | `-v` | Display version information | |
| `--help` | `-h` | Display help screen | |

---

## Using as a Rust Library

You can use `rustpass` directly in your Rust projects by adding it to `Cargo.toml`:

```rust
use rustpass::{
    calculate_entropy, generate, generate_passphrase, strength_rating, Config, PassphraseConfig,
};

fn main() {
    // Standard password
    let cfg = Config {
        length: 20,
        exclude_ambiguous: true,
        ..Config::default()
    };
    let (password, pool_size) = generate(&cfg).expect("generation failed");
    let entropy = calculate_entropy(&password, pool_size);
    let rating = strength_rating(entropy);
    println!("Generated: {}", password);
    println!("Entropy: {:.1} bits ({})", entropy, rating);

    // Memorable passphrase
    let pass_cfg = PassphraseConfig {
        word_count: 4,
        separator: "-".to_string(),
        capitalize: true,
        ..PassphraseConfig::default()
    };
    let (passphrase, _) = generate_passphrase(&pass_cfg).expect("passphrase generation failed");
    println!("Passphrase: {}", passphrase);
}
```

---

## Testing & Verification

Run all unit tests:

```bash
cargo test
```

Check code formatting and linter:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Build release binary:

```bash
cargo build --release
```

---

## License

MIT License.
