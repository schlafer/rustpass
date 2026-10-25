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
- **Strength & Entropy Analysis**: Real-time theoretical keyspace and Shannon entropy calculation with human-readable ratings (`-E` / `--entropy`).
- **Batch Generation**: Generate multiple passwords at once (`-n 5` / `--count 5`).
- **Script-Friendly**: Suppress trailing newlines (`-0` / `--no-newline`) for clean piping into commands, variables, or files.
- **Memory Hygiene**: Actively wipes sensitive internal character buffers using volatile operations and zeroizes clipboard buffers via `zeroize`.
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

### 5. Policy Presets

Apply battle-tested security policies with a single flag:

```bash
# Strict: 20 chars, all groups, excludes lookalikes (0, O, 1, l, I, |)
rustpass --preset strict

# Alphanumeric: 16 chars, letters and digits only
rustpass --preset alphanumeric

# Memorable: 5 words, capitalized, random numeric suffix
rustpass --preset memorable
```

Presets establish sensible defaults and can be freely customized with explicit flags (e.g. `rustpass --preset strict -l 32`).

### 6. Minimum Entropy Requirements

Specify a target theoretical keyspace entropy and let RustPass dynamically compute the required length:

```bash
# Automatically sets length to reach at least 100 bits of entropy
rustpass --min-entropy 100

# Works seamlessly with passphrases
rustpass -p --min-entropy 80
```

### 7. Structured JSON Output

Generate passwords in structured JSON format for scripts and integrations:

```bash
rustpass -n 2 -l 16 -f json
```

Output:
```json
{
  "count": 2,
  "passwords": [
    {
      "value": "vR9$pL2#vR5@kL7*",
      "length": 16
    },
    {
      "value": "xT1*bN7!qZ3_bA4%",
      "length": 16
    }
  ]
}
```

Include entropy analysis metadata with `-E`:

```bash
rustpass -l 16 -f json -E
```

Output:
```json
{
  "count": 1,
  "passwords": [
    {
      "value": "Aq#8Tz3LpR_4kL7*",
      "length": 16,
      "entropy_bits": 97.4,
      "shannon_entropy": 3.75,
      "pool_size": 68,
      "strength_rating": "Strong"
    }
  ]
}
```

### 8. Shell Completions & Man Page

Generate autocompletions for your shell:

```bash
# Bash
source <(rustpass --completions bash)

# Zsh
rustpass --completions zsh > ~/.zfunc/_rustpass

# Fish
rustpass --completions fish > ~/.config/fish/completions/rustpass.fish
```

View or install the man page:

```bash
# View directly
rustpass --man | man -l -

# Or install to system man pages
rustpass --man | sudo tee /usr/local/share/man/man1/rustpass.1 > /dev/null
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
| `--preset <preset>` | | Policy preset (`strict`, `alphanumeric`, `memorable`) | |
| `--min-entropy <float>` | | Minimum required keyspace entropy in bits | |
| `--format <format>` | `-f` | Output format (`text` or `json`) | `text` |
| `--quiet` | `-q` | Suppress status and diagnostic messages on stderr | `false` |
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
| `--copy-only` | | Copy to clipboard only, suppressing stdout output | `false` |
| `--entropy` | `-E` | Display entropy and strength | `false` |
| `--no-newline` | `-0` | Suppress trailing newline | `false` |
| `--completions <shell>` | | Generate completions (`bash`, `elvish`, `fish`, `powershell`, `zsh`) | |
| `--man` | | Output manual page in roff format | |
| `--version` | `-v` | Display version information | |
| `--help` | `-h` | Display help screen | |

---

## Using as a Rust Library

You can use `rustpass` directly in your Rust projects by adding it to `Cargo.toml`:

```rust
use rustpass::{
    calculate_entropy, generate, generate_passphrase, strength_rating, Config, Error,
    PassphraseConfig,
};

fn main() -> Result<(), Error> {
    // Standard password
    let cfg = Config {
        length: 20,
        exclude_ambiguous: true,
        ..Config::default()
    };
    match generate(&cfg) {
        Ok((password, pool_size)) => {
            let entropy = calculate_entropy(&password, pool_size);
            let rating = strength_rating(entropy);
            println!("Generated: {}", password);
            println!("Entropy: {:.1} bits ({})", entropy, rating);
        }
        Err(Error::EmptyPool(msg)) => eprintln!("Pool configuration empty: {}", msg),
        Err(err) => eprintln!("Generation error: {}", err),
    }

    // Memorable passphrase
    let pass_cfg = PassphraseConfig {
        word_count: 4,
        separator: "-".to_string(),
        capitalize: true,
        ..PassphraseConfig::default()
    };
    let (passphrase, _) = generate_passphrase(&pass_cfg)?;
    println!("Passphrase: {}", passphrase);

    Ok(())
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

## Security Considerations & Limitations

- **Entropy Estimates:** The reported entropy (`-E`) is a theoretical upper-bound estimate calculated under the assumption of independent, uniform character selection from the effective pool ($L \times \log_2(pool)$). When character groups are partitioned (e.g. guaranteeing representation across groups), true keyspace size is slightly constrained. Shannon entropy reflects empirical character frequency diversity within the generated sample, not attacker guessability.
- **Memory Hygiene:** RustPass uses volatile memory clearing and the `zeroize` crate to erase temporary character and clipboard buffers. However, memory cannot be guaranteed erased in all operating environments: heap reallocations, standard library `String` moves, terminal scrollback buffers, clipboard managers, or OS swap files may retain copies outside the application's boundary.
- **Randomness:** Randomness is strictly sourced from the operating system's cryptographic random number generator via the `rand` crate CSPRNG.

---

## License

MIT License.
