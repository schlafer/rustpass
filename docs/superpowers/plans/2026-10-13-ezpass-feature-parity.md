# Rustpass Feature Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `rustpass` to full feature parity with `ezpass` (v1.1.0) — covering granular character-set controls, Diceware passphrase generation, entropy analysis, clipboard integration, batch output, memory zeroing, and a proper library/binary architecture.

**Architecture:** Decompose the current monolithic `src/main.rs` into a library crate (`src/lib.rs`) re-exporting focused modules (`generator`, `passphrase`, `wordlist`, `entropy`, `clipboard`) and a thin binary crate (`src/main.rs`) that delegates to a `cli` module. Each module mirrors the responsibility boundaries in `ezpass/pkg/ezpass/`.

**Tech Stack:** Rust 2021 edition, `clap 4` (derive), `rand 0.9`, `base64` (for OSC 52), `zeroize` (memory wiping). Zero other third-party runtime dependencies for core generation — clipboard uses OS executables via `std::process::Command`.

**Spec:** The reference implementation is `ezpass` at `/home/schlafer/Projects/ezpass` (Go, v1.1.0). The feature set, CLI flags, character pools, entropy formulas, wordlist, and clipboard behavior described in this plan are derived directly from that codebase.

## Global Constraints

- Rust edition 2021, MSRV not explicitly pinned (follow existing `Cargo.toml`).
- Zero third-party runtime dependencies for core generation logic (only `rand` for CSPRNG). `clap` for CLI, `base64` for OSC 52, `zeroize` for memory hygiene.
- All randomness via `rand::rng()` backed by OS CSPRNG (`getrandom`). Never use non-cryptographic PRNGs.
- Default password length: `12`. Default symbols: `!@#$*_`. Default passphrase word count: `4`, separator: `"-"`.
- `stdout` is exclusively for password/passphrase output. All diagnostics (entropy info, clipboard status, errors) go to `stderr`.
- Exit code `0` on success, `1` on application error (empty pool, invalid length), `2` on CLI parse error (clap default).

## Review Focus

1. **All character groups disabled** — user passes `--no-upper --no-lower --no-digits --no-symbols`: must return a clear error, not panic or produce empty output. Test added in Task 2.
2. **Length < number of active groups** (e.g. `--length 2` with 4 groups active): must still produce a valid password with distinct group representation using `rand_perm`. Test added in Task 3.
3. **Exclusion empties a group entirely** (e.g. `--exclude "0123456789"` with `--no-upper --no-lower --no-symbols`): must error with empty pool message. Test added in Task 2.
4. **Passphrase with 0 words** — `--passphrase --words 0`: must return an error, not an empty string. Test added in Task 4.
5. **`--copy` on headless server with no clipboard tool** — must not panic; should fall back to OSC 52 or report a clear error. Test added in Task 6.

---

### Task 1: Restructure into Library Crate & Define Core Types

**Files:**
- Create: `src/lib.rs`
- Create: `src/generator.rs`
- Create: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `Cargo.toml`
- Test: inline `#[cfg(test)]` in `src/generator.rs`

**Interfaces:**
- Consumes: nothing (foundational task)
- Produces:
  - `pub struct Config { pub length: usize, pub no_upper: bool, pub no_lower: bool, pub no_digits: bool, pub no_symbols: bool, pub only_alphanumeric: bool, pub symbols: String, pub exclude_ambiguous: bool, pub exclude_chars: String }`
  - `pub fn default_config() -> Config`
  - `pub fn secure_random(min: usize, max: usize) -> usize` (moved from main)
  - `pub fn generate(cfg: &Config) -> Result<(String, usize), String>` — returns `(password, pool_size)`
  - `pub fn shuffle(chars: &mut Vec<char>)` (moved from main)
  - `pub const DEFAULT_LENGTH: usize = 12`
  - `pub const DEFAULT_SYMBOLS: &str = "!@#$*_"`
  - `pub const AMBIGUOUS_CHARS: &str = "0O1lI|"`

- [ ] **Step 1: Add `zeroize` and `base64` to `Cargo.toml`**

Add dependencies that will be needed across later tasks:
```toml
zeroize = "1"
base64 = "0.22"
```

- [ ] **Step 2: Create `src/lib.rs` re-exporting modules**

Declare modules: `pub mod generator;` (and stubs for future modules: `pub mod passphrase; pub mod wordlist; pub mod entropy; pub mod clipboard;`). Create empty stub files for the future modules so the crate compiles.

- [ ] **Step 3: Move generation logic into `src/generator.rs`**

Move `secure_random`, `generate_password`, `shuffle` from `main.rs` into `generator.rs`. Rename `generate_password` to `generate`. Add `Config` struct and `default_config()`. Change `generate` signature to accept `&Config` and return `Result<(String, usize), String>` where the `usize` is pool size (sum of lengths of active character groups). For now, only `length` is used from Config; the filtering flags are wired in Task 2. Move all 6 existing unit tests into `generator.rs`'s `#[cfg(test)]` module, adapting them to use `Config`.

- [ ] **Step 4: Create `src/cli.rs` with clap Args struct**

Define `Args` with all flags matching ezpass's CLI (see CLI table in spec). For this task, only `--length` and `--version` need to be functional; the rest are defined but not yet wired. Add `pub fn run()` that parses args, calls `generate`, shuffles, and prints.

- [ ] **Step 5: Slim `src/main.rs` to a thin entry point**

Replace the current `main.rs` body with `fn main() { rustpass::cli::run(); }`.

- [ ] **Step 6: Run all tests**

Run: `cargo test`
Expected: all existing tests pass, crate compiles as both lib and binary.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: restructure into library crate with generator module"
```

---

### Task 2: Character Set Filtering & Pool Validation

**Files:**
- Modify: `src/generator.rs`
- Modify: `src/cli.rs`
- Test: inline `#[cfg(test)]` in `src/generator.rs`

**Interfaces:**
- Consumes: `Config`, `generate(&Config)` from Task 1
- Produces: `generate` now respects all filtering fields in `Config` (`no_upper`, `no_lower`, `no_digits`, `no_symbols`, `only_alphanumeric`, `symbols`, `exclude_ambiguous`, `exclude_chars`). Returns `Err("character pool is empty; verify your inclusion and exclusion options")` when the resulting pool is empty.

- [ ] **Step 1: Write failing tests for character filtering**

```rust
#[test]
fn test_generate_no_symbols() {
    let cfg = Config { no_symbols: true, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert!(pw.chars().all(|c| !"!@#$*_".contains(c)));
}

#[test]
fn test_generate_no_upper() {
    let cfg = Config { no_upper: true, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert!(pw.chars().all(|c| !c.is_ascii_uppercase()));
}

#[test]
fn test_generate_no_lower() {
    let cfg = Config { no_lower: true, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert!(pw.chars().all(|c| !c.is_ascii_lowercase()));
}

#[test]
fn test_generate_no_digits() {
    let cfg = Config { no_digits: true, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert!(pw.chars().all(|c| !c.is_ascii_digit()));
}

#[test]
fn test_generate_only_alphanumeric() {
    let cfg = Config { only_alphanumeric: true, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn test_generate_exclude_ambiguous() {
    let cfg = Config { exclude_ambiguous: true, length: 100, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert!(pw.chars().all(|c| !"0O1lI|".contains(c)));
}

#[test]
fn test_generate_exclude_chars() {
    let cfg = Config { exclude_chars: "abc".to_string(), length: 100, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert!(pw.chars().all(|c| !"abc".contains(c)));
}

#[test]
fn test_generate_custom_symbols() {
    let cfg = Config { symbols: "^&".to_string(), length: 100, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    let sym_chars: Vec<char> = pw.chars().filter(|c| !c.is_ascii_alphanumeric()).collect();
    assert!(sym_chars.iter().all(|c| "^&".contains(*c)));
}

#[test]
fn test_generate_empty_pool() {
    let cfg = Config { no_upper: true, no_lower: true, no_digits: true, no_symbols: true, ..default_config() };
    assert!(generate(&cfg).is_err());
}

#[test]
fn test_generate_exclusion_empties_pool() {
    let cfg = Config {
        no_upper: true, no_lower: true, no_symbols: true,
        exclude_chars: "0123456789".to_string(),
        ..default_config()
    };
    assert!(generate(&cfg).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test`
Expected: new tests FAIL (filtering not implemented yet)

- [ ] **Step 3: Implement `filter_group(charset: &str, exclude_ambiguous: bool, exclude_chars: &str) -> String` and update `generate`**

Add a private helper `filter_group` that removes characters matching exclusion criteria. In `generate`, build the active groups list by applying Config flags: skip upper if `no_upper`, skip lower if `no_lower`, skip digits if `no_digits`, skip symbols if `no_symbols` or `only_alphanumeric`, use `cfg.symbols` instead of `DEFAULT_SYMBOLS` when non-empty. Apply `filter_group` to each active group. Check if all groups are empty after filtering and return `Err`. Compute `pool_size` as the sum of filtered group lengths and return it.

- [ ] **Step 4: Wire CLI flags to Config in `src/cli.rs`**

Map the clap `Args` fields to the corresponding `Config` fields before calling `generate`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add character set filtering and pool validation"
```

---

### Task 3: Small Length Handling with `rand_perm`

**Files:**
- Modify: `src/generator.rs`
- Test: inline `#[cfg(test)]` in `src/generator.rs`

**Interfaces:**
- Consumes: `generate(&Config)`, `secure_random` from Tasks 1–2
- Produces: `fn rand_perm(n: usize, k: usize) -> Vec<usize>` (private helper). `generate` now correctly handles `length < active_groups` by selecting `length` distinct groups via `rand_perm`.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn test_generate_length_1() {
    let cfg = Config { length: 1, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert_eq!(pw.len(), 1);
}

#[test]
fn test_generate_length_2() {
    let cfg = Config { length: 2, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert_eq!(pw.len(), 2);
}

#[test]
fn test_generate_length_3() {
    let cfg = Config { length: 3, ..default_config() };
    let (pw, _) = generate(&cfg).unwrap();
    assert_eq!(pw.len(), 3);
    // Characters should come from 3 distinct groups
}
```

- [ ] **Step 2: Run tests to verify they fail (or produce biased output)**

Run: `cargo test`
Expected: tests may pass for length but character group distribution is suboptimal for `length < 4`

- [ ] **Step 3: Implement `rand_perm` and integrate into `generate`**

`rand_perm(n, k)` selects `k` distinct random indices from `0..n` using `secure_random`. In `generate`, when `length < active_groups.len()`, call `rand_perm(active_groups.len(), length)` to select which groups contribute one character each, instead of the current modular distribution.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: handle small lengths with rand_perm group selection"
```

---

### Task 4: Diceware Passphrase Generation

**Files:**
- Create: `src/wordlist.rs` (populate with EFF short wordlist, 1296 words)
- Modify: `src/passphrase.rs` (replace stub)
- Modify: `src/cli.rs`
- Test: inline `#[cfg(test)]` in `src/passphrase.rs`

**Interfaces:**
- Consumes: `secure_random` from Task 1's `generator` module
- Produces:
  - `pub const DEFAULT_WORDLIST: &[&str]` in `wordlist.rs` (1,296 entries)
  - `pub struct PassphraseConfig { pub word_count: usize, pub separator: String, pub capitalize: bool, pub include_number: bool, pub word_list: Option<Vec<String>> }`
  - `pub fn generate_passphrase(cfg: &PassphraseConfig) -> Result<(String, usize), String>` — returns `(passphrase, wordlist_size)`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn test_passphrase_default() {
    let cfg = PassphraseConfig::default();
    let (pp, wl_size) = generate_passphrase(&cfg).unwrap();
    assert_eq!(pp.split('-').count(), 4);
    assert_eq!(wl_size, 1296);
}

#[test]
fn test_passphrase_custom_words() {
    let cfg = PassphraseConfig { word_count: 6, ..Default::default() };
    let (pp, _) = generate_passphrase(&cfg).unwrap();
    assert_eq!(pp.split('-').count(), 6);
}

#[test]
fn test_passphrase_custom_separator() {
    let cfg = PassphraseConfig { separator: ".".to_string(), ..Default::default() };
    let (pp, _) = generate_passphrase(&cfg).unwrap();
    assert_eq!(pp.split('.').count(), 4);
}

#[test]
fn test_passphrase_capitalize() {
    let cfg = PassphraseConfig { capitalize: true, ..Default::default() };
    let (pp, _) = generate_passphrase(&cfg).unwrap();
    for word in pp.split('-') {
        assert!(word.chars().next().unwrap().is_uppercase());
    }
}

#[test]
fn test_passphrase_include_number() {
    let cfg = PassphraseConfig { include_number: true, ..Default::default() };
    let (pp, _) = generate_passphrase(&cfg).unwrap();
    let parts: Vec<&str> = pp.split('-').collect();
    assert_eq!(parts.len(), 5); // 4 words + 1 number
    let num_part = parts.last().unwrap();
    assert!(num_part.parse::<u32>().is_ok());
}

#[test]
fn test_passphrase_zero_words() {
    let cfg = PassphraseConfig { word_count: 0, ..Default::default() };
    assert!(generate_passphrase(&cfg).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test`
Expected: FAIL (module stubs are empty)

- [ ] **Step 3: Populate `src/wordlist.rs` with the EFF short wordlist**

Copy the 1,296-word EFF short wordlist from `ezpass/pkg/ezpass/wordlist.go` and express it as `pub const DEFAULT_WORDLIST: &[&str] = &[...]`.

- [ ] **Step 4: Implement `generate_passphrase` in `src/passphrase.rs`**

Select `word_count` random words from the wordlist using `secure_random`. Apply `capitalize` by uppercasing first char of each word. Join with `separator`. If `include_number`, append separator + random number in `[0, 99]`. Return error if `word_count == 0`.

- [ ] **Step 5: Wire `--passphrase`, `--words`, `--separator`, `--capitalize`, `--include-number` in `src/cli.rs`**

When `--passphrase` is set, call `generate_passphrase` instead of `generate`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add Diceware passphrase generation with EFF wordlist"
```

---

### Task 5: Entropy Calculation & Strength Rating

**Files:**
- Modify: `src/entropy.rs` (replace stub)
- Modify: `src/cli.rs`
- Test: inline `#[cfg(test)]` in `src/entropy.rs`

**Interfaces:**
- Consumes: pool size from `generate` (Task 1), wordlist size from `generate_passphrase` (Task 4)
- Produces:
  - `pub fn calculate_entropy(password: &str, pool_size: usize) -> f64` — returns `length * log2(pool_size)`
  - `pub fn calculate_passphrase_entropy(word_count: usize, wordlist_size: usize) -> f64` — returns `word_count * log2(wordlist_size)`
  - `pub fn strength_rating(entropy: f64) -> &'static str` — `"Very Weak"` / `"Weak"` / `"Fair"` / `"Strong"` / `"Very Strong"`
  - `pub fn shannon_entropy(s: &str) -> f64`
  - `fn estimate_pool_size(password: &str) -> usize` (private)

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn test_calculate_entropy() {
    // 12 chars from pool of 68: 12 * log2(68) ≈ 73.2
    let e = calculate_entropy("aB3!aB3!aB3!", 68);
    assert!((e - 73.2).abs() < 0.5);
}

#[test]
fn test_passphrase_entropy() {
    // 4 words from 1296: 4 * log2(1296) ≈ 41.4
    let e = calculate_passphrase_entropy(4, 1296);
    assert!((e - 41.4).abs() < 0.5);
}

#[test]
fn test_strength_rating_thresholds() {
    assert_eq!(strength_rating(30.0), "Very Weak");
    assert_eq!(strength_rating(50.0), "Weak");
    assert_eq!(strength_rating(70.0), "Fair");
    assert_eq!(strength_rating(90.0), "Strong");
    assert_eq!(strength_rating(120.0), "Very Strong");
}

#[test]
fn test_shannon_entropy() {
    // All same char -> 0 entropy
    assert_eq!(shannon_entropy("aaaa"), 0.0);
    // Two equally frequent chars -> 1.0 bit
    assert!((shannon_entropy("ab") - 1.0).abs() < 0.01);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test`
Expected: FAIL

- [ ] **Step 3: Implement entropy functions in `src/entropy.rs`**

`calculate_entropy`: `password.len() as f64 * (pool_size as f64).log2()`. `strength_rating`: match on thresholds `<36 → "Very Weak"`, `<60 → "Weak"`, `<80 → "Fair"`, `<110 → "Strong"`, `≥110 → "Very Strong"`. `shannon_entropy`: count character frequencies, compute $-\sum p_i \log_2(p_i)$. `estimate_pool_size`: inspect character classes present and sum their sizes (26+26+10+symbols).

- [ ] **Step 4: Wire `--entropy` flag in `src/cli.rs`**

When `--entropy`/`-E` is set, after generating password/passphrase, compute and print entropy info to `stderr`: the entropy value in bits, Shannon entropy, strength rating, and pool/wordlist size.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add entropy calculation and strength analysis"
```

---

### Task 6: Clipboard Integration

**Files:**
- Modify: `src/clipboard.rs` (replace stub)
- Modify: `src/cli.rs`
- Modify: `Cargo.toml` (if `base64` not yet added)
- Test: inline `#[cfg(test)]` in `src/clipboard.rs`

**Interfaces:**
- Consumes: generated password/passphrase string from Tasks 1/4
- Produces:
  - `pub fn copy_to_clipboard(text: &str) -> Result<(), String>`
  - `fn write_osc52(text: &str) -> Result<(), String>` (private)

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn test_osc52_sequence_format() {
    // Test that the OSC 52 escape sequence is correctly formatted
    let encoded = base64::engine::general_purpose::STANDARD.encode("test");
    let expected = format!("\x1b]52;c;{}\x07", encoded);
    assert_eq!(expected, "\x1b]52;c;dGVzdA==\x07");
}

#[test]
fn test_copy_to_clipboard_does_not_panic() {
    // On CI/headless, clipboard may not be available, but function must not panic
    let result = copy_to_clipboard("test");
    // Result can be Ok or Err, but must not panic
    let _ = result;
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test`
Expected: FAIL

- [ ] **Step 3: Implement `copy_to_clipboard` and `write_osc52` in `src/clipboard.rs`**

`copy_to_clipboard`: check for clipboard executables in order: `wl-copy`, `xclip` (with `-selection clipboard`), `xsel` (with `--clipboard --input`), `pbcopy`, `clip.exe` — using `std::process::Command`. If a native tool succeeds, return `Ok`. Otherwise, fall back to `write_osc52`. `write_osc52`: base64-encode the text, write `\x1b]52;c;{base64}\x07` to `/dev/tty` (or stderr). If `$TMUX` is set, wrap in tmux passthrough (`\x1bPtmux;\x1b...\x1b\\`).

- [ ] **Step 4: Wire `--copy`/`-c` flag in `src/cli.rs`**

When `--copy` is set, call `copy_to_clipboard` with the generated output and print status to `stderr` (`✓ Copied to clipboard` or the error).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add multi-platform clipboard integration with OSC 52 fallback"
```

---

### Task 7: Batch Generation, Output Controls & Memory Zeroing

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/generator.rs` (add `zero_vec`)
- Test: inline `#[cfg(test)]` in `src/generator.rs`

**Interfaces:**
- Consumes: `generate` (Task 1), `generate_passphrase` (Task 4), `copy_to_clipboard` (Task 6), `calculate_entropy` (Task 5)
- Produces:
  - `pub fn zero_vec(v: &mut Vec<char>)` in `generator.rs`
  - CLI handles `--count`/`-n`, `--no-newline`/`-0`, `--version`/`-v`

- [ ] **Step 1: Write failing tests**

```rust
// In generator.rs
#[test]
fn test_zero_vec() {
    let mut v = vec!['a', 'B', '3', '!'];
    zero_vec(&mut v);
    assert!(v.iter().all(|c| *c == '\0'));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test`
Expected: FAIL

- [ ] **Step 3: Implement `zero_vec` in `src/generator.rs`**

Overwrite each element with `'\0'`. Also consider using `zeroize::Zeroize` trait on `String` for the final password string in `cli.rs` after output.

- [ ] **Step 4: Implement batch loop and output controls in `src/cli.rs`**

When `--count N` is specified, loop `N` times, generating and printing one password/passphrase per iteration. When `--no-newline` is set and count is 1 and entropy is not shown, use `print!` instead of `println!`. When `--copy` is set, concatenate all generated passwords (newline-separated) and copy once. Apply `zeroize` to the password `String` after printing. Wire `--version` to print `"rustpass 1.1.0"` and exit.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS

- [ ] **Step 6: Manual smoke test of batch and no-newline**

Run: `cargo run -- -n 5` — expect 5 passwords on separate lines.
Run: `cargo run -- -0` — expect password with no trailing newline.
Run: `cargo run -- --version` — expect `rustpass 1.1.0`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add batch generation, output controls, and memory zeroing"
```

---

### Task 8: CI Pipeline & Final Integration Test

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `README.md`
- Test: `cargo test`, `cargo clippy`, `cargo build --release`

**Interfaces:**
- Consumes: all modules from Tasks 1–7
- Produces: CI workflow file, updated README

- [ ] **Step 1: Create `.github/workflows/ci.yml`**

GitHub Actions workflow triggered on push and PR to `main`. Matrix of stable Rust. Steps: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --verbose`, `cargo build --release --verbose`.

- [ ] **Step 2: Update `README.md`**

Update README to document all new CLI flags, passphrase mode, entropy analysis, clipboard support, and batch generation. Mirror the structure of ezpass's README.

- [ ] **Step 3: Run full test suite and clippy**

Run: `cargo test && cargo clippy -- -D warnings`
Expected: all tests PASS, no clippy warnings

- [ ] **Step 4: Build release binary**

Run: `cargo build --release`
Expected: clean build

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "ci: add GitHub Actions workflow and update README"
```
