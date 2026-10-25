use std::process;

use clap::{CommandFactory, Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::clipboard::copy_to_clipboard;
use crate::entropy::{
    calculate_entropy, calculate_passphrase_entropy_with_number, shannon_entropy, strength_rating,
};
use crate::generator::{effective_pool_size, generate, Config};
use crate::passphrase::{generate_passphrase, PassphraseConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// High-security password: length 20, all character groups, excludes ambiguous characters
    Strict,
    /// Alphanumeric only: length 16, letters and numbers, no symbols
    Alphanumeric,
    /// Memorable Diceware passphrase: 5 words, capitalized, with random number suffix
    Memorable,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct JsonResponse {
    pub count: usize,
    pub passwords: Vec<JsonPasswordEntry>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct JsonPasswordEntry {
    pub value: String,
    pub length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_bits: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shannon_entropy: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strength_rating: Option<String>,
}

#[derive(Parser, Debug)]
#[command(
    name = "rustpass",
    about = "CLI password generator",
    disable_version_flag = true
)]
pub struct Args {
    /// Password length (default: 12, or set by preset/min-entropy)
    #[arg(short = 'l', long = "length")]
    pub length: Option<usize>,

    /// Number of passwords to generate
    #[arg(short = 'n', long = "count", default_value_t = 1)]
    pub count: usize,

    /// Password policy preset (strict, alphanumeric, memorable)
    #[arg(long = "preset", value_enum)]
    pub preset: Option<Preset>,

    /// Minimum required theoretical keyspace entropy in bits
    #[arg(long = "min-entropy")]
    pub min_entropy: Option<f64>,

    /// Output format (text or json)
    #[arg(short = 'f', long = "format", value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Suppress status and diagnostic messages on stderr
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Exclude uppercase letters (A-Z)
    #[arg(short = 'U', long = "no-upper")]
    pub no_upper: bool,

    /// Exclude lowercase letters (a-z)
    #[arg(short = 'L', long = "no-lower")]
    pub no_lower: bool,

    /// Exclude numbers (0-9)
    #[arg(short = 'D', long = "no-digits")]
    pub no_digits: bool,

    /// Exclude special symbols
    #[arg(short = 'S', long = "no-symbols")]
    pub no_symbols: bool,

    /// Use only letters and digits
    #[arg(short = 'A', long = "only-alphanumeric")]
    pub only_alphanumeric: bool,

    /// Custom symbols (default: !@#$*_)
    #[arg(long = "symbols", default_value = "")]
    pub symbols: String,

    /// Exclude lookalike characters (0, O, 1, l, I, |)
    #[arg(short = 'a', long = "exclude-ambiguous")]
    pub exclude_ambiguous: bool,

    /// Exclude specific characters
    #[arg(short = 'e', long = "exclude", default_value = "")]
    pub exclude: String,

    // Passphrase flags
    /// Generate a memorable Diceware passphrase
    #[arg(short = 'p', long = "passphrase")]
    pub passphrase: bool,

    /// Number of words in passphrase (default: 4, or set by preset/min-entropy)
    #[arg(short = 'w', long = "words")]
    pub words: Option<usize>,

    /// Word separator for passphrase
    #[arg(long = "separator", alias = "sep")]
    pub separator: Option<String>,

    /// Capitalize each word in passphrase
    #[arg(long = "capitalize")]
    pub capitalize: bool,

    /// Append a random number to passphrase
    #[arg(long = "include-number")]
    pub include_number: bool,

    // Output & utility flags
    /// Copy generated password to clipboard
    #[arg(short = 'c', long = "copy")]
    pub copy: bool,

    /// Copy directly to clipboard without printing to stdout
    #[arg(long = "copy-only", alias = "clipboard-only")]
    pub copy_only: bool,

    /// Display estimated theoretical keyspace entropy and strength rating
    #[arg(short = 'E', long = "entropy")]
    pub entropy: bool,

    /// Do not print trailing newline
    #[arg(short = '0', long = "no-newline")]
    pub no_newline: bool,

    /// Generate shell completions (bash, elvish, fish, powershell, zsh)
    #[arg(long = "completions", value_enum)]
    pub completions: Option<clap_complete::Shell>,

    /// Generate man page documentation in roff format
    #[arg(long = "man")]
    pub man: bool,

    /// Show version information
    #[arg(short = 'v', long = "version")]
    pub version: bool,
}

pub fn run() {
    let args = Args::parse();
    if let Err(code) = execute_args(&args, &mut std::io::stdout(), &mut std::io::stderr()) {
        process::exit(code);
    }
}

pub fn execute_args(
    args: &Args,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> Result<(), i32> {
    if let Some(shell) = args.completions {
        let mut cmd = Args::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, name, stdout);
        return Ok(());
    }

    if args.man {
        let cmd = Args::command();
        let man = clap_mangen::Man::new(cmd);
        man.render(stdout).map_err(|e| {
            writeln!(stderr, "Error rendering man page: {}", e).ok();
            1
        })?;
        return Ok(());
    }

    if args.version {
        writeln!(stdout, "rustpass 1.1.0").ok();
        return Ok(());
    }

    if args.count == 0 {
        writeln!(stderr, "Error: count must be greater than 0").ok();
        return Err(1);
    }

    let mut is_passphrase = args.passphrase;
    let mut length_opt = args.length;
    let mut words_opt = args.words;
    let separator = args
        .separator
        .clone()
        .unwrap_or_else(|| crate::passphrase::DEFAULT_PASSPHRASE_SEPARATOR.to_string());
    let mut capitalize = args.capitalize;
    let mut include_number = args.include_number;
    let no_upper = args.no_upper;
    let no_lower = args.no_lower;
    let no_digits = args.no_digits;
    let mut no_symbols = args.no_symbols;
    let mut only_alphanumeric = args.only_alphanumeric;
    let mut exclude_ambiguous = args.exclude_ambiguous;
    let symbols_str = if args.symbols.is_empty() {
        crate::generator::DEFAULT_SYMBOLS.to_string()
    } else {
        args.symbols.clone()
    };

    if let Some(preset) = args.preset {
        match preset {
            Preset::Strict => {
                if is_passphrase {
                    writeln!(
                        stderr,
                        "Error: cannot combine --preset strict with passphrase mode (-p)"
                    )
                    .ok();
                    return Err(1);
                }
                if length_opt.is_none() {
                    length_opt = Some(20);
                }
                exclude_ambiguous = true;
            }
            Preset::Alphanumeric => {
                if is_passphrase {
                    writeln!(
                        stderr,
                        "Error: cannot combine --preset alphanumeric with passphrase mode (-p)"
                    )
                    .ok();
                    return Err(1);
                }
                if !args.symbols.is_empty() {
                    writeln!(
                        stderr,
                        "Error: cannot specify custom symbols with alphanumeric preset"
                    )
                    .ok();
                    return Err(1);
                }
                if length_opt.is_none() {
                    length_opt = Some(16);
                }
                only_alphanumeric = true;
                no_symbols = true;
            }
            Preset::Memorable => {
                if only_alphanumeric
                    || no_symbols
                    || no_upper
                    || no_lower
                    || no_digits
                    || !args.symbols.is_empty()
                {
                    writeln!(
                        stderr,
                        "Error: cannot combine character filter options with memorable preset"
                    )
                    .ok();
                    return Err(1);
                }
                is_passphrase = true;
                if words_opt.is_none() {
                    words_opt = Some(5);
                }
                capitalize = true;
                include_number = true;
            }
        }
    }

    if only_alphanumeric && !args.symbols.is_empty() {
        writeln!(
            stderr,
            "Error: cannot specify custom symbols when --only-alphanumeric is enabled"
        )
        .ok();
        return Err(1);
    }

    if no_symbols && !args.symbols.is_empty() {
        writeln!(
            stderr,
            "Error: cannot specify custom symbols when --no-symbols is enabled"
        )
        .ok();
        return Err(1);
    }

    if let Some(min_ent) = args.min_entropy {
        if min_ent <= 0.0 {
            writeln!(stderr, "Error: --min-entropy must be greater than 0").ok();
            return Err(1);
        }
        if min_ent > 10000.0 {
            writeln!(
                stderr,
                "Error: --min-entropy target is unreasonably large (max: 10000)"
            )
            .ok();
            return Err(1);
        }

        if is_passphrase {
            let wordlist_size = crate::wordlist::DEFAULT_WORDLIST.len() as f64;
            let bits_per_word = wordlist_size.log2();
            let num_bits = if include_number {
                (100.0_f64).log2()
            } else {
                0.0
            };
            let needed_entropy = (min_ent - num_bits).max(0.0);
            let required_words = (needed_entropy / bits_per_word).ceil() as usize;
            let required_words = required_words.max(1);

            if let Some(w) = words_opt {
                let actual_entropy = (w as f64) * bits_per_word + num_bits;
                if actual_entropy < min_ent {
                    writeln!(
                        stderr,
                        "Error: specified word count {} yields approximately {:.1} bits of entropy, which is less than requested minimum of {:.1} bits (requires {} words)",
                        w, actual_entropy, min_ent, required_words
                    ).ok();
                    return Err(1);
                }
            } else {
                words_opt = Some(required_words);
            }
        } else {
            let temp_cfg = Config {
                length: 1,
                no_upper,
                no_lower,
                no_digits,
                no_symbols,
                only_alphanumeric,
                symbols: symbols_str.clone(),
                exclude_ambiguous,
                exclude_chars: args.exclude.clone(),
            };
            let pool_size = match effective_pool_size(&temp_cfg) {
                Ok(size) => size,
                Err(e) => {
                    writeln!(stderr, "Error: {}", e).ok();
                    return Err(1);
                }
            };
            if pool_size <= 1 {
                writeln!(
                    stderr,
                    "Error: character pool size is too small to satisfy minimum entropy"
                )
                .ok();
                return Err(1);
            }
            let bits_per_char = (pool_size as f64).log2();
            let required_length = (min_ent / bits_per_char).ceil() as usize;
            let required_length = required_length.max(1);

            if let Some(l) = length_opt {
                let actual_entropy = (l as f64) * bits_per_char;
                if actual_entropy < min_ent {
                    writeln!(
                        stderr,
                        "Error: specified length {} yields approximately {:.1} bits of entropy, which is less than requested minimum of {:.1} bits (requires length {})",
                        l, actual_entropy, min_ent, required_length
                    ).ok();
                    return Err(1);
                }
            } else {
                length_opt = Some(required_length);
            }
        }
    }

    let final_length = length_opt.unwrap_or(crate::generator::DEFAULT_LENGTH);
    let final_words = words_opt.unwrap_or(crate::passphrase::DEFAULT_PASSPHRASE_WORD_COUNT);

    if !is_passphrase && final_length == 0 {
        writeln!(stderr, "Error: password length must be greater than 0").ok();
        return Err(1);
    }

    if is_passphrase && final_words == 0 {
        writeln!(stderr, "Error: word count must be greater than 0").ok();
        return Err(1);
    }

    let cfg = Config {
        length: final_length,
        no_upper,
        no_lower,
        no_digits,
        no_symbols,
        only_alphanumeric,
        symbols: symbols_str,
        exclude_ambiguous,
        exclude_chars: args.exclude.clone(),
    };

    let pass_cfg = PassphraseConfig {
        word_count: final_words,
        separator,
        capitalize,
        include_number,
        word_list: None,
    };

    let mut results: Vec<String> = Vec::with_capacity(args.count);
    let mut json_entries: Vec<JsonPasswordEntry> = Vec::with_capacity(args.count);

    for _ in 0..args.count {
        let (output, pool_size, entropy) = if is_passphrase {
            match generate_passphrase(&pass_cfg) {
                Ok((passphrase, pool_size)) => {
                    let entropy = calculate_passphrase_entropy_with_number(
                        final_words,
                        pool_size,
                        include_number,
                    );
                    (passphrase, pool_size, entropy)
                }
                Err(err) => {
                    writeln!(stderr, "Error: {}", err).ok();
                    return Err(1);
                }
            }
        } else {
            match generate(&cfg) {
                Ok((password, pool_size)) => {
                    let entropy = calculate_entropy(&password, pool_size);
                    (password, pool_size, entropy)
                }
                Err(err) => {
                    writeln!(stderr, "Error: {}", err).ok();
                    return Err(1);
                }
            }
        };

        if args.format == OutputFormat::Json {
            json_entries.push(JsonPasswordEntry {
                value: output.clone(),
                length: output.chars().count(),
                entropy_bits: if args.entropy {
                    Some((entropy * 10.0).round() / 10.0)
                } else {
                    None
                },
                shannon_entropy: if args.entropy {
                    Some((shannon_entropy(&output) * 100.0).round() / 100.0)
                } else {
                    None
                },
                pool_size: if args.entropy { Some(pool_size) } else { None },
                strength_rating: if args.entropy {
                    Some(strength_rating(entropy).to_string())
                } else {
                    None
                },
            });
        } else if args.entropy && !args.copy_only {
            let rating = strength_rating(entropy);
            if args.count == 1 {
                writeln!(stdout, "{}", output).ok();
                if !args.quiet {
                    print_entropy_diagnostics_to(&output, entropy, pool_size, stderr);
                }
            } else {
                writeln!(
                    stdout,
                    "{:<24} [Entropy: {:.1} bits, Strength: {}]",
                    output, entropy, rating
                )
                .ok();
            }
        }

        results.push(output);
    }

    if args.copy || args.copy_only {
        let mut clipboard_text = results.join("\n");
        let copy_res = handle_copy(&clipboard_text, stderr, args.quiet);
        clipboard_text.zeroize();
        if args.copy_only && copy_res.is_err() {
            for mut s in results {
                s.zeroize();
            }
            return Err(1);
        }
    }

    if !args.copy_only {
        if args.format == OutputFormat::Json {
            let response = JsonResponse {
                count: json_entries.len(),
                passwords: json_entries,
            };
            let json_str = serde_json::to_string_pretty(&response).map_err(|e| {
                writeln!(stderr, "Error: serializing JSON: {}", e).ok();
                1
            })?;
            if args.no_newline {
                write!(stdout, "{}", json_str).ok();
            } else {
                writeln!(stdout, "{}", json_str).ok();
            }
        } else if !args.entropy {
            if args.no_newline && args.count == 1 {
                write!(stdout, "{}", results[0]).ok();
            } else {
                for res in &results {
                    writeln!(stdout, "{}", res).ok();
                }
            }
        }
    }

    for mut s in results {
        s.zeroize();
    }

    Ok(())
}

fn handle_copy(text: &str, stderr: &mut dyn std::io::Write, quiet: bool) -> Result<(), ()> {
    match copy_to_clipboard(text) {
        Ok(()) => {
            if !quiet {
                writeln!(stderr, "✓ Copied to clipboard").ok();
            }
            Ok(())
        }
        Err(e) => {
            if !quiet {
                writeln!(stderr, "Warning: {}", e).ok();
            }
            Err(())
        }
    }
}

fn print_entropy_diagnostics_to(
    output: &str,
    entropy: f64,
    pool_size: usize,
    stderr: &mut dyn std::io::Write,
) {
    let rating = strength_rating(entropy);
    let shannon = shannon_entropy(output);
    writeln!(
        stderr,
        "Entropy:   {:.1} bits ({})\nShannon:   {:.2} bits/char\nPool Size: {}",
        entropy, rating, shannon, pool_size
    )
    .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_args_entropy_flags() {
        let args = Args::try_parse_from(["rustpass", "-E"]).unwrap();
        assert!(args.entropy);

        let args = Args::try_parse_from(["rustpass", "--entropy"]).unwrap();
        assert!(args.entropy);

        let args = Args::try_parse_from(["rustpass"]).unwrap();
        assert!(!args.entropy);
    }

    #[test]
    fn test_args_copy_flags() {
        let args = Args::try_parse_from(["rustpass", "-c"]).unwrap();
        assert!(args.copy);

        let args = Args::try_parse_from(["rustpass", "--copy"]).unwrap();
        assert!(args.copy);

        let args = Args::try_parse_from(["rustpass"]).unwrap();
        assert!(!args.copy);
    }

    #[test]
    fn test_args_count_flags() {
        let args = Args::try_parse_from(["rustpass", "-n", "5"]).unwrap();
        assert_eq!(args.count, 5);

        let args = Args::try_parse_from(["rustpass", "--count", "10"]).unwrap();
        assert_eq!(args.count, 10);

        let args = Args::try_parse_from(["rustpass"]).unwrap();
        assert_eq!(args.count, 1);
    }

    #[test]
    fn test_args_no_newline_flags() {
        let args = Args::try_parse_from(["rustpass", "-0"]).unwrap();
        assert!(args.no_newline);

        let args = Args::try_parse_from(["rustpass", "--no-newline"]).unwrap();
        assert!(args.no_newline);

        let args = Args::try_parse_from(["rustpass"]).unwrap();
        assert!(!args.no_newline);
    }

    #[test]
    fn test_args_version_flags() {
        let args = Args::try_parse_from(["rustpass", "-v"]).unwrap();
        assert!(args.version);

        let args = Args::try_parse_from(["rustpass", "--version"]).unwrap();
        assert!(args.version);

        let args = Args::try_parse_from(["rustpass"]).unwrap();
        assert!(!args.version);
    }

    #[test]
    fn test_execute_version() {
        let args = Args::try_parse_from(["rustpass", "--version"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out_str = String::from_utf8(stdout).unwrap();
        assert_eq!(out_str, "rustpass 1.1.0\n");
    }

    #[test]
    fn test_execute_zero_count() {
        let args = Args::try_parse_from(["rustpass", "-n", "0"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Err(1));
        let err_str = String::from_utf8(stderr).unwrap();
        assert!(err_str.contains("Error: count must be greater than 0"));
    }

    #[test]
    fn test_execute_zero_length() {
        let args = Args::try_parse_from(["rustpass", "-l", "0"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Err(1));
        let err_str = String::from_utf8(stderr).unwrap();
        assert!(err_str.contains("Error: password length must be greater than 0"));
    }

    #[test]
    fn test_execute_batch_generation() {
        let args = Args::try_parse_from(["rustpass", "-n", "5"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out_str = String::from_utf8(stdout).unwrap();
        let lines: Vec<&str> = out_str.lines().collect();
        assert_eq!(lines.len(), 5);
        for line in lines {
            assert_eq!(line.len(), 12);
        }
    }

    #[test]
    fn test_execute_no_newline() {
        let args = Args::try_parse_from(["rustpass", "-0"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out_str = String::from_utf8(stdout).unwrap();
        assert_eq!(out_str.len(), 12);
        assert!(!out_str.ends_with('\n'));
    }

    #[test]
    fn test_execute_no_newline_ignored_for_count_greater_than_1() {
        let args = Args::try_parse_from(["rustpass", "-0", "-n", "2"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out_str = String::from_utf8(stdout).unwrap();
        let lines: Vec<&str> = out_str.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(out_str.ends_with('\n'));
    }

    #[test]
    fn test_execute_single_entropy() {
        let args = Args::try_parse_from(["rustpass", "-E"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out_str = String::from_utf8(stdout).unwrap();
        let lines: Vec<&str> = out_str.lines().collect();
        assert_eq!(lines.len(), 1);
        let err_str = String::from_utf8(stderr).unwrap();
        assert!(err_str.contains("Entropy:"));
        assert!(err_str.contains("Pool Size:"));
    }

    #[test]
    fn test_execute_batch_entropy() {
        let args = Args::try_parse_from(["rustpass", "-n", "3", "-E"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out_str = String::from_utf8(stdout).unwrap();
        let lines: Vec<&str> = out_str.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            assert!(line.contains("[Entropy:"));
            assert!(line.contains("Strength:"));
        }
    }

    #[test]
    fn test_execute_passphrase_batch() {
        let args =
            Args::try_parse_from(["rustpass", "-p", "-n", "3", "-w", "4", "--separator", "#"])
                .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out_str = String::from_utf8(stdout).unwrap();
        let lines: Vec<&str> = out_str.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            assert_eq!(line.split('#').count(), 4);
        }
    }

    #[test]
    fn test_zeroize_hygiene() {
        let mut s = "super_secret_password".to_string();
        s.zeroize();
        assert!(s.is_empty());
    }

    #[test]
    fn test_handle_copy_writes_to_stderr() {
        let mut stderr = Vec::new();
        let _ = handle_copy("test-password", &mut stderr, false);
        let out = String::from_utf8(stderr).unwrap();
        assert!(out.contains("✓ Copied to clipboard") || out.contains("Warning:"));
    }

    #[test]
    fn test_handle_copy_quiet_suppresses_stderr() {
        let mut stderr = Vec::new();
        let _ = handle_copy("test-password", &mut stderr, true);
        assert!(stderr.is_empty());
    }

    #[test]
    fn test_execute_with_copy() {
        let args = Args::try_parse_from(["rustpass", "--copy"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let err_out = String::from_utf8(stderr).unwrap();
        assert!(err_out.contains("✓ Copied to clipboard") || err_out.contains("Warning:"));
    }

    #[test]
    fn test_execute_with_copy_and_quiet() {
        let args = Args::try_parse_from(["rustpass", "--copy", "-q"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        assert!(stderr.is_empty());
    }

    #[test]
    fn test_execute_json_output() {
        let args = Args::try_parse_from(["rustpass", "-n", "2", "-l", "16", "-f", "json"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        assert!(stderr.is_empty());

        let out_str = String::from_utf8(stdout).unwrap();
        let parsed: JsonResponse = serde_json::from_str(&out_str).unwrap();
        assert_eq!(parsed.count, 2);
        assert_eq!(parsed.passwords.len(), 2);
        for entry in &parsed.passwords {
            assert_eq!(entry.length, 16);
            assert_eq!(entry.value.len(), 16);
            // Entropy fields must NOT be present when -E is not passed
            assert!(entry.entropy_bits.is_none());
            assert!(entry.shannon_entropy.is_none());
            assert!(entry.pool_size.is_none());
            assert!(entry.strength_rating.is_none());
        }
    }

    #[test]
    fn test_execute_json_output_with_entropy() {
        let args = Args::try_parse_from(["rustpass", "-l", "16", "-f", "json", "-E"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        assert!(stderr.is_empty());

        let out_str = String::from_utf8(stdout).unwrap();
        let parsed: JsonResponse = serde_json::from_str(&out_str).unwrap();
        assert_eq!(parsed.count, 1);
        let entry = &parsed.passwords[0];
        assert_eq!(entry.length, 16);
        assert!(entry.entropy_bits.is_some());
        assert!(entry.shannon_entropy.is_some());
        assert_eq!(entry.pool_size, Some(68));
        assert!(entry.strength_rating.is_some());
    }

    #[test]
    fn test_execute_json_passphrase() {
        let args = Args::try_parse_from([
            "rustpass",
            "-p",
            "-w",
            "5",
            "--include-number",
            "-f",
            "json",
            "-E",
        ])
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        assert!(stderr.is_empty());

        let out_str = String::from_utf8(stdout).unwrap();
        let parsed: JsonResponse = serde_json::from_str(&out_str).unwrap();
        assert_eq!(parsed.count, 1);
        let entry = &parsed.passwords[0];
        assert!(entry.entropy_bits.is_some());
        // 5 words (~51.7) + number (~6.64) ≈ 58.3 bits
        assert!(entry.entropy_bits.unwrap() > 55.0);
    }

    #[test]
    fn test_execute_conflicting_symbols_with_only_alphanumeric() {
        let args = Args::try_parse_from(["rustpass", "-A", "--symbols", "!@#"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Err(1));
        let err_out = String::from_utf8(stderr).unwrap();
        assert!(err_out
            .contains("Error: cannot specify custom symbols when --only-alphanumeric is enabled"));
    }

    #[test]
    fn test_execute_conflicting_symbols_with_no_symbols() {
        let args = Args::try_parse_from(["rustpass", "-S", "--symbols", "!@#"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Err(1));
        let err_out = String::from_utf8(stderr).unwrap();
        assert!(
            err_out.contains("Error: cannot specify custom symbols when --no-symbols is enabled")
        );
    }

    #[test]
    fn test_execute_passphrase_entropy_includes_number() {
        // Without number: 4 words -> ~41.4 bits
        let args_without = Args::try_parse_from(["rustpass", "-p", "-E"]).unwrap();
        let mut out_without = Vec::new();
        let mut err_without = Vec::new();
        execute_args(&args_without, &mut out_without, &mut err_without).unwrap();
        let err_str_without = String::from_utf8(err_without).unwrap();
        assert!(err_str_without.contains("Entropy:   41.4 bits"));

        // With number: 4 words + number -> ~48.0 bits
        let args_with = Args::try_parse_from(["rustpass", "-p", "-E", "--include-number"]).unwrap();
        let mut out_with = Vec::new();
        let mut err_with = Vec::new();
        execute_args(&args_with, &mut out_with, &mut err_with).unwrap();
        let err_str_with = String::from_utf8(err_with).unwrap();
        assert!(err_str_with.contains("Entropy:   48.0 bits"));
    }

    #[test]
    fn test_execute_preset_strict() {
        let args = Args::try_parse_from(["rustpass", "--preset", "strict"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        assert_eq!(out.len(), 20); // Strict default length is 20
        assert!(out.chars().all(|c| !"0O1lI|".contains(c))); // Ambiguous excluded
    }

    #[test]
    fn test_execute_preset_strict_with_length_override() {
        let args = Args::try_parse_from(["rustpass", "--preset", "strict", "-l", "32"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn test_execute_preset_alphanumeric() {
        let args = Args::try_parse_from(["rustpass", "--preset", "alphanumeric"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        assert_eq!(out.len(), 16); // Alphanumeric default length is 16
        assert!(out.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_execute_preset_alphanumeric_conflicting_symbols() {
        let args =
            Args::try_parse_from(["rustpass", "--preset", "alphanumeric", "--symbols", "!@#"])
                .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Err(1));
        let err = String::from_utf8(stderr).unwrap();
        assert!(err.contains("Error: cannot specify custom symbols with alphanumeric preset"));
    }

    #[test]
    fn test_execute_preset_memorable() {
        let args = Args::try_parse_from(["rustpass", "--preset", "memorable"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        let parts: Vec<&str> = out.split('-').collect();
        assert_eq!(parts.len(), 6); // 5 words + 1 number
        for w in &parts[..5] {
            assert!(w.chars().next().unwrap().is_uppercase());
        }
    }

    #[test]
    fn test_execute_min_entropy_standard_password() {
        // Pool is 68 -> log2(68) ≈ 6.087 bits/char. 100 bits requires ceil(100/6.087) = 17 chars.
        let args = Args::try_parse_from(["rustpass", "--min-entropy", "100"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        assert_eq!(out.len(), 17);
    }

    #[test]
    fn test_execute_min_entropy_rejected_when_length_too_small() {
        let args = Args::try_parse_from(["rustpass", "--min-entropy", "100", "-l", "10"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Err(1));
        let err = String::from_utf8(stderr).unwrap();
        assert!(err.contains("less than requested minimum"));
    }

    #[test]
    fn test_execute_min_entropy_passphrase() {
        // EFF wordlist = 1296 -> log2(1296) ≈ 10.34 bits/word. 50 bits requires ceil(50/10.34) = 5 words.
        let args = Args::try_parse_from(["rustpass", "-p", "--min-entropy", "50"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        let parts: Vec<&str> = out.split('-').collect();
        assert_eq!(parts.len(), 5);
    }

    #[test]
    fn test_execute_copy_only() {
        let args = Args::try_parse_from(["rustpass", "--copy-only"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        // Stdout MUST be empty
        assert!(stdout.is_empty());
    }

    #[test]
    fn test_execute_completions() {
        let args = Args::try_parse_from(["rustpass", "--completions", "bash"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap();
        assert!(out.contains("_rustpass") || out.contains("complete"));
    }

    #[test]
    fn test_execute_man() {
        let args = Args::try_parse_from(["rustpass", "--man"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap();
        assert!(out.contains(".TH rustpass") || out.contains("rustpass"));
    }
}
