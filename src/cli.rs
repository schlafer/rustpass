use std::process;

use clap::{CommandFactory, Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::clipboard::copy_to_clipboard;
use crate::entropy::{
    calculate_partitioned_entropy, calculate_passphrase_entropy_with_number, floor_entropy,
    min_length_for_entropy, shannon_entropy, strength_rating,
};
use crate::generator::{build_active_groups, generate, Config};
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

fn validate_min_entropy(min_ent: f64, stderr: &mut dyn std::io::Write) -> Result<(), ()> {
    if !min_ent.is_finite() {
        writeln!(stderr, "Error: --min-entropy must be a finite number").ok();
        return Err(());
    }
    if min_ent <= 0.0 {
        writeln!(stderr, "Error: --min-entropy must be greater than 0").ok();
        return Err(());
    }
    if min_ent > 10000.0 {
        writeln!(
            stderr,
            "Error: --min-entropy target is unreasonably large (max: 10000)"
        )
        .ok();
        return Err(());
    }
    Ok(())
}

pub fn execute_args(
    args: &Args,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> Result<(), i32> {
    execute_args_with(args, stdout, stderr, copy_to_clipboard)
}

pub(crate) fn execute_args_with(
    args: &Args,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
    mut copy_fn: impl FnMut(&str) -> Result<(), crate::error::Error>,
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
        if validate_min_entropy(min_ent, stderr).is_err() {
            return Err(1);
        }

        if is_passphrase {
            let wordlist_size = crate::wordlist::DEFAULT_WORDLIST.len();
            let bits_per_word = (wordlist_size as f64).log2();
            let num_bits = if include_number {
                (100.0_f64).log2()
            } else {
                0.0
            };
            let needed_entropy = (min_ent - num_bits).max(0.0);
            let required_words = (needed_entropy / bits_per_word).ceil() as usize;
            let required_words = required_words.max(1);

            if let Some(w) = words_opt {
                let actual_entropy =
                    calculate_passphrase_entropy_with_number(w, wordlist_size, include_number);
                if actual_entropy < min_ent {
                    writeln!(
                        stderr,
                        "Error: specified word count {} yields approximately {:.1} bits of entropy, which is less than requested minimum of {:.1} bits (requires {} words)",
                        w, floor_entropy(actual_entropy), min_ent, required_words
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
            let groups = match build_active_groups(&temp_cfg) {
                Ok(g) => g,
                Err(e) => {
                    writeln!(stderr, "Error: {}", e).ok();
                    return Err(1);
                }
            };
            let group_sizes: Vec<usize> = groups.iter().map(|g| g.chars().count()).collect();
            let required_length = match min_length_for_entropy(&group_sizes, min_ent) {
                Some(len) => len,
                None => {
                    writeln!(
                        stderr,
                        "Error: character pool configuration cannot satisfy minimum entropy target"
                    )
                    .ok();
                    return Err(1);
                }
            };

            if let Some(l) = length_opt {
                let actual_entropy = calculate_partitioned_entropy(&group_sizes, l);
                if actual_entropy < min_ent {
                    writeln!(
                        stderr,
                        "Error: specified length {} yields approximately {:.1} bits of entropy, which is less than requested minimum of {:.1} bits (requires length {})",
                        l, floor_entropy(actual_entropy), min_ent, required_length
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

    let (overall_pool_size, overall_entropy) = if is_passphrase {
        let pool_size = crate::wordlist::DEFAULT_WORDLIST.len();
        let entropy =
            calculate_passphrase_entropy_with_number(final_words, pool_size, include_number);
        (pool_size, entropy)
    } else {
        let groups = match build_active_groups(&cfg) {
            Ok(g) => g,
            Err(err) => {
                writeln!(stderr, "Error: {}", err).ok();
                return Err(1);
            }
        };
        let pool_size: usize = groups.iter().map(|g| g.chars().count()).sum();
        let group_sizes: Vec<usize> = groups.iter().map(|g| g.chars().count()).collect();
        let entropy = calculate_partitioned_entropy(&group_sizes, final_length);
        (pool_size, entropy)
    };

    let floored_ent = floor_entropy(overall_entropy);
    let rating = strength_rating(floored_ent);

    let mut results: Vec<Zeroizing<String>> = Vec::with_capacity(args.count);
    let mut json_entries: Vec<JsonPasswordEntry> = Vec::with_capacity(args.count);

    for _ in 0..args.count {
        let output = if is_passphrase {
            match generate_passphrase(&pass_cfg) {
                Ok((passphrase, _)) => passphrase,
                Err(err) => {
                    writeln!(stderr, "Error: {}", err).ok();
                    return Err(1);
                }
            }
        } else {
            match generate(&cfg) {
                Ok((password, _)) => password,
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
                    Some(floored_ent)
                } else {
                    None
                },
                shannon_entropy: if args.entropy {
                    Some((shannon_entropy(&output) * 100.0).round() / 100.0)
                } else {
                    None
                },
                pool_size: if args.entropy {
                    Some(overall_pool_size)
                } else {
                    None
                },
                strength_rating: if args.entropy {
                    Some(rating.to_string())
                } else {
                    None
                },
            });
        } else if args.entropy && !args.copy_only {
            if args.count == 1 {
                writeln!(stdout, "{}", output).ok();
                if !args.quiet {
                    print_entropy_diagnostics_to(
                        &output,
                        floored_ent,
                        rating,
                        overall_pool_size,
                        stderr,
                    );
                }
            } else {
                writeln!(
                    stdout,
                    "{:<24} [Entropy: {:.1} bits, Strength: {}]",
                    output, floored_ent, rating
                )
                .ok();
            }
        }

        results.push(Zeroizing::new(output));
    }

    if args.copy || args.copy_only {
        let copy_res = if results.len() == 1 {
            handle_copy(&results[0], stderr, args.quiet, &mut copy_fn)
        } else {
            let total_len: usize =
                results.iter().map(|s| s.len()).sum::<usize>() + (results.len() - 1);
            let mut joined = Zeroizing::new(String::with_capacity(total_len));
            for (i, r) in results.iter().enumerate() {
                if i > 0 {
                    joined.push('\n');
                }
                joined.push_str(r);
            }
            handle_copy(&joined, stderr, args.quiet, &mut copy_fn)
        };

        if args.copy_only && copy_res.is_err() {
            return Err(1);
        }
    }

    if !args.copy_only {
        if args.format == OutputFormat::Json {
            let mut response = JsonResponse {
                count: json_entries.len(),
                passwords: json_entries,
            };
            let mut json_str = serde_json::to_string_pretty(&response).map_err(|e| {
                writeln!(stderr, "Error: serializing JSON: {}", e).ok();
                for entry in &mut response.passwords {
                    entry.value.zeroize();
                }
                1
            })?;
            for entry in &mut response.passwords {
                entry.value.zeroize();
            }
            if args.no_newline {
                write!(stdout, "{}", json_str).ok();
            } else {
                writeln!(stdout, "{}", json_str).ok();
            }
            json_str.zeroize();
        } else if !args.entropy {
            if args.no_newline && args.count == 1 {
                write!(stdout, "{}", results[0].as_str()).ok();
            } else {
                for res in &results {
                    writeln!(stdout, "{}", res.as_str()).ok();
                }
            }
        }
    }

    Ok(())
}

fn handle_copy(
    text: &str,
    stderr: &mut dyn std::io::Write,
    quiet: bool,
    copy_fn: &mut dyn FnMut(&str) -> Result<(), crate::error::Error>,
) -> Result<(), ()> {
    match copy_fn(text) {
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
    rating: &str,
    pool_size: usize,
    stderr: &mut dyn std::io::Write,
) {
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
        let _ = handle_copy("test-password", &mut stderr, false, &mut |_| Ok(()));
        let out = String::from_utf8(stderr).unwrap();
        assert!(out.contains("✓ Copied to clipboard"));
    }

    #[test]
    fn test_handle_copy_warning_to_stderr() {
        let mut stderr = Vec::new();
        let _ = handle_copy("test-password", &mut stderr, false, &mut |_| {
            Err(crate::error::Error::Clipboard("failed".to_string()))
        });
        let out = String::from_utf8(stderr).unwrap();
        assert!(out.contains("Warning: Clipboard error: failed"));
    }

    #[test]
    fn test_handle_copy_quiet_suppresses_stderr() {
        let mut stderr = Vec::new();
        let _ = handle_copy("test-password", &mut stderr, true, &mut |_| Ok(()));
        assert!(stderr.is_empty());
    }

    #[test]
    fn test_execute_with_copy() {
        let args = Args::try_parse_from(["rustpass", "--copy"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args_with(&args, &mut stdout, &mut stderr, |_| Ok(()));
        assert_eq!(res, Ok(()));
        let err_out = String::from_utf8(stderr).unwrap();
        assert!(err_out.contains("✓ Copied to clipboard"));
    }

    #[test]
    fn test_execute_with_copy_and_quiet() {
        let args = Args::try_parse_from(["rustpass", "--copy", "-q"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args_with(&args, &mut stdout, &mut stderr, |_| Ok(()));
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
        // Without number: 4 words -> 4 * log2(1296) ≈ 41.359 bits floored to 41.3 bits
        let args_without = Args::try_parse_from(["rustpass", "-p", "-E"]).unwrap();
        let mut out_without = Vec::new();
        let mut err_without = Vec::new();
        execute_args(&args_without, &mut out_without, &mut err_without).unwrap();
        let err_str_without = String::from_utf8(err_without).unwrap();
        assert!(err_str_without.contains("Entropy:   41.3 bits"));

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
        let args = Args::try_parse_from(["rustpass", "--preset", "memorable", "--separator", "."])
            .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        let parts: Vec<&str> = out.split('.').collect();
        assert_eq!(parts.len(), 6); // 5 words + 1 number
        for w in &parts[..5] {
            assert!(w.chars().next().unwrap().is_uppercase());
        }

        // Verify default separator constant
        assert_eq!(crate::passphrase::DEFAULT_PASSPHRASE_SEPARATOR, "-");
    }

    #[test]
    fn test_execute_min_entropy_standard_password() {
        // Under partitioned generation, 17 chars yields 93.6 bits, while 18 chars achieves 100.15 bits (>= 100).
        let args = Args::try_parse_from(["rustpass", "--min-entropy", "100"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        assert_eq!(out.len(), 18);
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
        let args =
            Args::try_parse_from(["rustpass", "-p", "--separator", ".", "--min-entropy", "50"])
                .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args(&args, &mut stdout, &mut stderr);
        assert_eq!(res, Ok(()));
        let out = String::from_utf8(stdout).unwrap().trim().to_string();
        let parts: Vec<&str> = out.split('.').collect();
        assert_eq!(parts.len(), 5);
    }

    #[test]
    fn test_execute_copy_only() {
        let args = Args::try_parse_from(["rustpass", "--copy-only"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args_with(&args, &mut stdout, &mut stderr, |_| Ok(()));
        assert_eq!(res, Ok(()));
        // Stdout MUST be empty
        assert!(stdout.is_empty());
    }

    #[test]
    fn test_execute_mock_backend_single_copy() {
        let args = Args::try_parse_from(["rustpass", "-c"]).unwrap();
        let mut copied = String::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args_with(&args, &mut stdout, &mut stderr, |text| {
            copied = text.to_string();
            Ok(())
        });
        assert_eq!(res, Ok(()));
        let stdout_str = String::from_utf8(stdout).unwrap().trim().to_string();
        assert_eq!(copied, stdout_str);
    }

    #[test]
    fn test_execute_mock_backend_batch_copy() {
        let args = Args::try_parse_from(["rustpass", "-n", "3", "-c"]).unwrap();
        let mut copied = String::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args_with(&args, &mut stdout, &mut stderr, |text| {
            copied = text.to_string();
            Ok(())
        });
        assert_eq!(res, Ok(()));
        let stdout_str = String::from_utf8(stdout).unwrap().trim().to_string();
        assert_eq!(copied, stdout_str);
        let lines: Vec<&str> = copied.lines().collect();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn test_execute_mock_backend_copy_only_silent_stdout() {
        let args = Args::try_parse_from(["rustpass", "--copy-only"]).unwrap();
        let mut copied = String::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args_with(&args, &mut stdout, &mut stderr, |text| {
            copied = text.to_string();
            Ok(())
        });
        assert_eq!(res, Ok(()));
        assert!(stdout.is_empty());
        assert!(!copied.is_empty());
    }

    #[test]
    fn test_execute_mock_backend_copy_only_failure_exits_one() {
        let args = Args::try_parse_from(["rustpass", "--copy-only"]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let res = execute_args_with(&args, &mut stdout, &mut stderr, |_| {
            Err(crate::error::Error::Clipboard(
                "mock copy error".to_string(),
            ))
        });
        assert_eq!(res, Err(1));
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("mock copy error"));
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

    #[test]
    fn test_execute_min_entropy_validation() {
        let make_args = |min_ent: f64| Args {
            length: None,
            count: 1,
            preset: None,
            min_entropy: Some(min_ent),
            format: OutputFormat::Text,
            quiet: false,
            no_upper: false,
            no_lower: false,
            no_digits: false,
            no_symbols: false,
            only_alphanumeric: false,
            symbols: String::new(),
            exclude_ambiguous: false,
            exclude: String::new(),
            passphrase: false,
            words: None,
            separator: None,
            capitalize: false,
            include_number: false,
            copy: false,
            copy_only: false,
            entropy: false,
            no_newline: false,
            completions: None,
            man: false,
            version: false,
        };

        // 1. NaN
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_args(&make_args(f64::NAN), &mut stdout, &mut stderr),
            Err(1)
        );
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("must be a finite number"));

        // 2. Infinity
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_args(&make_args(f64::INFINITY), &mut stdout, &mut stderr),
            Err(1)
        );
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("must be a finite number"));

        // 3. Negative Infinity
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_args(&make_args(f64::NEG_INFINITY), &mut stdout, &mut stderr),
            Err(1)
        );
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("must be a finite number"));

        // 4. Zero
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_args(&make_args(0.0), &mut stdout, &mut stderr),
            Err(1)
        );
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("greater than 0"));

        // 5. Negative
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_args(&make_args(-1.0), &mut stdout, &mut stderr),
            Err(1)
        );
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("greater than 0"));

        // 6. Too large
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_args(&make_args(10001.0), &mut stdout, &mut stderr),
            Err(1)
        );
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("unreasonably large"));

        // 7. Tiny positive
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_args(&make_args(0.001), &mut stdout, &mut stderr),
            Ok(())
        );
        assert_eq!(String::from_utf8(stdout).unwrap().trim().len(), 1);

        // 8. Valid target
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_args(&make_args(50.0), &mut stdout, &mut stderr),
            Ok(())
        );
        assert_eq!(String::from_utf8(stdout).unwrap().trim().len(), 10);
    }

    #[test]
    fn test_entropy_text_and_json_consistency() {
        for len in [8, 12, 16, 20] {
            // JSON execution
            let args_json =
                Args::try_parse_from(["rustpass", "-l", &len.to_string(), "-f", "json", "-E"])
                    .unwrap();
            let mut stdout_json = Vec::new();
            let mut stderr_json = Vec::new();
            execute_args(&args_json, &mut stdout_json, &mut stderr_json).unwrap();
            let json_resp: JsonResponse =
                serde_json::from_str(&String::from_utf8(stdout_json).unwrap()).unwrap();
            let json_bits = json_resp.passwords[0].entropy_bits.unwrap();
            let json_rating = json_resp.passwords[0].strength_rating.as_ref().unwrap();

            // Text execution
            let args_text =
                Args::try_parse_from(["rustpass", "-l", &len.to_string(), "-E"]).unwrap();
            let mut stdout_text = Vec::new();
            let mut stderr_text = Vec::new();
            execute_args(&args_text, &mut stdout_text, &mut stderr_text).unwrap();
            let err_text = String::from_utf8(stderr_text).unwrap();

            assert!(err_text.contains(&format!(
                "Entropy:   {:.1} bits ({})",
                json_bits, json_rating
            )));
        }
    }
}
