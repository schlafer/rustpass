use std::process;

use clap::Parser;
use zeroize::Zeroize;

use crate::clipboard::copy_to_clipboard;
use crate::entropy::{
    calculate_entropy, calculate_passphrase_entropy, shannon_entropy, strength_rating,
};
use crate::generator::{generate, Config};
use crate::passphrase::{generate_passphrase, PassphraseConfig};

#[derive(Parser, Debug)]
#[command(
    name = "rustpass",
    about = "CLI password generator",
    disable_version_flag = true
)]
pub struct Args {
    /// Password length
    #[arg(short = 'l', long = "length", default_value_t = 12)]
    pub length: usize,

    /// Number of passwords to generate
    #[arg(short = 'n', long = "count", default_value_t = 1)]
    pub count: usize,

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

    /// Number of words in passphrase
    #[arg(short = 'w', long = "words", default_value_t = 4)]
    pub words: usize,

    /// Word separator for passphrase
    #[arg(long = "separator", alias = "sep", default_value = "-")]
    pub separator: String,

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

    /// Display entropy and strength rating
    #[arg(short = 'E', long = "entropy")]
    pub entropy: bool,

    /// Do not print trailing newline
    #[arg(short = '0', long = "no-newline")]
    pub no_newline: bool,

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
    if args.version {
        writeln!(stdout, "rustpass 1.1.0").ok();
        return Ok(());
    }

    if args.count == 0 {
        writeln!(stderr, "Error: count must be greater than 0").ok();
        return Err(1);
    }

    if !args.passphrase && args.length == 0 {
        writeln!(stderr, "Error: password length must be greater than 0").ok();
        return Err(1);
    }

    let cfg = Config {
        length: args.length,
        no_upper: args.no_upper,
        no_lower: args.no_lower,
        no_digits: args.no_digits,
        no_symbols: args.no_symbols,
        only_alphanumeric: args.only_alphanumeric,
        symbols: if args.symbols.is_empty() {
            crate::generator::DEFAULT_SYMBOLS.to_string()
        } else {
            args.symbols.clone()
        },
        exclude_ambiguous: args.exclude_ambiguous,
        exclude_chars: args.exclude.clone(),
    };

    let pass_cfg = PassphraseConfig {
        word_count: args.words,
        separator: args.separator.clone(),
        capitalize: args.capitalize,
        include_number: args.include_number,
        word_list: None,
    };

    let mut results: Vec<String> = Vec::with_capacity(args.count);

    for _ in 0..args.count {
        let (output, pool_size, entropy) = if args.passphrase {
            match generate_passphrase(&pass_cfg) {
                Ok((passphrase, pool_size)) => {
                    let entropy = calculate_passphrase_entropy(args.words, pool_size);
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

        if args.entropy {
            let rating = strength_rating(entropy);
            if args.count == 1 {
                writeln!(stdout, "{}", output).ok();
                print_entropy_diagnostics_to(&output, entropy, pool_size, stderr);
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

    if !args.entropy {
        if args.no_newline && args.count == 1 {
            write!(stdout, "{}", results[0]).ok();
        } else {
            for res in &results {
                writeln!(stdout, "{}", res).ok();
            }
        }
    }

    if args.copy {
        let mut clipboard_text = results.join("\n");
        handle_copy(&clipboard_text, stderr);
        clipboard_text.zeroize();
    }

    for mut s in results {
        s.zeroize();
    }

    Ok(())
}

fn handle_copy(text: &str, stderr: &mut dyn std::io::Write) {
    match copy_to_clipboard(text) {
        Ok(()) => {
            writeln!(stderr, "✓ Copied to clipboard").ok();
        }
        Err(e) => {
            writeln!(stderr, "Warning: {}", e).ok();
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
        handle_copy("test-password", &mut stderr);
        let out = String::from_utf8(stderr).unwrap();
        assert!(out.contains("✓ Copied to clipboard") || out.contains("Warning:"));
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
}
