use std::process;

use clap::Parser;

use crate::entropy::{calculate_entropy, calculate_passphrase_entropy, strength_rating};
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

    if args.version {
        println!("rustpass 1.1.0");
        process::exit(0);
    }

    if args.passphrase {
        let pass_cfg = PassphraseConfig {
            word_count: args.words,
            separator: args.separator,
            capitalize: args.capitalize,
            include_number: args.include_number,
            word_list: None,
        };

        match generate_passphrase(&pass_cfg) {
            Ok((passphrase, pool_size)) => {
                if args.entropy {
                    let entropy = calculate_passphrase_entropy(args.words, pool_size);
                    let rating = strength_rating(entropy);
                    if args.count == 1 {
                        println!(
                            "Password:  {}\nEntropy:   {:.1} bits ({})\nPool Size: {}",
                            passphrase, entropy, rating, pool_size
                        );
                    } else {
                        println!(
                            "{:<24} [Entropy: {:.1} bits, Strength: {}]",
                            passphrase, entropy, rating
                        );
                    }
                } else {
                    println!("{}", passphrase);
                }
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                process::exit(1);
            }
        }
    } else {
        if args.length == 0 {
            eprintln!("Error: password length must be greater than 0");
            process::exit(1);
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
                args.symbols
            },
            exclude_ambiguous: args.exclude_ambiguous,
            exclude_chars: args.exclude,
        };

        match generate(&cfg) {
            Ok((password, pool_size)) => {
                if args.entropy {
                    let entropy = calculate_entropy(&password, pool_size);
                    let rating = strength_rating(entropy);
                    if args.count == 1 {
                        println!(
                            "Password:  {}\nEntropy:   {:.1} bits ({})\nPool Size: {}",
                            password, entropy, rating, pool_size
                        );
                    } else {
                        println!(
                            "{:<24} [Entropy: {:.1} bits, Strength: {}]",
                            password, entropy, rating
                        );
                    }
                } else {
                    println!("{}", password);
                }
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                process::exit(1);
            }
        }
    }
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
}
