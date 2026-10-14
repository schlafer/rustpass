use rand::Rng;

pub const DEFAULT_LENGTH: usize = 12;
pub const DEFAULT_SYMBOLS: &str = "!@#$*_";
pub const AMBIGUOUS_CHARS: &str = "0O1lI|";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub length: usize,
    pub no_upper: bool,
    pub no_lower: bool,
    pub no_digits: bool,
    pub no_symbols: bool,
    pub only_alphanumeric: bool,
    pub symbols: String,
    pub exclude_ambiguous: bool,
    pub exclude_chars: String,
}

impl Default for Config {
    fn default() -> Self {
        default_config()
    }
}

pub fn default_config() -> Config {
    Config {
        length: DEFAULT_LENGTH,
        no_upper: false,
        no_lower: false,
        no_digits: false,
        no_symbols: false,
        only_alphanumeric: false,
        symbols: DEFAULT_SYMBOLS.to_string(),
        exclude_ambiguous: false,
        exclude_chars: String::new(),
    }
}

pub fn secure_random(min: usize, max: usize) -> usize {
    rand::rng().random_range(min..=max)
}

#[allow(clippy::ptr_arg)]
pub fn shuffle(chars: &mut Vec<char>) {
    let len = chars.len();
    for i in (1..len).rev() {
        let j = secure_random(0, i);
        chars.swap(i, j);
    }
}

pub fn generate(cfg: &Config) -> Result<(String, usize), String> {
    if cfg.length == 0 {
        return Err("password length must be greater than 0".to_string());
    }

    let upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lower = "abcdefghijklmnopqrstuvwxyz";
    let nums = "0123456789";
    let special = "!@#$*_";

    let groups: Vec<&str> = vec![upper, lower, nums, special];
    let pool_size = upper.len() + lower.len() + nums.len() + special.len();

    let base = cfg.length / 4;
    let remainder = cfg.length % 4;

    let mut pass: Vec<char> = Vec::with_capacity(cfg.length);

    for (g, group) in groups.iter().enumerate() {
        let mut this_len = base;
        if g < remainder {
            this_len += 1;
        }
        for _ in 0..this_len {
            let idx = secure_random(0, group.len() - 1);
            pass.push(group.chars().nth(idx).unwrap());
        }
    }

    shuffle(&mut pass);

    Ok((pass.into_iter().collect(), pool_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &str = "0123456789";
    const SPECIAL: &str = "!@#$*_";

    #[test]
    fn test_secure_random_in_range() {
        for _ in 0..100 {
            let val = secure_random(5, 10);
            assert!(val >= 5 && val <= 10);
        }
    }

    #[test]
    fn test_generate_password_correct_length() {
        for len in [1, 4, 8, 12, 16, 20, 33] {
            let cfg = Config {
                length: len,
                ..default_config()
            };
            let (pass, pool_size) = generate(&cfg).unwrap();
            assert_eq!(pass.len(), len, "length {len} failed");
            assert_eq!(pool_size, 68);
        }
    }

    #[test]
    fn test_generate_password_valid_chars() {
        let cfg = Config {
            length: 100,
            ..default_config()
        };
        let (pass, _) = generate(&cfg).unwrap();
        let all_chars: String = [UPPER, LOWER, DIGITS, SPECIAL].concat();
        for c in pass.chars() {
            assert!(all_chars.contains(c), "invalid char: {c}");
        }
    }

    #[test]
    fn test_generate_password_group_distribution() {
        let len = 100;
        let cfg = Config {
            length: len,
            ..default_config()
        };
        let (pass, _) = generate(&cfg).unwrap();
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for c in pass.chars() {
            if UPPER.contains(c) {
                *counts.entry("upper").or_insert(0) += 1;
            } else if LOWER.contains(c) {
                *counts.entry("lower").or_insert(0) += 1;
            } else if DIGITS.contains(c) {
                *counts.entry("digit").or_insert(0) += 1;
            } else if SPECIAL.contains(c) {
                *counts.entry("special").or_insert(0) += 1;
            }
        }
        // Each group should contribute 25 (100/4)
        assert_eq!(*counts.get("upper").unwrap(), 25);
        assert_eq!(*counts.get("lower").unwrap(), 25);
        assert_eq!(*counts.get("digit").unwrap(), 25);
        assert_eq!(*counts.get("special").unwrap(), 25);
    }

    #[test]
    fn test_shuffle_permutes() {
        let original: Vec<char> = "abcdefghij".chars().collect();
        let mut shuffled = original.clone();
        shuffle(&mut shuffled);
        // Very unlikely to be identical after shuffle
        assert_ne!(original, shuffled);
    }

    #[test]
    fn test_shuffle_preserves_elements() {
        let original: Vec<char> = "abcdefghij".chars().collect();
        let mut shuffled = original.clone();
        shuffle(&mut shuffled);
        let mut orig_sorted = original.clone();
        let mut shuffled_sorted = shuffled.clone();
        orig_sorted.sort();
        shuffled_sorted.sort();
        assert_eq!(orig_sorted, shuffled_sorted);
    }

    #[test]
    fn test_default_config() {
        let cfg = default_config();
        assert_eq!(cfg.length, DEFAULT_LENGTH);
        assert_eq!(cfg.symbols, DEFAULT_SYMBOLS);
        assert!(!cfg.no_upper);
        assert!(!cfg.no_lower);
        assert!(!cfg.no_digits);
        assert!(!cfg.no_symbols);
        assert!(!cfg.only_alphanumeric);
        assert!(!cfg.exclude_ambiguous);
        assert!(cfg.exclude_chars.is_empty());
    }

    #[test]
    fn test_generate_zero_length() {
        let cfg = Config {
            length: 0,
            ..default_config()
        };
        assert!(generate(&cfg).is_err());
    }
}
