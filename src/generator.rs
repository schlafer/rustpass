use rand::Rng;
use zeroize::Zeroize;

use crate::error::Error;

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

/// Allocates character counts across active groups for partitioned generation.
///
/// For `length >= num_groups`, each group receives `length / num_groups` characters,
/// and the first `length % num_groups` groups (in deterministic order: upper, lower,
/// digits, symbols) receive one additional character.
pub fn allocate_group_counts(length: usize, num_groups: usize) -> Vec<usize> {
    if num_groups == 0 {
        return Vec::new();
    }
    let base = length / num_groups;
    let remainder = length % num_groups;
    (0..num_groups)
        .map(|g| if g < remainder { base + 1 } else { base })
        .collect()
}

/// Generates a cryptographically secure random integer in the inclusive range `[min, max]`.
///
/// If `min >= max`, returns `min` without panicking.
pub fn secure_random(min: usize, max: usize) -> usize {
    if min >= max {
        return min;
    }
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

/// Zeroizes the contents of a character buffer using the [`zeroize`] crate, then clears the vector.
#[allow(clippy::ptr_arg)]
pub fn zero_vec(v: &mut Vec<char>) {
    v.as_mut_slice().zeroize();
    v.clear();
}

fn rand_perm(n: usize, k: usize) -> Vec<usize> {
    assert!(k <= n, "cannot select {} distinct elements from {}", k, n);
    let mut pool: Vec<usize> = (0..n).collect();
    for i in 0..k {
        let j = secure_random(i, n - 1);
        pool.swap(i, j);
    }
    pool.truncate(k);
    pool
}

/// Filters a character group by excluding ambiguous characters and specific excluded characters.
/// Guarantees that the returned string contains only unique characters (deduplicated).
fn filter_group(charset: &str, exclude_ambiguous: bool, exclude_chars: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    charset
        .chars()
        .filter(|&c| {
            seen.insert(c)
                && (!exclude_ambiguous || !AMBIGUOUS_CHARS.contains(c))
                && !exclude_chars.contains(c)
        })
        .collect()
}

/// Builds the active, deduplicated, disjoint character groups for a given configuration.
pub fn build_active_groups(cfg: &Config) -> Result<Vec<String>, Error> {
    if cfg.only_alphanumeric && !cfg.symbols.is_empty() && cfg.symbols != DEFAULT_SYMBOLS {
        return Err(Error::ConflictingOptions(
            "cannot specify custom symbols when only-alphanumeric is enabled".to_string(),
        ));
    }

    if cfg.no_symbols && !cfg.symbols.is_empty() && cfg.symbols != DEFAULT_SYMBOLS {
        return Err(Error::ConflictingOptions(
            "cannot specify custom symbols when no-symbols is enabled".to_string(),
        ));
    }

    let upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lower = "abcdefghijklmnopqrstuvwxyz";
    let digits = "0123456789";
    let symbols = if cfg.symbols.is_empty() {
        DEFAULT_SYMBOLS
    } else {
        &cfg.symbols
    };

    let mut active_groups: Vec<String> = Vec::new();
    let mut all_seen = std::collections::HashSet::new();

    if !cfg.no_upper {
        let filtered = filter_group(upper, cfg.exclude_ambiguous, &cfg.exclude_chars);
        for c in filtered.chars() {
            all_seen.insert(c);
        }
        if !filtered.is_empty() {
            active_groups.push(filtered);
        }
    }

    if !cfg.no_lower {
        let filtered = filter_group(lower, cfg.exclude_ambiguous, &cfg.exclude_chars);
        for c in filtered.chars() {
            all_seen.insert(c);
        }
        if !filtered.is_empty() {
            active_groups.push(filtered);
        }
    }

    if !cfg.no_digits {
        let filtered = filter_group(digits, cfg.exclude_ambiguous, &cfg.exclude_chars);
        for c in filtered.chars() {
            all_seen.insert(c);
        }
        if !filtered.is_empty() {
            active_groups.push(filtered);
        }
    }

    if !cfg.no_symbols && !cfg.only_alphanumeric {
        let filtered = filter_group(symbols, cfg.exclude_ambiguous, &cfg.exclude_chars);
        // Exclude any characters already present in previously active groups to maintain disjoint groups
        let unique_symbols: String = filtered.chars().filter(|c| all_seen.insert(*c)).collect();
        if !unique_symbols.is_empty() {
            active_groups.push(unique_symbols);
        }
    }

    if active_groups.is_empty() {
        return Err(Error::EmptyPool(
            "character pool is empty; verify your inclusion and exclusion options".to_string(),
        ));
    }

    Ok(active_groups)
}

/// Returns the effective pool size (total distinct available characters) for a given configuration.
pub fn effective_pool_size(cfg: &Config) -> Result<usize, Error> {
    let groups = build_active_groups(cfg)?;
    Ok(groups.iter().map(|g| g.chars().count()).sum())
}

pub fn generate(cfg: &Config) -> Result<(String, usize), Error> {
    if cfg.length == 0 {
        return Err(Error::InvalidLength(
            "password length must be greater than 0".to_string(),
        ));
    }

    let active_groups = build_active_groups(cfg)?;
    let pool_size: usize = active_groups.iter().map(|g| g.chars().count()).sum();

    let num_groups = active_groups.len();
    let mut pass: Vec<char> = Vec::with_capacity(cfg.length);

    if cfg.length >= num_groups {
        let counts = allocate_group_counts(cfg.length, num_groups);

        for (g, group) in active_groups.iter().enumerate() {
            let this_len = counts[g];
            let group_chars: Vec<char> = group.chars().collect();
            for _ in 0..this_len {
                let idx = secure_random(0, group_chars.len() - 1);
                pass.push(group_chars[idx]);
            }
        }
    } else {
        // When length < num_groups, select `length` distinct groups at random without replacement
        // and pick one character from each, guaranteeing diverse group representation.
        let selected_indices = rand_perm(num_groups, cfg.length);
        for g in selected_indices {
            let group_chars: Vec<char> = active_groups[g].chars().collect();
            let idx = secure_random(0, group_chars.len() - 1);
            pass.push(group_chars[idx]);
        }
    }

    shuffle(&mut pass);

    let total_len: usize = pass.iter().map(|c| c.len_utf8()).sum();
    let mut result = String::with_capacity(total_len);
    for &c in &pass {
        result.push(c);
    }
    zero_vec(&mut pass);
    Ok((result, pool_size))
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
            assert!((5..=10).contains(&val));
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

    #[test]
    fn test_generate_no_symbols() {
        let cfg = Config {
            no_symbols: true,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert!(pw.chars().all(|c| !"!@#$*_".contains(c)));
    }

    #[test]
    fn test_generate_no_upper() {
        let cfg = Config {
            no_upper: true,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert!(pw.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_generate_no_lower() {
        let cfg = Config {
            no_lower: true,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert!(pw.chars().all(|c| !c.is_ascii_lowercase()));
    }

    #[test]
    fn test_generate_no_digits() {
        let cfg = Config {
            no_digits: true,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert!(pw.chars().all(|c| !c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_only_alphanumeric() {
        let cfg = Config {
            only_alphanumeric: true,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_exclude_ambiguous() {
        let cfg = Config {
            exclude_ambiguous: true,
            length: 100,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert!(pw.chars().all(|c| !"0O1lI|".contains(c)));
    }

    #[test]
    fn test_generate_exclude_chars() {
        let cfg = Config {
            exclude_chars: "abc".to_string(),
            length: 100,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert!(pw.chars().all(|c| !"abc".contains(c)));
    }

    #[test]
    fn test_generate_custom_symbols() {
        let cfg = Config {
            symbols: "^&".to_string(),
            length: 100,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        let sym_chars: Vec<char> = pw.chars().filter(|c| !c.is_ascii_alphanumeric()).collect();
        assert!(sym_chars.iter().all(|c| "^&".contains(*c)));
    }

    #[test]
    fn test_generate_empty_pool() {
        let cfg = Config {
            no_upper: true,
            no_lower: true,
            no_digits: true,
            no_symbols: true,
            ..default_config()
        };
        assert!(generate(&cfg).is_err());
    }

    #[test]
    fn test_generate_exclusion_empties_pool() {
        let cfg = Config {
            no_upper: true,
            no_lower: true,
            no_symbols: true,
            exclude_chars: "0123456789".to_string(),
            ..default_config()
        };
        let err = generate(&cfg).unwrap_err();
        assert_eq!(
            err,
            Error::EmptyPool(
                "character pool is empty; verify your inclusion and exclusion options".to_string()
            )
        );
    }

    #[test]
    fn test_filter_group() {
        assert_eq!(filter_group("abc", false, ""), "abc");
        assert_eq!(filter_group("abc", false, "b"), "ac");
        assert_eq!(filter_group("0O1lI|a", true, ""), "a");
        assert_eq!(filter_group("0O1lI|abc", true, "a"), "bc");
        assert_eq!(filter_group("abc", false, "abc"), "");
    }

    #[test]
    fn test_generate_length_1() {
        let cfg = Config {
            length: 1,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert_eq!(pw.len(), 1);
    }

    #[test]
    fn test_generate_length_2() {
        let cfg = Config {
            length: 2,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert_eq!(pw.len(), 2);
    }

    #[test]
    fn test_generate_length_3() {
        let cfg = Config {
            length: 3,
            ..default_config()
        };
        let (pw, _) = generate(&cfg).unwrap();
        assert_eq!(pw.len(), 3);
        // Characters should come from 3 distinct groups
        let mut distinct_groups = std::collections::HashSet::new();
        for c in pw.chars() {
            if UPPER.contains(c) {
                distinct_groups.insert("upper");
            } else if LOWER.contains(c) {
                distinct_groups.insert("lower");
            } else if DIGITS.contains(c) {
                distinct_groups.insert("digit");
            } else if SPECIAL.contains(c) {
                distinct_groups.insert("special");
            }
        }
        assert_eq!(
            distinct_groups.len(),
            3,
            "Characters should come from 3 distinct groups"
        );
    }

    #[test]
    fn test_generate_small_length_distribution() {
        let cfg = Config {
            length: 1,
            ..default_config()
        };
        let mut saw_upper = false;
        let mut saw_lower = false;
        let mut saw_digit = false;
        let mut saw_symbol = false;

        for _ in 0..200 {
            let (pw, _) = generate(&cfg).unwrap();
            let c = pw.chars().next().unwrap();
            if UPPER.contains(c) {
                saw_upper = true;
            } else if LOWER.contains(c) {
                saw_lower = true;
            } else if DIGITS.contains(c) {
                saw_digit = true;
            } else if SPECIAL.contains(c) {
                saw_symbol = true;
            }
        }

        assert!(
            saw_upper && saw_lower && saw_digit && saw_symbol,
            "All groups should be represented across length-1 generations (upper={}, lower={}, digit={}, symbol={})",
            saw_upper, saw_lower, saw_digit, saw_symbol
        );
    }

    #[test]
    fn test_rand_perm_distinct_and_bounds() {
        for _ in 0..100 {
            let perm = rand_perm(10, 5);
            assert_eq!(perm.len(), 5);
            let mut set = std::collections::HashSet::new();
            for &idx in &perm {
                assert!(idx < 10);
                assert!(set.insert(idx), "indices should be distinct");
            }
        }
    }

    #[test]
    fn test_rand_perm_edge_cases() {
        assert_eq!(rand_perm(0, 0), Vec::<usize>::new());
        assert_eq!(rand_perm(5, 0), Vec::<usize>::new());

        let perm = rand_perm(4, 4);
        assert_eq!(perm.len(), 4);
        let mut sorted = perm;
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "cannot select 5 distinct elements from 4")]
    fn test_rand_perm_k_greater_than_n() {
        rand_perm(4, 5);
    }

    #[test]
    fn test_rand_perm_coverage() {
        let mut counts = [0usize; 4];
        for _ in 0..200 {
            let perm = rand_perm(4, 2);
            for idx in perm {
                counts[idx] += 1;
            }
        }
        for (i, count) in counts.iter().enumerate() {
            assert!(*count > 0, "element {i} should be picked");
        }
    }

    #[test]
    fn test_secure_random_boundary_safe() {
        assert_eq!(secure_random(5, 5), 5);
        assert_eq!(secure_random(10, 5), 10);
    }

    #[test]
    fn test_filter_group_deduplication() {
        assert_eq!(filter_group("aabbcc!!", false, ""), "abc!");
        assert_eq!(filter_group("!@@##$$", false, ""), "!@#$");
    }

    #[test]
    fn test_generate_custom_symbols_deduplicated() {
        let cfg = Config {
            symbols: "!!@@##".to_string(),
            length: 12,
            ..default_config()
        };
        let (pw, pool_size) = generate(&cfg).unwrap();
        assert_eq!(pw.len(), 12);
        // Upper(26) + Lower(26) + Digits(10) + Symbols(3 unique: !, @, #) = 65
        assert_eq!(pool_size, 65);
    }

    #[test]
    fn test_generate_custom_symbols_overlapping_classes() {
        let cfg = Config {
            symbols: "aA1!".to_string(),
            length: 12,
            ..default_config()
        };
        let (pw, pool_size) = generate(&cfg).unwrap();
        assert_eq!(pw.len(), 12);
        // 'a', 'A', '1' are already in lower, upper, digits groups. Only '!' remains in symbols.
        // Upper(26) + Lower(26) + Digits(10) + Symbols(1: !) = 63
        assert_eq!(pool_size, 63);
    }

    #[test]
    fn test_generate_conflicting_symbols_with_only_alphanumeric() {
        let cfg = Config {
            only_alphanumeric: true,
            symbols: "!@#".to_string(),
            ..default_config()
        };
        let err = generate(&cfg).unwrap_err();
        assert_eq!(
            err,
            Error::ConflictingOptions(
                "cannot specify custom symbols when only-alphanumeric is enabled".to_string()
            )
        );
    }

    #[test]
    fn test_generate_conflicting_symbols_with_no_symbols() {
        let cfg = Config {
            no_symbols: true,
            symbols: "!@#".to_string(),
            ..default_config()
        };
        let err = generate(&cfg).unwrap_err();
        assert_eq!(
            err,
            Error::ConflictingOptions(
                "cannot specify custom symbols when no-symbols is enabled".to_string()
            )
        );
    }

    #[test]
    fn test_generate_length_smaller_than_active_groups_distinct() {
        // With 4 groups active and length 2:
        for _ in 0..50 {
            let cfg = Config {
                length: 2,
                ..default_config()
            };
            let (pw, pool_size) = generate(&cfg).unwrap();
            assert_eq!(pw.len(), 2);
            assert_eq!(pool_size, 68);

            let mut groups = std::collections::HashSet::new();
            for c in pw.chars() {
                if UPPER.contains(c) {
                    groups.insert("upper");
                } else if LOWER.contains(c) {
                    groups.insert("lower");
                } else if DIGITS.contains(c) {
                    groups.insert("digits");
                } else if SPECIAL.contains(c) {
                    groups.insert("special");
                }
            }
            assert_eq!(
                groups.len(),
                2,
                "Both characters must come from distinct groups"
            );
        }
    }

    #[test]
    fn test_zero_vec() {
        let mut v = vec!['a', 'B', '3', '!'];
        zero_vec(&mut v);
        assert!(v.is_empty());

        let mut empty: Vec<char> = Vec::new();
        zero_vec(&mut empty);
        assert!(empty.is_empty());
    }
}
