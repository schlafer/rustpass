// Entropy calculation and password strength analysis module

use std::collections::{HashMap, HashSet};

/// Calculates the theoretical keyspace entropy in bits based on length and pool size.
///
/// # Assumptions & Model
/// This formula computes `L * log2(pool_size)`, which is an **upper-bound estimate**
/// assuming that each character is independently and uniformly selected from the entire
/// effective pool.
///
/// **Note on Partitioned Generation:** When character groups are partitioned (such as
/// in `generator::generate` which guarantees representation of each enabled group by
/// dividing length across groups), the true keyspace size is strictly smaller than
/// `pool_size^L`. For instance, a 12-character password with 4 default groups (pool 68)
/// has a true keyspace entropy of ~64.4 bits rather than the simple i.i.d. estimate of ~73.0 bits.
///
/// This estimate is a useful upper bound for comparing configurations, but should not
/// be taken as an absolute guarantee of password unguessability under targeted attacks.
///
/// If password is empty or pool_size <= 1, returns 0.0.
/// If pool_size is 0, dynamically estimates the pool size from the password.
pub fn calculate_entropy(password: &str, pool_size: usize) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let pool_size = if pool_size == 0 {
        estimate_pool_size(password)
    } else {
        pool_size
    };

    if pool_size <= 1 {
        return 0.0;
    }

    password.chars().count() as f64 * (pool_size as f64).log2()
}

/// Calculates word-selection entropy for a passphrase based on word count and wordlist size.
///
/// Assumes each word is chosen uniformly and independently from a wordlist of `wordlist_size`
/// distinct words. Deterministic separators and capitalization do not add entropy.
///
/// If word_count is 0 or wordlist_size <= 1, returns 0.0.
pub fn calculate_passphrase_entropy(word_count: usize, wordlist_size: usize) -> f64 {
    calculate_passphrase_entropy_with_number(word_count, wordlist_size, false)
}

/// Calculates entropy for a passphrase, optionally accounting for a uniformly generated
/// numeric suffix (0..=99) which contributes up to `log2(100)` (~6.64) bits of entropy.
///
/// # Assumptions
/// - Words are selected uniformly and independently with replacement from `wordlist_size` unique words.
/// - If `include_number` is true, an integer in `0..=99` is uniformly and independently chosen.
/// - Deterministic capitalization and static word separators do not add entropy and are not counted.
pub fn calculate_passphrase_entropy_with_number(
    word_count: usize,
    wordlist_size: usize,
    include_number: bool,
) -> f64 {
    if word_count == 0 || wordlist_size <= 1 {
        return 0.0;
    }

    let mut bits = word_count as f64 * (wordlist_size as f64).log2();
    if include_number {
        bits += (100.0_f64).log2();
    }
    bits
}

/// Returns a human-readable strength description based on bits of entropy:
/// - `< 36.0`  -> "Very Weak"
/// - `< 60.0`  -> "Weak"
/// - `< 80.0`  -> "Fair"
/// - `< 110.0` -> "Strong"
/// - `>= 110.0` -> "Very Strong"
pub fn strength_rating(entropy: f64) -> &'static str {
    if entropy.is_nan() || entropy < 36.0 {
        "Very Weak"
    } else if entropy < 60.0 {
        "Weak"
    } else if entropy < 80.0 {
        "Fair"
    } else if entropy < 110.0 {
        "Strong"
    } else {
        "Very Strong"
    }
}

/// Calculates the Shannon information entropy (uncertainty) of a string based on character frequencies.
///
/// # Distinction from Keyspace Guessability
/// Shannon entropy measures the empirical diversity and frequency distribution of characters
/// within the *generated string itself* (in bits per character).
///
/// It is **not** a direct measure of password strength or attacker guessability:
/// a password chosen from a high-entropy random process might coincidentally have repeated
/// characters, resulting in a lower Shannon entropy, yet remain cryptographically strong
/// against brute-force search. Conversely, a deterministic pattern like "abcdefghij" has
/// high Shannon entropy despite zero cryptographic security.
///
/// Returns 0.0 for an empty string.
pub fn shannon_entropy(s: &str) -> f64 {
    let total = s.chars().count();
    if total == 0 {
        return 0.0;
    }

    let mut counts = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }

    let total_f = total as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / total_f;
        entropy -= p * p.log2();
    }

    if entropy.abs() < 1e-12 {
        0.0
    } else {
        entropy
    }
}

/// Estimates the effective character set size of a given string based on
/// character classes present:
/// - Lowercase: +26
/// - Uppercase: +26
/// - Digits: +10
/// - Special / symbols: +32 if unique count > 6, else +unique count
///
/// Returns at least 1.
pub fn estimate_pool_size(password: &str) -> usize {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;
    let mut seen_special = HashSet::new();

    for r in password.chars() {
        if r.is_ascii_lowercase() {
            has_lower = true;
        } else if r.is_ascii_uppercase() {
            has_upper = true;
        } else if r.is_ascii_digit() {
            has_digit = true;
        } else {
            has_special = true;
            seen_special.insert(r);
        }
    }

    let mut pool = 0;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_special {
        if seen_special.len() > 6 {
            pool += 32;
        } else {
            pool += seen_special.len();
        }
    }

    if pool == 0 {
        pool = 1;
    }
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy() {
        // 12 chars from pool of 68: 12 * log2(68) ≈ 73.2
        let e = calculate_entropy("aB3!aB3!aB3!", 68);
        assert!((e - 73.2).abs() < 0.5);
    }

    #[test]
    fn test_calculate_entropy_edge_cases() {
        // Empty password has 0 entropy
        assert_eq!(calculate_entropy("", 68), 0.0);
        // Pool size <= 1 has 0 entropy
        assert_eq!(calculate_entropy("abc", 1), 0.0);
        // Pool size 0 dynamically estimates pool size (lower only: 26)
        let e = calculate_entropy("abc", 0);
        assert!((e - (3.0 * (26.0_f64).log2())).abs() < 1e-6);
    }

    #[test]
    fn test_passphrase_entropy() {
        // 4 words from 1296: 4 * log2(1296) ≈ 41.36
        let e = calculate_passphrase_entropy(4, 1296);
        assert!((e - 41.36).abs() < 0.1);
    }

    #[test]
    fn test_passphrase_entropy_with_numeric_suffix() {
        // Without number: 4 * log2(1296) ≈ 41.36
        let e_no_num = calculate_passphrase_entropy_with_number(4, 1296, false);
        assert!((e_no_num - 41.36).abs() < 0.1);

        // With number: 4 * log2(1296) + log2(100) ≈ 41.36 + 6.64 = 48.00
        let e_with_num = calculate_passphrase_entropy_with_number(4, 1296, true);
        assert!((e_with_num - 48.00).abs() < 0.1);
        assert!((e_with_num - e_no_num - (100.0_f64).log2()).abs() < 1e-10);
    }

    #[test]
    fn test_passphrase_entropy_edge_cases() {
        assert_eq!(calculate_passphrase_entropy(0, 1296), 0.0);
        assert_eq!(calculate_passphrase_entropy(4, 1), 0.0);
        assert_eq!(calculate_passphrase_entropy(4, 0), 0.0);
        assert_eq!(calculate_passphrase_entropy_with_number(0, 1296, true), 0.0);
        assert_eq!(calculate_passphrase_entropy_with_number(4, 1, true), 0.0);
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
    fn test_strength_rating_boundaries() {
        assert_eq!(strength_rating(0.0), "Very Weak");
        assert_eq!(strength_rating(35.9), "Very Weak");
        assert_eq!(strength_rating(36.0), "Weak");
        assert_eq!(strength_rating(59.9), "Weak");
        assert_eq!(strength_rating(60.0), "Fair");
        assert_eq!(strength_rating(79.9), "Fair");
        assert_eq!(strength_rating(80.0), "Strong");
        assert_eq!(strength_rating(109.9), "Strong");
        assert_eq!(strength_rating(110.0), "Very Strong");
        assert_eq!(strength_rating(f64::NAN), "Very Weak");
    }

    #[test]
    fn test_shannon_entropy() {
        // All same char -> 0 entropy
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        // Two equally frequent chars -> 1.0 bit
        assert!((shannon_entropy("ab") - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_shannon_entropy_edge_cases() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("a"), 0.0);
        // 4 equally frequent characters -> 2.0 bits
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-6);
    }

    #[test]
    fn test_estimate_pool_size() {
        assert_eq!(estimate_pool_size(""), 1);
        assert_eq!(estimate_pool_size("hello"), 26);
        assert_eq!(estimate_pool_size("HELLO"), 26);
        assert_eq!(estimate_pool_size("12345"), 10);
        assert_eq!(estimate_pool_size("helloHELLO"), 52);
        assert_eq!(estimate_pool_size("helloHELLO123"), 62);
        // Small number of specials (<= 6)
        assert_eq!(estimate_pool_size("hello!"), 26 + 1);
        assert_eq!(estimate_pool_size("hello!@#"), 26 + 3);
        // Many specials (> 6)
        assert_eq!(estimate_pool_size("!@#$%^&*"), 32);
        assert_eq!(estimate_pool_size("aB3!@#$%^&*"), 26 + 26 + 10 + 32);
    }
}
