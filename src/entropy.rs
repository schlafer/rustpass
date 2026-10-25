// Entropy calculation and password strength analysis module

use std::collections::{HashMap, HashSet};

use crate::error::Error;
use crate::generator::{allocate_group_counts, build_active_groups, Config};

/// Helper to compute log2(n!) = sum_{i=1}^n log2(i).
fn log2_factorial(n: usize) -> f64 {
    (1..=n).map(|i| (i as f64).log2()).sum()
}

/// Calculates the theoretical keyspace entropy in bits for the partitioned character generator.
///
/// # Mathematical Model
/// Let `k` be the number of active, non-empty disjoint character groups (`group_sizes.len()`),
/// `s_g` be the size of group `g` (`group_sizes[g]`), and `L` be the desired password `length`.
///
/// ## Case 1: `L >= k`
/// When length is at least the number of active groups, each group `g` is allocated a deterministic
/// number of characters `n_g` via [`allocate_group_counts`]:
/// - `n_g = L / k + 1` for the first `L % k` groups
/// - `n_g = L / k` for the remaining groups
///
/// Characters are selected uniformly and independently with replacement from each group, and the
/// resulting multiset of characters is shuffled uniformly at random across all `L!` permutations.
/// Because every resulting password is generated with equal probability, the entropy is exact:
///
/// ```text
/// H = log2(L! / prod(n_g!)) + sum(n_g * log2(s_g))
///   = log2(L!) - sum(log2(n_g!)) + sum(n_g * log2(s_g))
/// ```
///
/// ## Case 2: `L < k`
/// When length is strictly less than the number of active groups, the generator chooses `L` distinct
/// groups uniformly at random without replacement from the `k` available groups, draws one character
/// uniformly from each chosen group, and shuffles them.
///
/// When group sizes differ, the resulting probability distribution across generated strings is not
/// uniform. We compute the min-entropy (the negative log2 of the maximum probability, `-log2(p_max)`),
/// which provides a conservative, robust bound on guess resistance:
///
/// ```text
/// H_min = log2(k! / (k - L)!) + sum(log2(s_g) for the L smallest s_g)
/// ```
///
/// Returns `0.0` if `length == 0`, `group_sizes` is empty, or any group size is `0`.
pub fn calculate_partitioned_entropy(group_sizes: &[usize], length: usize) -> f64 {
    if length == 0 || group_sizes.is_empty() || group_sizes.contains(&0) {
        return 0.0;
    }

    let k = group_sizes.len();
    if length >= k {
        let counts = allocate_group_counts(length, k);
        let mut bits = log2_factorial(length);
        for (g, &count) in counts.iter().enumerate() {
            bits -= log2_factorial(count);
            bits += count as f64 * (group_sizes[g] as f64).log2();
        }
        bits.max(0.0)
    } else {
        // L < k: log2(k! / (k - L)!) + sum of the L smallest log2(s_g)
        let perm_bits: f64 = ((k - length + 1)..=k).map(|i| (i as f64).log2()).sum();
        let mut sorted_sizes = group_sizes.to_vec();
        sorted_sizes.sort_unstable();
        let smallest_sum: f64 = sorted_sizes[..length]
            .iter()
            .map(|&s| (s as f64).log2())
            .sum();
        (perm_bits + smallest_sum).max(0.0)
    }
}

/// Builds active character groups from a [`Config`] and calculates exact partitioned entropy.
pub fn calculate_config_entropy(cfg: &Config) -> Result<f64, Error> {
    let groups = build_active_groups(cfg)?;
    let sizes: Vec<usize> = groups.iter().map(|g| g.chars().count()).collect();
    Ok(calculate_partitioned_entropy(&sizes, cfg.length))
}

/// Finds the minimum password length required to achieve at least `target` bits of entropy
/// for the given `group_sizes`.
///
/// Uses an exponential search (doubling) to establish an upper bound, followed by binary
/// search. Returns `None` if the target is unreachable (e.g. non-finite/non-positive target,
/// empty group sizes, or a single group of size 1 where entropy is 0 for all lengths).
pub fn min_length_for_entropy(group_sizes: &[usize], target: f64) -> Option<usize> {
    if !target.is_finite() || target <= 0.0 || group_sizes.is_empty() {
        return None;
    }
    if group_sizes.len() == 1 && group_sizes[0] <= 1 {
        return None;
    }

    // Sane upper cap for length search
    const MAX_LEN: usize = 100_000;

    if calculate_partitioned_entropy(group_sizes, 1) >= target {
        return Some(1);
    }

    let mut high = 1;
    while calculate_partitioned_entropy(group_sizes, high) < target {
        let next = high.saturating_mul(2);
        if next == high || high >= MAX_LEN {
            if calculate_partitioned_entropy(group_sizes, MAX_LEN) < target {
                return None;
            }
            high = MAX_LEN;
            break;
        }

        let cur_ent = calculate_partitioned_entropy(group_sizes, high);
        let next_ent = calculate_partitioned_entropy(group_sizes, next);
        if next_ent <= cur_ent && next_ent == 0.0 {
            return None;
        }

        high = next.min(MAX_LEN);
    }

    let mut low = high / 2;
    let mut ans = high;
    while low <= high {
        let mid = low + (high - low) / 2;
        if calculate_partitioned_entropy(group_sizes, mid) >= target {
            ans = mid;
            if mid == 0 {
                break;
            }
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    Some(ans)
}

/// Floors entropy to one decimal place with a tiny epsilon (`floor(bits * 10 + 1e-9) / 10`),
/// ensuring that the displayed value never exceeds the true entropy.
pub fn floor_entropy(bits: f64) -> f64 {
    if !bits.is_finite() || bits <= 0.0 {
        0.0
    } else {
        (bits * 10.0 + 1e-9).floor() / 10.0
    }
}

/// Calculates the theoretical keyspace entropy in bits assuming independent, identically
/// distributed (i.i.d.) character selection: `L * log2(pool_size)`.
///
/// # Compatibility Note
/// This formula computes an **upper-bound estimate** assuming each character is independently
/// and uniformly drawn from the entire character pool. It does **not** model the partitioned
/// generation algorithm used by RustPass.
///
/// To calculate the exact entropy of passwords generated by RustPass, use
/// [`calculate_partitioned_entropy`] or [`calculate_config_entropy`].
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

    fn helper_permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        if items.is_empty() {
            return vec![Vec::new()];
        }
        let mut res = Vec::new();
        for i in 0..items.len() {
            let mut rest = items.to_vec();
            let elem = rest.remove(i);
            for mut p in helper_permutations(&rest) {
                p.insert(0, elem.clone());
                res.push(p);
            }
        }
        res
    }

    fn helper_cartesian_product<T: Clone>(pools: &[Vec<T>]) -> Vec<Vec<T>> {
        if pools.is_empty() {
            return vec![Vec::new()];
        }
        let mut result = vec![Vec::new()];
        for pool in pools {
            let mut next = Vec::new();
            for r in &result {
                for item in pool {
                    let mut new_r = r.clone();
                    new_r.push(item.clone());
                    next.push(new_r);
                }
            }
            result = next;
        }
        result
    }

    fn helper_combinations_indices(n: usize, k: usize) -> Vec<Vec<usize>> {
        if k == 0 {
            return vec![Vec::new()];
        }
        if n < k {
            return Vec::new();
        }
        let mut res = Vec::new();
        fn recurse(
            start: usize,
            n: usize,
            k: usize,
            current: &mut Vec<usize>,
            res: &mut Vec<Vec<usize>>,
        ) {
            if current.len() == k {
                res.push(current.clone());
                return;
            }
            for i in start..n {
                current.push(i);
                recurse(i + 1, n, k, current, res);
                current.pop();
            }
        }
        recurse(0, n, k, &mut Vec::new(), &mut res);
        res
    }

    fn enumerate_distribution(groups: &[&str], length: usize) -> HashMap<String, f64> {
        let k = groups.len();
        let mut dist = HashMap::new();

        if length >= k {
            let counts = allocate_group_counts(length, k);
            let mut group_choices = Vec::new();
            for (g, &count) in counts.iter().enumerate() {
                let chars: Vec<char> = groups[g].chars().collect();
                let mut single_group_pools = Vec::new();
                for _ in 0..count {
                    single_group_pools.push(chars.clone());
                }
                let draws = helper_cartesian_product(&single_group_pools);
                group_choices.push(draws);
            }
            let all_selections = helper_cartesian_product(&group_choices);
            for selection in all_selections {
                let mut flat_chars = Vec::new();
                let mut draw_prob = 1.0;
                for (g, draws) in selection.iter().enumerate() {
                    for &c in draws {
                        flat_chars.push(c);
                        draw_prob /= groups[g].len() as f64;
                    }
                }
                let perms = helper_permutations(&flat_chars);
                let perm_prob = draw_prob / perms.len() as f64;
                for p in perms {
                    let s: String = p.into_iter().collect();
                    *dist.entry(s).or_insert(0.0) += perm_prob;
                }
            }
        } else {
            let comb_indices = helper_combinations_indices(k, length);
            let prob_comb = 1.0 / comb_indices.len() as f64;
            for subset in comb_indices {
                let mut pools = Vec::new();
                let mut draw_prob = prob_comb;
                for &g in &subset {
                    let chars: Vec<char> = groups[g].chars().collect();
                    draw_prob /= chars.len() as f64;
                    pools.push(chars);
                }
                let draws = helper_cartesian_product(&pools);
                for d in draws {
                    let perms = helper_permutations(&d);
                    let perm_prob = draw_prob / perms.len() as f64;
                    for p in perms {
                        let s: String = p.into_iter().collect();
                        *dist.entry(s).or_insert(0.0) += perm_prob;
                    }
                }
            }
        }
        dist
    }

    #[test]
    fn test_partitioned_entropy_exhaustive_enumeration_two_groups() {
        let groups = ["ab", "c"];
        let sizes = [2, 1];

        // L < k: L = 1
        let dist1 = enumerate_distribution(&groups, 1);
        let p_max1 = dist1.values().cloned().fold(0.0, f64::max);
        let min_ent1 = -p_max1.log2();
        let formula1 = calculate_partitioned_entropy(&sizes, 1);
        assert!((formula1 - min_ent1).abs() < 1e-10);

        // L == k: L = 2
        let dist2 = enumerate_distribution(&groups, 2);
        let h2: f64 = dist2.values().map(|&p| -p * p.log2()).sum();
        let formula2 = calculate_partitioned_entropy(&sizes, 2);
        assert!((formula2 - h2).abs() < 1e-10);

        // L > k: L = 3
        let dist3 = enumerate_distribution(&groups, 3);
        let h3: f64 = dist3.values().map(|&p| -p * p.log2()).sum();
        let formula3 = calculate_partitioned_entropy(&sizes, 3);
        assert!((formula3 - h3).abs() < 1e-10);
    }

    #[test]
    fn test_partitioned_entropy_exhaustive_enumeration_three_groups_non_uniform() {
        let groups = ["a", "bc", "d"];
        let sizes = [1, 2, 1];

        // L < k: L = 1
        let dist1 = enumerate_distribution(&groups, 1);
        let p_max1 = dist1.values().cloned().fold(0.0, f64::max);
        let min_ent1 = -p_max1.log2();
        let formula1 = calculate_partitioned_entropy(&sizes, 1);
        assert!((formula1 - min_ent1).abs() < 1e-10);

        // L < k: L = 2 (non-uniform subset probabilities: {a, bc} vs {a, d})
        let dist2 = enumerate_distribution(&groups, 2);
        let p_max2 = dist2.values().cloned().fold(0.0, f64::max);
        let min_ent2 = -p_max2.log2();
        let formula2 = calculate_partitioned_entropy(&sizes, 2);
        assert!((formula2 - min_ent2).abs() < 1e-10);

        // L == k: L = 3
        let dist3 = enumerate_distribution(&groups, 3);
        let h3: f64 = dist3.values().map(|&p| -p * p.log2()).sum();
        let formula3 = calculate_partitioned_entropy(&sizes, 3);
        assert!((formula3 - h3).abs() < 1e-10);

        // L > k: L = 4
        let dist4 = enumerate_distribution(&groups, 4);
        let h4: f64 = dist4.values().map(|&p| -p * p.log2()).sum();
        let formula4 = calculate_partitioned_entropy(&sizes, 4);
        assert!((formula4 - h4).abs() < 1e-10);
    }

    #[test]
    fn test_partitioned_entropy_default_config_known_lengths() {
        let default_sizes = [26, 26, 10, 6];

        // Length 1 (L < 4): log2(4!/3!) + log2(6) = 2.0 + 2.5849625 ≈ 4.58496
        let e1 = calculate_partitioned_entropy(&default_sizes, 1);
        assert!((e1 - 4.5849625).abs() < 1e-4);

        // Length 2 (L < 4): log2(4!/2!) + log2(6) + log2(10) ≈ 3.5849625 + 5.90689 ≈ 9.49185
        let e2 = calculate_partitioned_entropy(&default_sizes, 2);
        assert!((e2 - 9.491853).abs() < 1e-4);

        // Length 3 (L < 4): log2(4!/1!) + log2(6) + log2(10) + log2(26) ≈ 15.19229
        let e3 = calculate_partitioned_entropy(&default_sizes, 3);
        assert!((e3 - 15.192297).abs() < 1e-4);

        // Length 4 (L >= 4): log2(4!/1!) + 2*log2(26) + log2(10) + log2(6) ≈ 19.89274
        let e4 = calculate_partitioned_entropy(&default_sizes, 4);
        assert!((e4 - 19.892741).abs() < 1e-4);

        // Length 12: ~64.41888
        let e12 = calculate_partitioned_entropy(&default_sizes, 12);
        assert!((e12 - 64.41888).abs() < 1e-3);

        // Length 16: ~87.14144
        let e16 = calculate_partitioned_entropy(&default_sizes, 16);
        assert!((e16 - 87.14144).abs() < 1e-3);

        // Length 20: ~109.98922 (about 109.99 bits)
        let e20 = calculate_partitioned_entropy(&default_sizes, 20);
        assert!((e20 - 109.98922).abs() < 1e-3);
    }

    #[test]
    fn test_partitioned_entropy_custom_configs() {
        use crate::generator::default_config;

        let configs = [
            Config {
                no_symbols: true,
                ..default_config()
            },
            Config {
                only_alphanumeric: true,
                ..default_config()
            },
            Config {
                no_upper: true,
                ..default_config()
            },
            Config {
                no_lower: true,
                ..default_config()
            },
            Config {
                no_digits: true,
                ..default_config()
            },
            Config {
                exclude_ambiguous: true,
                ..default_config()
            },
            Config {
                symbols: "!@#".to_string(),
                ..default_config()
            },
            Config {
                symbols: "aA1!".to_string(),
                ..default_config()
            },
            Config {
                exclude_chars: "abc".to_string(),
                ..default_config()
            },
        ];

        for cfg in &configs {
            let ent = calculate_config_entropy(cfg).expect("valid config must compute entropy");
            assert!(ent > 0.0);
        }
    }

    #[test]
    fn test_partitioned_entropy_monotonicity() {
        use crate::generator::default_config;

        let base_configs = [
            default_config(),
            Config {
                no_symbols: true,
                ..default_config()
            },
            Config {
                only_alphanumeric: true,
                ..default_config()
            },
            Config {
                exclude_ambiguous: true,
                ..default_config()
            },
            Config {
                symbols: "!@#$%^&*".to_string(),
                ..default_config()
            },
        ];

        for base in &base_configs {
            let mut prev_entropy = 0.0;
            for len in 1..=200 {
                let mut cfg = base.clone();
                cfg.length = len;
                let ent = calculate_config_entropy(&cfg).unwrap();
                assert!(
                    ent >= prev_entropy - 1e-12,
                    "entropy must be monotonic in length: len {} has {} < prev {}",
                    len,
                    ent,
                    prev_entropy
                );
                prev_entropy = ent;
            }
        }
    }

    #[test]
    fn test_min_length_for_entropy() {
        let default_sizes = [26, 26, 10, 6];

        // 100 bits requires 18 chars on default config
        let len100 = min_length_for_entropy(&default_sizes, 100.0).unwrap();
        assert_eq!(len100, 18);
        assert!(calculate_partitioned_entropy(&default_sizes, 18) >= 100.0);
        assert!(calculate_partitioned_entropy(&default_sizes, 17) < 100.0);

        // 50 bits requires 10 chars
        let len50 = min_length_for_entropy(&default_sizes, 50.0).unwrap();
        assert_eq!(len50, 10);
        assert!(calculate_partitioned_entropy(&default_sizes, 10) >= 50.0);
        assert!(calculate_partitioned_entropy(&default_sizes, 9) < 50.0);

        // Unreachable targets
        assert_eq!(min_length_for_entropy(&[1], 10.0), None);
        assert_eq!(min_length_for_entropy(&[1], 0.1), None);
        assert_eq!(min_length_for_entropy(&[], 50.0), None);
        assert_eq!(min_length_for_entropy(&default_sizes, f64::NAN), None);
        assert_eq!(min_length_for_entropy(&default_sizes, 0.0), None);
        assert_eq!(min_length_for_entropy(&default_sizes, -5.0), None);
    }

    #[test]
    fn test_floor_entropy_and_boundary_rating() {
        // 109.99 floors to 109.9 and rates "Strong"
        let floored_strong = floor_entropy(109.99);
        assert_eq!(floored_strong, 109.9);
        assert_eq!(strength_rating(floored_strong), "Strong");

        // 110.00 floors to 110.0 and rates "Very Strong"
        let floored_vstrong = floor_entropy(110.00);
        assert_eq!(floored_vstrong, 110.0);
        assert_eq!(strength_rating(floored_vstrong), "Very Strong");

        // 41.3594 floors to 41.3
        assert_eq!(floor_entropy(41.3594), 41.3);

        // Non-finite values
        assert_eq!(floor_entropy(f64::NAN), 0.0);
        assert_eq!(floor_entropy(-10.0), 0.0);
    }
}
