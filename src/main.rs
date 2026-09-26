use std::process;

use clap::Parser;
use rand::Rng;

#[derive(Parser)]
#[command(name = "rustpass", about = "CLI password generator")]
struct Args {
    /// Password length
    #[arg(short, long, default_value_t = 12)]
    length: usize,
}

fn secure_random(min: usize, max: usize) -> usize {
    rand::rng().random_range(min..=max)
}

fn generate_password(length: usize) -> Vec<char> {
    let upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lower = "abcdefghijklmnopqrstuvwxyz";
    let nums = "0123456789";
    let special = "!@#$*_";

    let groups: Vec<&str> = vec![upper, lower, nums, special];
    let base = length / 4;
    let remainder = length % 4;

    let mut pass: Vec<char> = Vec::with_capacity(length);

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

    pass
}

fn shuffle(chars: &mut Vec<char>) {
    let len = chars.len();
    for i in (1..len).rev() {
        let j = secure_random(0, i);
        chars.swap(i, j);
    }
}

fn main() {
    let args = Args::parse();

    if args.length == 0 {
        eprintln!("Length must be greater than 0");
        process::exit(1);
    }

    let mut password = generate_password(args.length);
    shuffle(&mut password);
    println!("{}", password.iter().collect::<String>());
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
            let pass = generate_password(len);
            assert_eq!(pass.len(), len, "length {len} failed");
        }
    }

    #[test]
    fn test_generate_password_valid_chars() {
        let pass = generate_password(100);
        let all_chars: String = [UPPER, LOWER, DIGITS, SPECIAL].concat();
        for c in &pass {
            assert!(all_chars.contains(*c), "invalid char: {c}");
        }
    }

    #[test]
    fn test_generate_password_group_distribution() {
        let len = 100;
        let pass = generate_password(len);
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for c in &pass {
            if UPPER.contains(*c) {
                *counts.entry("upper").or_insert(0) += 1;
            } else if LOWER.contains(*c) {
                *counts.entry("lower").or_insert(0) += 1;
            } else if DIGITS.contains(*c) {
                *counts.entry("digit").or_insert(0) += 1;
            } else if SPECIAL.contains(*c) {
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
}
