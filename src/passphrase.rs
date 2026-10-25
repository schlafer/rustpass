use std::collections::HashSet;
use zeroize::Zeroize;

use crate::error::Error;
use crate::generator::secure_random;
use crate::wordlist::DEFAULT_WORDLIST;

pub const DEFAULT_PASSPHRASE_WORD_COUNT: usize = 4;
pub const DEFAULT_PASSPHRASE_SEPARATOR: &str = "-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseConfig {
    pub word_count: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
    pub word_list: Option<Vec<String>>,
}

impl Default for PassphraseConfig {
    fn default() -> Self {
        Self {
            word_count: DEFAULT_PASSPHRASE_WORD_COUNT,
            separator: DEFAULT_PASSPHRASE_SEPARATOR.to_string(),
            capitalize: false,
            include_number: false,
            word_list: None,
        }
    }
}

fn capitalize_word(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => {
            let mut s = String::with_capacity(word.len());
            for upper in first.to_uppercase() {
                s.push(upper);
            }
            s.push_str(chars.as_str());
            s
        }
    }
}

pub fn generate_passphrase(cfg: &PassphraseConfig) -> Result<(String, usize), Error> {
    if cfg.word_count == 0 {
        return Err(Error::InvalidLength(
            "word count must be greater than 0".to_string(),
        ));
    }

    let cleaned_custom: Option<Vec<String>> = cfg.word_list.as_ref().map(|custom| {
        let mut seen = HashSet::new();
        custom
            .iter()
            .map(|w| w.trim().to_string())
            .filter(|w| !w.is_empty() && seen.insert(w.clone()))
            .collect()
    });

    let (wordlist_len, custom_words_ref) = match &cleaned_custom {
        Some(custom) => {
            if custom.is_empty() {
                return Err(Error::InvalidWordlist(
                    "wordlist has no valid non-empty words".to_string(),
                ));
            }
            (custom.len(), Some(custom))
        }
        None => {
            if DEFAULT_WORDLIST.is_empty() {
                return Err(Error::InvalidWordlist("wordlist is empty".to_string()));
            }
            (DEFAULT_WORDLIST.len(), None)
        }
    };

    let total_elements = cfg.word_count + if cfg.include_number { 1 } else { 0 };
    let mut selected_words = Vec::with_capacity(total_elements);
    for _ in 0..cfg.word_count {
        let idx = secure_random(0, wordlist_len - 1);
        let word_str = match custom_words_ref {
            Some(custom) => custom[idx].as_str(),
            None => DEFAULT_WORDLIST[idx],
        };
        if cfg.capitalize {
            selected_words.push(capitalize_word(word_str));
        } else {
            selected_words.push(word_str.to_string());
        }
    }

    if cfg.include_number {
        let num = secure_random(0, 99);
        selected_words.push(num.to_string());
    }

    let result = selected_words.join(&cfg.separator);

    for mut w in selected_words {
        w.zeroize();
    }

    Ok((result, wordlist_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passphrase_default() {
        let cfg = PassphraseConfig::default();
        let (pp, wl_size) = generate_passphrase(&cfg).unwrap();
        let expected_parts = 4 + pp.matches("yo-yo").count();
        assert_eq!(pp.split('-').count(), expected_parts);
        assert_eq!(wl_size, 1296);
    }

    #[test]
    fn test_passphrase_custom_words() {
        let cfg = PassphraseConfig {
            word_count: 6,
            ..Default::default()
        };
        let (pp, _) = generate_passphrase(&cfg).unwrap();
        let expected_parts = 6 + pp.matches("yo-yo").count();
        assert_eq!(pp.split('-').count(), expected_parts);
    }

    #[test]
    fn test_passphrase_custom_separator() {
        let cfg = PassphraseConfig {
            separator: ".".to_string(),
            ..Default::default()
        };
        let (pp, _) = generate_passphrase(&cfg).unwrap();
        assert_eq!(pp.split('.').count(), 4);
    }

    #[test]
    fn test_passphrase_capitalize() {
        let cfg = PassphraseConfig {
            capitalize: true,
            separator: ".".to_string(),
            ..Default::default()
        };
        let (pp, _) = generate_passphrase(&cfg).unwrap();
        for word in pp.split('.') {
            assert!(word.chars().next().unwrap().is_uppercase());
        }
    }

    #[test]
    fn test_passphrase_include_number() {
        let cfg = PassphraseConfig {
            include_number: true,
            separator: ".".to_string(),
            ..Default::default()
        };
        let (pp, _) = generate_passphrase(&cfg).unwrap();
        let parts: Vec<&str> = pp.split('.').collect();
        assert_eq!(parts.len(), 5); // 4 words + 1 number
        let num_part = parts.last().unwrap();
        assert!(num_part.parse::<u32>().is_ok());
    }

    #[test]
    fn test_passphrase_zero_words() {
        let cfg = PassphraseConfig {
            word_count: 0,
            ..Default::default()
        };
        assert!(generate_passphrase(&cfg).is_err());
    }

    #[test]
    fn test_passphrase_custom_wordlist() {
        let custom = vec![
            "apple".to_string(),
            "banana".to_string(),
            "cherry".to_string(),
        ];
        let cfg = PassphraseConfig {
            word_list: Some(custom),
            word_count: 3,
            ..Default::default()
        };
        let (pp, wl_size) = generate_passphrase(&cfg).unwrap();
        assert_eq!(wl_size, 3);
        assert_eq!(pp.split('-').count(), 3);
    }

    #[test]
    fn test_passphrase_empty_custom_wordlist() {
        let cfg = PassphraseConfig {
            word_list: Some(vec![]),
            ..Default::default()
        };
        assert!(generate_passphrase(&cfg).is_err());
    }

    #[test]
    fn test_passphrase_custom_wordlist_deduplication_and_whitespace() {
        let custom = vec![
            "apple".to_string(),
            "  apple  ".to_string(),
            "".to_string(),
            "   ".to_string(),
            "banana".to_string(),
            "banana".to_string(),
        ];
        let cfg = PassphraseConfig {
            word_list: Some(custom),
            word_count: 2,
            ..Default::default()
        };
        let (pp, wl_size) = generate_passphrase(&cfg).unwrap();
        // Only 2 unique non-empty words: "apple" and "banana"
        assert_eq!(wl_size, 2);
        let words: Vec<&str> = pp.split('-').collect();
        assert_eq!(words.len(), 2);
        for w in words {
            assert!(w == "apple" || w == "banana");
        }
    }

    #[test]
    fn test_passphrase_custom_wordlist_all_empty_errors() {
        let custom = vec!["".to_string(), "   ".to_string()];
        let cfg = PassphraseConfig {
            word_list: Some(custom),
            word_count: 2,
            ..Default::default()
        };
        let err = generate_passphrase(&cfg).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidWordlist("wordlist has no valid non-empty words".to_string())
        );
    }

    #[test]
    fn test_passphrase_include_number_range() {
        let cfg = PassphraseConfig {
            include_number: true,
            word_count: 1,
            ..Default::default()
        };
        for _ in 0..50 {
            let (pp, _) = generate_passphrase(&cfg).unwrap();
            let (words, num_str) = pp.rsplit_once('-').unwrap();
            assert!(!words.is_empty());
            let num: u32 = num_str.parse().unwrap();
            assert!(num <= 99);
        }
    }
}
