use rustpass::{
    calculate_entropy, calculate_passphrase_entropy_with_number, generate, generate_passphrase,
    shannon_entropy, strength_rating, Config, Error, PassphraseConfig,
};

#[test]
fn test_library_standard_password_generation() {
    let cfg = Config {
        length: 24,
        exclude_ambiguous: true,
        ..Config::default()
    };

    let (password, pool_size) = generate(&cfg).expect("password generation should succeed");
    assert_eq!(password.len(), 24);
    assert!(pool_size > 0);

    let entropy = calculate_entropy(&password, pool_size);
    let rating = strength_rating(entropy);
    assert!(entropy > 100.0);
    assert_eq!(rating, "Very Strong");

    let shannon = shannon_entropy(&password);
    assert!(shannon > 3.0);
}

#[test]
fn test_library_passphrase_generation() {
    let pass_cfg = PassphraseConfig {
        word_count: 5,
        separator: ".".to_string(),
        capitalize: true,
        include_number: true,
        word_list: None,
    };

    let (passphrase, pool_size) =
        generate_passphrase(&pass_cfg).expect("passphrase generation should succeed");
    let parts: Vec<&str> = passphrase.split('.').collect();
    assert_eq!(parts.len(), 6); // 5 words + 1 number

    for word in &parts[..5] {
        assert!(word.chars().next().unwrap().is_uppercase());
    }

    let entropy = calculate_passphrase_entropy_with_number(5, pool_size, true);
    assert!(entropy > 55.0);
}

#[test]
fn test_library_typed_errors_handled_by_downstream_caller() {
    // 1. Invalid Length
    let cfg_zero = Config {
        length: 0,
        ..Config::default()
    };
    match generate(&cfg_zero) {
        Err(Error::InvalidLength(msg)) => {
            assert!(msg.contains("greater than 0"));
        }
        other => panic!("Expected Error::InvalidLength, got {:?}", other),
    }

    // 2. Conflicting Options
    let cfg_conflict = Config {
        only_alphanumeric: true,
        symbols: "!@#".to_string(),
        ..Config::default()
    };
    match generate(&cfg_conflict) {
        Err(Error::ConflictingOptions(msg)) => {
            assert!(msg.contains("only-alphanumeric"));
        }
        other => panic!("Expected Error::ConflictingOptions, got {:?}", other),
    }

    // 3. Empty Pool
    let cfg_empty = Config {
        no_upper: true,
        no_lower: true,
        no_digits: true,
        no_symbols: true,
        ..Config::default()
    };
    match generate(&cfg_empty) {
        Err(Error::EmptyPool(msg)) => {
            assert!(msg.contains("character pool is empty"));
        }
        other => panic!("Expected Error::EmptyPool, got {:?}", other),
    }

    // 4. Invalid Wordlist
    let pass_cfg_empty = PassphraseConfig {
        word_count: 4,
        word_list: Some(vec!["".to_string(), "   ".to_string()]),
        ..PassphraseConfig::default()
    };
    match generate_passphrase(&pass_cfg_empty) {
        Err(Error::InvalidWordlist(msg)) => {
            assert!(msg.contains("no valid non-empty words"));
        }
        other => panic!("Expected Error::InvalidWordlist, got {:?}", other),
    }
}
