pub mod cli;
pub mod clipboard;
pub mod entropy;
pub mod error;
pub mod generator;
pub mod passphrase;
pub mod wordlist;

pub use cli::{Args, JsonPasswordEntry, JsonResponse, OutputFormat, Preset};
pub use clipboard::copy_to_clipboard;
pub use entropy::{
    calculate_config_entropy, calculate_entropy, calculate_partitioned_entropy,
    calculate_passphrase_entropy, calculate_passphrase_entropy_with_number, estimate_pool_size,
    floor_entropy, min_length_for_entropy, shannon_entropy, strength_rating,
};
pub use error::{Error, Result};
pub use generator::{
    allocate_group_counts, build_active_groups, default_config, effective_pool_size, generate,
    secure_random, shuffle, zero_vec, Config, AMBIGUOUS_CHARS, DEFAULT_LENGTH, DEFAULT_SYMBOLS,
};
pub use passphrase::{
    generate_passphrase, PassphraseConfig, DEFAULT_PASSPHRASE_SEPARATOR,
    DEFAULT_PASSPHRASE_WORD_COUNT,
};
pub use wordlist::DEFAULT_WORDLIST;
