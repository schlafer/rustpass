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
    calculate_entropy, calculate_passphrase_entropy, calculate_passphrase_entropy_with_number,
    estimate_pool_size, shannon_entropy, strength_rating,
};
pub use error::{Error, Result};
pub use generator::{
    build_active_groups, default_config, effective_pool_size, generate, secure_random, shuffle,
    zero_vec, Config, AMBIGUOUS_CHARS, DEFAULT_LENGTH, DEFAULT_SYMBOLS,
};
pub use passphrase::{
    generate_passphrase, PassphraseConfig, DEFAULT_PASSPHRASE_SEPARATOR,
    DEFAULT_PASSPHRASE_WORD_COUNT,
};
pub use wordlist::DEFAULT_WORDLIST;
