use base64::Engine;
use std::io::Write;
use zeroize::Zeroizing;

use crate::error::Error;

const CLIPBOARD_COMMANDS: &[(&str, &[&str])] = &[
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard"]),
    ("xsel", &["--clipboard", "--input"]),
    ("pbcopy", &[]),
    ("clip.exe", &[]),
];

/// Formats the OSC 52 sequence for the given text directly into a pre-sized [`Zeroizing<String>`].
/// If `is_tmux` is true, wraps the sequence in a tmux passthrough sequence.
fn format_osc52_sequence(text: &str, is_tmux: bool) -> Zeroizing<String> {
    let raw_bytes = text.as_bytes();
    let b64_len = raw_bytes.len().div_ceil(3) * 4;
    let (prefix, suffix) = if is_tmux {
        ("\x1bPtmux;\x1b\x1b]52;c;", "\x07\x1b\\")
    } else {
        ("\x1b]52;c;", "\x07")
    };
    let total_cap = prefix.len() + b64_len + suffix.len();
    let mut seq = Zeroizing::new(String::with_capacity(total_cap));
    seq.push_str(prefix);
    base64::engine::general_purpose::STANDARD.encode_string(raw_bytes, &mut seq);
    seq.push_str(suffix);
    seq
}

fn write_osc52_to<W: Write + ?Sized>(sink: &mut W, text: &str, is_tmux: bool) -> Result<(), Error> {
    let seq = format_osc52_sequence(text, is_tmux);
    sink.write_all(seq.as_bytes())
        .map_err(|e| Error::Clipboard(e.to_string()))?;
    sink.flush().map_err(|e| Error::Clipboard(e.to_string()))?;
    Ok(())
}

fn write_osc52_internal<W: Write>(
    text: &str,
    is_tmux: bool,
    tty_sink: Option<&mut dyn Write>,
    is_stderr_terminal: bool,
    stderr_sink: Option<&mut W>,
) -> Result<(), Error> {
    if let Some(tty) = tty_sink {
        write_osc52_to(tty, text, is_tmux)
    } else if is_stderr_terminal {
        if let Some(stderr) = stderr_sink {
            write_osc52_to(stderr, text, is_tmux)
        } else {
            let mut real_stderr = std::io::stderr();
            write_osc52_to(&mut real_stderr, text, is_tmux)
        }
    } else {
        Err(Error::Clipboard(
            "cannot write OSC 52 sequence: stderr is not a terminal and /dev/tty is unavailable"
                .to_string(),
        ))
    }
}

/// Writes the OSC 52 sequence to `/dev/tty` if available, or falls back to stderr ONLY
/// if stderr is verified to be an interactive terminal.
fn write_osc52(text: &str) -> Result<(), Error> {
    use std::io::IsTerminal;
    let is_tmux = std::env::var_os("TMUX").is_some();

    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        write_osc52_internal(
            text,
            is_tmux,
            Some(&mut tty),
            false,
            None::<&mut std::io::Stderr>,
        )
    } else {
        let is_term = std::io::stderr().is_terminal();
        write_osc52_internal(text, is_tmux, None, is_term, None::<&mut std::io::Stderr>)
    }
}

fn run_clipboard_command(cmd: &str, args: &[&str], text: &str) -> bool {
    let spawned = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    if let Ok(mut child) = spawned {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
            drop(stdin);
        }
        if let Ok(status) = child.wait() {
            return status.success();
        }
    }
    false
}

pub(crate) fn copy_to_clipboard_with(
    text: &str,
    commands: &[(&str, &[&str])],
    mut command_runner: impl FnMut(&str, &[&str], &str) -> bool,
    mut osc52_sink: impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    for (cmd, args) in commands {
        if command_runner(cmd, args, text) {
            return Ok(());
        }
    }

    // Fall back to OSC 52 only if all native tools fail
    osc52_sink(text).map_err(|_| {
        Error::Clipboard(
            "could not copy to clipboard (install xclip, wl-copy, or use an OSC 52 compatible terminal)"
                .to_string(),
        )
    })
}

/// Copies text to the system clipboard.
///
/// Tries platform-native tools in order (`wl-copy`, `xclip`, `xsel`, `pbcopy`, `clip.exe`).
/// If a native tool succeeds, returns `Ok(())` immediately.
/// Otherwise, falls back to emitting an OSC 52 escape sequence (only if connected to a terminal).
pub fn copy_to_clipboard(text: &str) -> Result<(), Error> {
    copy_to_clipboard_with(text, CLIPBOARD_COMMANDS, run_clipboard_command, write_osc52)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osc52_sequence_format() {
        let expected = "\x1b]52;c;dGVzdA==\x07";
        assert_eq!(format_osc52_sequence("test", false).as_str(), expected);
    }

    #[test]
    fn test_osc52_sequence_format_empty() {
        assert_eq!(format_osc52_sequence("", false).as_str(), "\x1b]52;c;\x07");
    }

    #[test]
    fn test_osc52_sequence_format_arbitrary_string() {
        let text = "P@ssw0rd!#%^&*()_+";
        let seq = format_osc52_sequence(text, false);
        assert!(seq.starts_with("\x1b]52;c;"));
        assert!(seq.ends_with("\x07"));
    }

    #[test]
    fn test_osc52_tmux_format() {
        let expected = "\x1bPtmux;\x1b\x1b]52;c;dGVzdA==\x07\x1b\\";
        assert_eq!(format_osc52_sequence("test", true).as_str(), expected);
    }

    #[test]
    fn test_non_terminal_stderr_never_receives_osc52() {
        let mut sink = Vec::new();
        let res = write_osc52_internal("my_secret", false, None, false, Some(&mut sink));
        assert!(res.is_err());
        assert!(
            sink.is_empty(),
            "non-terminal stderr must not receive any OSC 52 bytes"
        );
    }

    #[test]
    fn test_terminal_stderr_receives_osc52() {
        let mut sink = Vec::new();
        let res = write_osc52_internal("my_secret", false, None, true, Some(&mut sink));
        assert!(res.is_ok());
        assert_eq!(sink, format_osc52_sequence("my_secret", false).as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_command_success_exit_zero() {
        let res = copy_to_clipboard_with("secret", &[("true", &[])], run_clipboard_command, |_| {
            panic!("OSC 52 sink should not be reached when command succeeds")
        });
        assert_eq!(res, Ok(()));
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_command_exit_one_falls_through() {
        let mut sink_called = false;
        let res =
            copy_to_clipboard_with("secret", &[("false", &[])], run_clipboard_command, |_| {
                sink_called = true;
                Ok(())
            });
        assert_eq!(res, Ok(()));
        assert!(sink_called);
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_command_receives_exact_bytes_no_trailing_newline() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!(
            "rustpass_test_clipboard_{}.txt",
            std::process::id()
        ));
        let temp_str = temp_file.to_str().unwrap();

        let res = copy_to_clipboard_with(
            "exact_secret_no_newline!",
            &[("sh", &["-c", "cat > \"$0\"", temp_str])],
            run_clipboard_command,
            |_| panic!("should not reach sink"),
        );
        assert_eq!(res, Ok(()));

        let contents = std::fs::read(&temp_file).expect("temp file should exist");
        let _ = std::fs::remove_file(&temp_file);
        assert_eq!(contents, b"exact_secret_no_newline!");
    }

    #[test]
    fn test_copy_to_clipboard_does_not_panic() {
        // On CI/headless, clipboard may not be available, but function must not panic
        let result = copy_to_clipboard("test");
        let _ = result;

        let result_empty = copy_to_clipboard("");
        let _ = result_empty;

        let result_special = copy_to_clipboard("complex-p@ssw0rd!\n\t");
        let _ = result_special;
    }

    #[test]
    fn test_write_osc52_does_not_panic() {
        let result = write_osc52("test");
        let _ = result;
    }
}
