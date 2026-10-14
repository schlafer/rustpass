use base64::Engine;
use std::io::Write;

const CLIPBOARD_COMMANDS: &[(&str, &[&str])] = &[
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard"]),
    ("xsel", &["--clipboard", "--input"]),
    ("pbcopy", &[]),
    ("clip.exe", &[]),
];

/// Formats the OSC 52 sequence for the given text.
/// If `is_tmux` is true, wraps the sequence in a tmux passthrough sequence.
pub(crate) fn format_osc52_sequence(text: &str, is_tmux: bool) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    if is_tmux {
        format!("\x1bPtmux;\x1b\x1b]52;c;{}\x07\x1b\\", encoded)
    } else {
        format!("\x1b]52;c;{}\x07", encoded)
    }
}

/// Writes the OSC 52 sequence to `/dev/tty` if available, or falls back to stderr.
pub(crate) fn write_osc52(text: &str) -> Result<(), String> {
    let is_tmux = std::env::var_os("TMUX").is_some();
    let seq = format_osc52_sequence(text, is_tmux);

    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        tty.write_all(seq.as_bytes()).map_err(|e| e.to_string())?;
        tty.flush().map_err(|e| e.to_string())?;
    } else {
        let mut stderr = std::io::stderr();
        stderr
            .write_all(seq.as_bytes())
            .map_err(|e| e.to_string())?;
        stderr.flush().map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Copies text to the system clipboard.
///
/// Tries platform-native tools in order (`wl-copy`, `xclip`, `xsel`, `pbcopy`, `clip.exe`).
/// Also emits an OSC 52 escape sequence so terminal emulators / SSH sessions receive it.
/// If either a native tool or OSC 52 succeeds, returns `Ok(())`.
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut tool_success = false;

    for (cmd, args) in CLIPBOARD_COMMANDS {
        let spawned = std::process::Command::new(cmd)
            .args(*args)
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
                if status.success() {
                    tool_success = true;
                    break;
                }
            }
        }
    }

    let osc_err = write_osc52(text);
    if tool_success || osc_err.is_ok() {
        Ok(())
    } else {
        Err("could not copy to clipboard (install xclip, wl-copy, or use an OSC 52 compatible terminal)".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osc52_sequence_format() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("test");
        let expected = format!("\x1b]52;c;{}\x07", encoded);
        assert_eq!(expected, "\x1b]52;c;dGVzdA==\x07");
        assert_eq!(
            format_osc52_sequence("test", false),
            "\x1b]52;c;dGVzdA==\x07"
        );
    }

    #[test]
    fn test_osc52_sequence_format_empty() {
        assert_eq!(format_osc52_sequence("", false), "\x1b]52;c;\x07");
    }

    #[test]
    fn test_osc52_sequence_format_arbitrary_string() {
        let text = "P@ssw0rd!#%^&*()_+";
        let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
        assert_eq!(
            format_osc52_sequence(text, false),
            format!("\x1b]52;c;{}\x07", encoded)
        );
    }

    #[test]
    fn test_osc52_tmux_format() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("test");
        let expected = format!("\x1bPtmux;\x1b\x1b]52;c;{}\x07\x1b\\", encoded);
        assert_eq!(expected, "\x1bPtmux;\x1b\x1b]52;c;dGVzdA==\x07\x1b\\");
        assert_eq!(
            format_osc52_sequence("test", true),
            "\x1bPtmux;\x1b\x1b]52;c;dGVzdA==\x07\x1b\\"
        );
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
