# rustpass

CLI password generator in Rust. Rewrite of [ezpass](https://github.com/schlafer/ezpass).

## Installation

Clone the repository:

```bash
git clone https://github.com/schlafer/rustpass
cd rustpass
```

Build the binary:

```bash
cargo build --release
```

You can now move it somewhere in your PATH (optional):

```bash
sudo cp target/release/rustpass /usr/local/bin/
```

## Usage

Generate a 12-character password:

```bash
rustpass
```

Generate a 20-character password:

```bash
rustpass --length 20
```

Example output:

```bash
Aq#8Tz3LpR_4fKm1Vb
```

## Example Integration

Use it in a shell script:

```bash
PASSWORD=$(rustpass --length 16)
echo "Generated password: $PASSWORD"
```

Or redirect it to a file:

```bash
rustpass --length 24 > mypassword.txt
```

## How It Works

- Password is built from four character groups:
  - Uppercase letters (A–Z)
  - Lowercase letters (a–z)
  - Digits (0–9)
  - Special symbols (!@#$*_)
- Each group contributes equally to the total length.
- Final password is shuffled using the Fisher–Yates algorithm.
- Random numbers are generated via the OS CSPRNG for maximum entropy.
