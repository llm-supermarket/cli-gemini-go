# cli-gemini-go
A small CLI tool that encrypts and decrypts using the rclone encryption defaults. 

## Features

- **Rclone-Compatible:** Implements 100% compatible file and filename encryption/decryption as used by `rclone crypt` remotes.
- **Secure Key Derivation:** Uses `scrypt` (N=16384, r=8, p=1) to derive robust keys.
- **Filename Encryption:** Supports wide-block `AES-EME` filename encryption with PKCS7 padding.
- **Content Encryption:** Uses NaCl SecretBox (`XSalsa20` + `Poly1305`) in 64 KB blocks.
- **Cross-Platform & Lightweight:** Written in pure Go with zero large framework dependencies, easily installable via Scoop and Homebrew.
- **Secure Prompts:** Prompts securely for passwords and salts without echoing keystrokes to the terminal.

## Installation

### Scoop (Windows)

To install via Scoop on Windows, add the repository as a bucket and install:

```bash
# Add the bucket (pointing directly to this GitHub repository)
scoop bucket add cli-gemini https://github.com/chris/cli-gemini.git

# Install the application
scoop install cli-gemini/cli-gemini
```

### Homebrew (macOS / Linux)

To install via Homebrew on macOS or Linux:

```bash
# Tap the repository
brew tap chris/cli-gemini https://github.com/chris/cli-gemini.git

# Install the application
brew install cli-gemini
```

## Usage

By default, the CLI will look for the password and salt in environment variables. If they are not found, it will securely prompt you in the terminal.

### 1. Interactive Prompt (Recommended)

When you don't supply a password via flag or environment variable, the tool securely prompts you:

```bash
# Encrypt a file (filename and output will be auto-derived using base32hex)
cli-gemini -i secret.txt

# Decrypt an encrypted file back to its original name
cli-gemini -d -i kr9tu4e1da4u3nifdd99g9tf5o
```

### 2. Environment Variables (Automated & Secure)

Set environment variables to authenticate securely in scripts:

```bash
export RCLONE_ENCRYPT_PASSWORD="MySuperSecurePassword"
export RCLONE_ENCRYPT_SALT="MyCustomSalt" # Optional

# Encrypt with base64 filename encoding
cli-gemini -i data.csv --encoding base64
```

### 3. Using --password Flag (Insecure)

You can pass the password directly, but the CLI will print a warning about security risks (history leakage, process listings):

```bash
# Encrypt with explicit output file
cli-gemini -i doc.pdf -o encrypted_doc.bin --password "Testpassword1"

# Decrypt using a custom salt
cli-gemini -d -i encrypted_doc.bin -o original_doc.pdf --password "Testpassword1" --salt "MyCustomSalt"
```

### Options

```text
cli-gemini - A CLI tool to encrypt and decrypt using rclone defaults

Usage:
  cli-gemini [options]

Options:
  -i, --input-file <path>     Input file path (required)
  -o, --output-file <path>    Output file path (optional)
  -p, --password <string>     Insecure password flag (warns on use)
  -s, --salt <string>         Custom salt used for key derivation (optional)
  --encoding <type>           Filename encoding: base32 or base64 (default: base32)
  -d, --decrypt               Set mode to decrypt (default is encrypt)
  -e, --encrypt               Set mode to encrypt (default)
  -h, --help                  Print this help message
```

## Development and Testing

To run the unit tests:

```bash
go test -v
```

To build a local release binary:

```bash
go build -o cli-gemini main.go
```
