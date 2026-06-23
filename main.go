package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rfjakob/eme"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

var defaultSalt = []byte{
	0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
	0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1,
}

// DeriveKeys derives the data key, name key, and name tweak using scrypt
func DeriveKeys(password string, salt []byte) (dataKey []byte, nameKey []byte, nameTweak []byte, err error) {
	if len(salt) == 0 {
		salt = defaultSalt
	}
	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 80)
	if err != nil {
		return nil, nil, nil, err
	}
	return key[0:32], key[32:64], key[64:80], nil
}

func pkcs7Pad(buf []byte, blockSize int) []byte {
	padLen := blockSize - (len(buf) % blockSize)
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(buf, padText...)
}

func pkcs7Unpad(buf []byte, blockSize int) ([]byte, error) {
	if len(buf) == 0 {
		return nil, errors.New("empty buffer")
	}
	if len(buf)%blockSize != 0 {
		return nil, errors.New("buffer is not a multiple of block size")
	}
	padLen := int(buf[len(buf)-1])
	if padLen < 1 || padLen > blockSize {
		return nil, errors.New("invalid PKCS7 padding size")
	}
	for i := len(buf) - padLen; i < len(buf); i++ {
		if buf[i] != byte(padLen) {
			return nil, errors.New("invalid PKCS7 padding bytes")
		}
	}
	return buf[:len(buf)-padLen], nil
}

// EncryptFileName encrypts a filename using EME and the specified encoding
func EncryptFileName(plaintext string, encoding string, nameKey []byte, nameTweak []byte) (string, error) {
	padded := pkcs7Pad([]byte(plaintext), 16)

	block, err := aes.NewCipher(nameKey)
	if err != nil {
		return "", err
	}

	emeCipher := eme.New(block)
	encrypted := emeCipher.Encrypt(nameTweak, padded)

	switch strings.ToLower(encoding) {
	case "base32":
		encoded := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(encrypted)
		return strings.ToLower(encoded), nil
	case "base64":
		return base64.RawURLEncoding.EncodeToString(encrypted), nil
	default:
		return "", fmt.Errorf("unsupported filename encoding: %s", encoding)
	}
}

// DecryptFileName decrypts a filename using EME and the specified encoding
func DecryptFileName(encryptedName string, encoding string, nameKey []byte, nameTweak []byte) (string, error) {
	var decoded []byte
	var err error

	switch strings.ToLower(encoding) {
	case "base32":
		upper := strings.ToUpper(encryptedName)
		decoded, err = base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(upper)
		if err != nil {
			return "", fmt.Errorf("failed to decode base32hex: %w", err)
		}
	case "base64":
		decoded, err = base64.RawURLEncoding.DecodeString(encryptedName)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encryptedName)
			if err != nil {
				decoded, err = base64.StdEncoding.DecodeString(encryptedName)
				if err != nil {
					return "", fmt.Errorf("failed to decode base64: %w", err)
				}
			}
		}
	default:
		return "", fmt.Errorf("unsupported filename encoding: %s", encoding)
	}

	if len(decoded) == 0 {
		return "", errors.New("empty decoded filename")
	}
	if len(decoded)%16 != 0 {
		return "", fmt.Errorf("decoded filename length %d is not a multiple of 16", len(decoded))
	}

	block, err := aes.NewCipher(nameKey)
	if err != nil {
		return "", err
	}

	emeCipher := eme.New(block)
	decrypted := emeCipher.Decrypt(nameTweak, decoded)

	unpadded, err := pkcs7Unpad(decrypted, 16)
	if err != nil {
		return "", fmt.Errorf("failed to unpad decrypted filename: %w", err)
	}

	return string(unpadded), nil
}

func incrementNonce(nonce *[24]byte) {
	for i := 0; i < len(nonce); i++ {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// EncryptFile encrypts an input file to an output file using NACL SecretBox
func EncryptFile(inputPath, outputPath string, dataKey []byte) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = outFile.Close()
	}()

	// Write magic header
	if _, err := outFile.Write([]byte("RCLONE\x00\x00")); err != nil {
		return fmt.Errorf("failed to write magic header: %w", err)
	}

	// Generate and write random nonce
	var initialNonce [24]byte
	if _, err := rand.Read(initialNonce[:]); err != nil {
		return fmt.Errorf("failed to generate random nonce: %w", err)
	}
	if _, err := outFile.Write(initialNonce[:]); err != nil {
		return fmt.Errorf("failed to write initial nonce: %w", err)
	}

	var dataKey32 [32]byte
	copy(dataKey32[:], dataKey)

	currentNonce := initialNonce
	const maxPlainBlockSize = 65536
	buf := make([]byte, maxPlainBlockSize)

	for {
		n, err := io.ReadFull(inFile, buf)
		if n > 0 {
			encrypted := secretbox.Seal(nil, buf[:n], &currentNonce, &dataKey32)
			if _, err := outFile.Write(encrypted); err != nil {
				return fmt.Errorf("failed to write encrypted block: %w", err)
			}
			incrementNonce(&currentNonce)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// DecryptFile decrypts an input file to an output file using NACL SecretBox
func DecryptFile(inputPath, outputPath string, dataKey []byte) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	header := make([]byte, 8)
	if _, err := io.ReadFull(inFile, header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}
	if string(header) != "RCLONE\x00\x00" {
		return fmt.Errorf("invalid header magic (not a valid rclone-encrypted file)")
	}

	var initialNonce [24]byte
	if _, err := io.ReadFull(inFile, initialNonce[:]); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = outFile.Close()
	}()

	var dataKey32 [32]byte
	copy(dataKey32[:], dataKey)

	currentNonce := initialNonce
	const maxEncryptedBlockSize = 65536 + 16
	buf := make([]byte, maxEncryptedBlockSize)

	for {
		n, err := io.ReadFull(inFile, buf)
		if n > 0 {
			decrypted, ok := secretbox.Open(nil, buf[:n], &currentNonce, &dataKey32)
			if !ok {
				return errors.New("decryption failed - bad password or corrupted block")
			}
			if _, err := outFile.Write(decrypted); err != nil {
				return fmt.Errorf("failed to write decrypted data: %w", err)
			}
			incrementNonce(&currentNonce)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pBytes, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(pBytes), nil
	} else {
		// Fallback for non-interactive / scripted test environments
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
}

func printHelp() {
	helpText := `rclone-encrypt-test-gemini - A CLI tool to encrypt and decrypt using rclone defaults

Usage:
  rclone-encrypt-test-gemini [options]

Options:
  -i, --input-file <path>     Input file path (required)
  -o, --output-file <path>    Output file path (optional)
  -p, --password <string>     Insecure password flag (warns on use)
  -s, --salt <string>         Custom salt used for key derivation (optional)
  --encoding <type>           Filename encoding: base32 or base64 (default: base32)
  -d, --decrypt               Set mode to decrypt (default is encrypt)
  -e, --encrypt               Set mode to encrypt (default)
  -h, --help                  Print this help message
`
	fmt.Println(helpText)
}

func main() {
	var inputFile string
	var outputFile string
	var cliPassword string
	var cliSalt string
	encoding := "base32"
	decryptMode := false

	// Parse custom command-line arguments to support both -flag and --flag
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "-i", "--input-file":
			if i+1 < len(os.Args) {
				inputFile = os.Args[i+1]
				i++
			}
		case "-o", "--output-file":
			if i+1 < len(os.Args) {
				outputFile = os.Args[i+1]
				i++
			}
		case "-p", "--password":
			if i+1 < len(os.Args) {
				cliPassword = os.Args[i+1]
				i++
			}
		case "-s", "--salt":
			if i+1 < len(os.Args) {
				cliSalt = os.Args[i+1]
				i++
			}
		case "--encoding":
			if i+1 < len(os.Args) {
				encoding = os.Args[i+1]
				i++
			}
		case "-d", "--decrypt":
			decryptMode = true
		case "-e", "--encrypt":
			decryptMode = false
		case "-h", "--help":
			printHelp()
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "Unknown argument: %s\n", arg)
			printHelp()
			os.Exit(1)
		}
	}

	if inputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: Input file (-i, --input-file) is required.")
		printHelp()
		os.Exit(1)
	}

	encoding = strings.ToLower(encoding)
	if encoding != "base32" && encoding != "base64" {
		fmt.Fprintf(os.Stderr, "Error: Unsupported encoding %q. Must be 'base32' or 'base64'.\n", encoding)
		os.Exit(1)
	}

	// Password and Salt resolution
	var password string
	var salt []byte

	if cliPassword != "" {
		fmt.Fprintln(os.Stderr, "Warning: Entering password via --password is insecure as it may be visible in process listings or shell history.")
		fmt.Fprintln(os.Stderr, "Consider using an environment variable or interactive prompt instead.")
		fmt.Fprintln(os.Stderr, "Remember to wipe your terminal history entry to protect your password.")
		password = cliPassword
	} else if envPassword := os.Getenv("RCLONE_ENCRYPT_PASSWORD"); envPassword != "" {
		password = envPassword
	} else if envPasswordAlt := os.Getenv("RCLONE_PASSWORD"); envPasswordAlt != "" {
		password = envPasswordAlt
	} else {
		p, err := readPassword("Enter password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		password = p
		if password == "" {
			fmt.Fprintln(os.Stderr, "Error: Password cannot be empty.")
			os.Exit(1)
		}
	}

	if cliSalt != "" {
		salt = []byte(cliSalt)
	} else if envSalt := os.Getenv("RCLONE_ENCRYPT_SALT"); envSalt != "" {
		salt = []byte(envSalt)
	} else if envSaltAlt := os.Getenv("RCLONE_SALT"); envSaltAlt != "" {
		salt = []byte(envSaltAlt)
	} else if cliPassword == "" {
		s, err := readPassword("Enter optional salt (press Enter to skip): ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading salt: %v\n", err)
			os.Exit(1)
		}
		if len(s) > 0 {
			salt = []byte(s)
		}
	}

	// Derive Keys
	dataKey, nameKey, nameTweak, err := DeriveKeys(password, salt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving keys: %v\n", err)
		os.Exit(1)
	}

	dir := filepath.Dir(inputFile)
	base := filepath.Base(inputFile)

	if decryptMode {
		// Decrypt Mode
		var decryptedBase string
		if outputFile == "" {
			// Resolve output file path by decrypting the input filename itself
			decBase, err := DecryptFileName(base, encoding, nameKey, nameTweak)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decrypting filename: %v. Please specify an explicit output file using -o/--output-file.\n", err)
				os.Exit(1)
			}
			decryptedBase = decBase
			outputFile = filepath.Join(dir, decryptedBase)
		}

		err = DecryptFile(inputFile, outputFile, dataKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("File decrypted successfully to %s\n", outputFile)
	} else {
		// Encrypt Mode
		var encryptedBase string
		if outputFile == "" {
			// Resolve output file path by encrypting the input filename itself
			encBase, err := EncryptFileName(base, encoding, nameKey, nameTweak)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error encrypting filename: %v. Please specify an explicit output file using -o/--output-file.\n", err)
				os.Exit(1)
			}
			encryptedBase = encBase
			outputFile = filepath.Join(dir, encryptedBase)
		}

		err = EncryptFile(inputFile, outputFile, dataKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("File encrypted successfully to %s\n", outputFile)
	}
}
