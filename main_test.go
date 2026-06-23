package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCLI_PasswordAndBase32 tests standard encryption and decryption with --password and base32 encoding (default)
func TestCLI_PasswordAndBase32(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rclone-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	plaintextFile := filepath.Join(tempDir, "test.txt")
	plaintext := []byte("Hello rclone encryption world! Bip39 words: abandon ability able about above absent absorb abstract absurd abuse")
	if err := os.WriteFile(plaintextFile, plaintext, 0644); err != nil {
		t.Fatalf("failed to write plaintext file: %v", err)
	}

	// 1. Encrypt using --password and base32
	cmd := exec.Command("go", "run", "main.go",
		"-i", plaintextFile,
		"-p", "SuperSecretPassword123",
		"--encoding", "base32",
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("encryption failed: %v\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	// Check if the warning message is printed to stderr
	if !bytes.Contains(stderr.Bytes(), []byte("Warning: Entering password via --password is insecure")) {
		t.Errorf("warning message not found on stderr: %s", stderr.String())
	}

	// Find the encrypted file. The input file name was test.txt.
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	var encryptedFile string
	for _, entry := range entries {
		if entry.Name() != "test.txt" {
			encryptedFile = filepath.Join(tempDir, entry.Name())
			break
		}
	}

	if encryptedFile == "" {
		t.Fatalf("encrypted output file not found in temp directory")
	}

	// 2. Decrypt back to plaintext
	decryptedFile := filepath.Join(tempDir, "decrypted.txt")
	cmdDec := exec.Command("go", "run", "main.go",
		"-d",
		"-i", encryptedFile,
		"-o", decryptedFile,
		"-p", "SuperSecretPassword123",
		"--encoding", "base32",
	)
	var stdoutDec bytes.Buffer
	var stderrDec bytes.Buffer
	cmdDec.Stdout = &stdoutDec
	cmdDec.Stderr = &stderrDec
	err = cmdDec.Run()
	if err != nil {
		t.Fatalf("decryption failed: %v\nStdout: %s\nStderr: %s", err, stdoutDec.String(), stderrDec.String())
	}

	// Verify decrypted contents
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decryptedContent, plaintext) {
		t.Errorf("decrypted content mismatch!\nExpected: %q\nGot:      %q", string(plaintext), string(decryptedContent))
	}
}

// TestCLI_SaltAndBase64 tests encryption/decryption using a custom salt, --password flag, and base64 filename encoding
func TestCLI_SaltAndBase64(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rclone-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	plaintextFile := filepath.Join(tempDir, "sample.txt")
	plaintext := []byte("Another test dataset with bip39 words: zebra zero zone zone")
	if err := os.WriteFile(plaintextFile, plaintext, 0644); err != nil {
		t.Fatalf("failed to write plaintext file: %v", err)
	}

	// 1. Encrypt with custom salt and base64
	cmd := exec.Command("go", "run", "main.go",
		"-i", plaintextFile,
		"-p", "AnotherSecurePassword987",
		"-s", "CustomSaltHere456",
		"--encoding", "base64",
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("encryption failed: %v\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	// Find the encrypted file. The input file name was sample.txt.
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	var encryptedFile string
	for _, entry := range entries {
		if entry.Name() != "sample.txt" {
			encryptedFile = filepath.Join(tempDir, entry.Name())
			break
		}
	}

	if encryptedFile == "" {
		t.Fatalf("encrypted output file not found in temp directory")
	}

	// 2. Decrypt back
	decryptedFile := filepath.Join(tempDir, "decrypted.txt")
	cmdDec := exec.Command("go", "run", "main.go",
		"-d",
		"-i", encryptedFile,
		"-o", decryptedFile,
		"-p", "AnotherSecurePassword987",
		"-s", "CustomSaltHere456",
		"--encoding", "base64",
	)
	var stdoutDec bytes.Buffer
	var stderrDec bytes.Buffer
	cmdDec.Stdout = &stdoutDec
	cmdDec.Stderr = &stderrDec
	err = cmdDec.Run()
	if err != nil {
		t.Fatalf("decryption failed: %v\nStdout: %s\nStderr: %s", err, stdoutDec.String(), stderrDec.String())
	}

	// Verify decrypted contents
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decryptedContent, plaintext) {
		t.Errorf("decrypted content mismatch!\nExpected: %q\nGot:      %q", string(plaintext), string(decryptedContent))
	}
}

// TestCLI_InteractivePrompts tests the scenario where the CLI prompts the user for the password and salt
func TestCLI_InteractivePrompts(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rclone-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	plaintextFile := filepath.Join(tempDir, "prompt.txt")
	plaintext := []byte("Testing secure interactive password and salt prompts!")
	if err := os.WriteFile(plaintextFile, plaintext, 0644); err != nil {
		t.Fatalf("failed to write plaintext file: %v", err)
	}

	// 1. Encrypt with interactive prompt fallback
	// We pass password and salt via Stdin
	cmd := exec.Command("go", "run", "main.go",
		"-i", plaintextFile,
	)
	var stdin bytes.Buffer
	stdin.WriteString("PromptPassword123\n")
	stdin.WriteString("PromptSalt456\n")
	cmd.Stdin = &stdin

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("encryption failed: %v\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	// Find the encrypted file. The input file name was prompt.txt.
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}

	var encryptedFile string
	for _, entry := range entries {
		if entry.Name() != "prompt.txt" {
			encryptedFile = filepath.Join(tempDir, entry.Name())
			break
		}
	}

	if encryptedFile == "" {
		t.Fatalf("encrypted output file not found in temp directory")
	}

	// 2. Decrypt using interactive prompt fallback
	decryptedFile := filepath.Join(tempDir, "decrypted.txt")
	cmdDec := exec.Command("go", "run", "main.go",
		"-d",
		"-i", encryptedFile,
		"-o", decryptedFile,
	)
	var stdinDec bytes.Buffer
	stdinDec.WriteString("PromptPassword123\n")
	stdinDec.WriteString("PromptSalt456\n")
	cmdDec.Stdin = &stdinDec

	var stdoutDec bytes.Buffer
	var stderrDec bytes.Buffer
	cmdDec.Stdout = &stdoutDec
	cmdDec.Stderr = &stderrDec
	err = cmdDec.Run()
	if err != nil {
		t.Fatalf("decryption failed: %v\nStdout: %s\nStderr: %s", err, stdoutDec.String(), stderrDec.String())
	}

	// Verify decrypted contents
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decryptedContent, plaintext) {
		t.Errorf("decrypted content mismatch!\nExpected: %q\nGot:      %q", string(plaintext), string(decryptedContent))
	}
}
