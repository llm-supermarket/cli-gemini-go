class RcloneEncryptTestGemini < Formula
  desc "A small CLI tool that encrypts and decrypts using the rclone encryption defaults"
  homepage "https://github.com/chris/rclone-encrypt-test-gemini"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/chris/rclone-encrypt-test-gemini/releases/download/v1.0.0/rclone-encrypt-test-gemini-darwin-amd64.tar.gz"
      sha256 "d3ca79d63c53bc50b3d5b0f5decf87fe1d93307cfde4d1bfde4b1bfde4b1bfde"
    else
      url "https://github.com/chris/rclone-encrypt-test-gemini/releases/download/v1.0.0/rclone-encrypt-test-gemini-darwin-arm64.tar.gz"
      sha256 "d3ca79d63c53bc50b3d5b0f5decf87fe1d93307cfde4d1bfde4b1bfde4b1bfde"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/chris/rclone-encrypt-test-gemini/releases/download/v1.0.0/rclone-encrypt-test-gemini-linux-amd64.tar.gz"
      sha256 "d3ca79d63c53bc50b3d5b0f5decf87fe1d93307cfde4d1bfde4b1bfde4b1bfde"
    else
      url "https://github.com/chris/rclone-encrypt-test-gemini/releases/download/v1.0.0/rclone-encrypt-test-gemini-linux-arm64.tar.gz"
      sha256 "d3ca79d63c53bc50b3d5b0f5decf87fe1d93307cfde4d1bfde4b1bfde4b1bfde"
    end
  end

  def install
    bin.install "rclone-encrypt-test-gemini"
  end

  test do
    system "#{bin}/rclone-encrypt-test-gemini", "-h"
  end
end
