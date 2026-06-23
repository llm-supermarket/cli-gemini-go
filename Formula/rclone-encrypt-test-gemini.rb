class RcloneEncryptTestGemini < Formula
  desc "A small CLI tool that encrypts and decrypts using the rclone encryption defaults"
  homepage "https://github.com/yetanotherchris/rclone-encrypt-test-gemini"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-gemini/releases/download/v1.0.0/rclone-encrypt-test-gemini-darwin-amd64.tar.gz"
      sha256 "be47820a8799981b2971e1269abd921b737304595b630fd50a42efdb73e2ee0c"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-gemini/releases/download/v1.0.0/rclone-encrypt-test-gemini-darwin-arm64.tar.gz"
      sha256 "fafd2d43f11bb4ab828d94d2c244add8a8b8d1085cecf1b0efb16471c4fb295e"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-gemini/releases/download/v1.0.0/rclone-encrypt-test-gemini-linux-amd64.tar.gz"
      sha256 "7778f2458691990a903534381b64b53d684ac5c638ea372ecfce887c1d5045db"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-gemini/releases/download/v1.0.0/rclone-encrypt-test-gemini-linux-arm64.tar.gz"
      sha256 "15eac0e032113937236315e2f78698f06ce77a9f53fbd2b9483e40b06379713f"
    end
  end

  def install
    bin.install "rclone-encrypt-test-gemini"
  end

  test do
    system "#{bin}/rclone-encrypt-test-gemini", "-h"
  end
end
