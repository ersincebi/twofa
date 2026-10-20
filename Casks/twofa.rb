cask "twofa" do
  version "1.0.0"
  sha256 "8883c53c18283192b0d5dd4f4145d4092df7205931057375c11ab8709bc89375"

  url "https://github.com/ersincebi/twofa/releases/download/v#{version}/TwoFA.zip"
  name "TwoFA"
  desc "Menu bar TOTP authenticator"
  homepage "https://github.com/ersincebi/twofa"

  depends_on macos: ">= :ventura"

  app "TwoFA.app"

  # The app is ad-hoc signed, not notarized: clear quarantine so Gatekeeper lets it open.
  postflight do
    system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{appdir}/TwoFA.app"]
  end

  uninstall quit: "com.ersincebi.twofa"

  zap trash: "~/Library/Application Support/TwoFA"
end
