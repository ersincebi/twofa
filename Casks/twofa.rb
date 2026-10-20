cask "twofa" do
  version "1.1.0"
  sha256 "c3834464a929713e9dcfd66891adacde89e9359ef0f5f94188c8b9de8ac63485"

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
