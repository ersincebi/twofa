# TwoFA

A tiny macOS menu bar app for TOTP two-factor codes. Click a code to copy it.

- Works with any service that shows a TOTP QR code or secret (GitHub, Google, AWS, …)
- Add accounts by pasting a secret, an `otpauth://` link or a QR code screenshot, or by opening a QR image
- Secrets are stored in your login Keychain
- Optional sync with the phone/web app: one end-to-end encrypted vault at 2fa.ersincebi.com (**⋯ → Connect to Sync…**)
- Backup / restore as plain `otpauth://` links (one per line), compatible with most authenticator apps
- SHA1 / SHA256 / SHA512, 6–8 digits, 15/30/60 s periods
- Universal binary, macOS 13+

## Install

```sh
brew tap ersincebi/twofa https://github.com/ersincebi/twofa
brew trust ersincebi/twofa
brew install --cask twofa
```

Update with `brew upgrade --cask twofa`.

Or download `TwoFA.zip` from [Releases](https://github.com/ersincebi/twofa/releases), unzip it into
`/Applications`, and since the app isn't notarized, run once:

```sh
xattr -dr com.apple.quarantine /Applications/TwoFA.app
```

## Notes

- **Keychain prompt after updates.** The app is ad-hoc signed, so macOS treats each new version as a
  new app and asks once whether TwoFA may access its keychain item. Choose **Always Allow**.
- **Backups are unencrypted.** The exported file contains your secrets in plain text — store it
  somewhere safe (e.g. an encrypted disk image or password manager).

## Development

```sh
swift test          # needs Xcode (XCTest isn't in the Command Line Tools)
./build.sh          # universal build/TwoFA.app + build/TwoFA.zip
./build.sh --install
```

### Releasing

```sh
git tag v1.1.0 && git push origin v1.1.0
```

The [release workflow](.github/workflows/release.yml) runs the tests, builds the app, publishes the
GitHub release and updates the version and checksum in [`Casks/twofa.rb`](Casks/twofa.rb).

## License

MIT

## Phone / web version and sync

See [`web/`](web/README.md): an installable PWA with an end-to-end encrypted vault synced through
Cloudflare, at https://2fa.ersincebi.com.

The Mac app joins the same vault via **⋯ → Connect to Sync…** with the vault's master password.
Accounts already on the Mac are uploaded on first connect; after that every device shows the same
list. The Mac keeps only the derived keys in the Keychain (never the password) and a local copy for
offline use. Like the web app, edits need a connection — offline changes are rolled back.

`TWOFA_TEST_SERVER=http://localhost:8787 swift test` also runs the sync client against `wrangler dev`.
