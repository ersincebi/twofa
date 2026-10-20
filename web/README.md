# TwoFA Web

The phone (and any browser) version of TwoFA: an installable PWA backed by a Cloudflare Worker,
with one end-to-end encrypted vault shared by every device.

## How it stays private

- The master password never leaves the device. PBKDF2 (600k rounds) + HKDF turn it into an
  AES-256-GCM key that stays local and an auth token that the server stores only as a hash.
- The Worker stores and returns ciphertext only — neither Cloudflare nor anyone who finds the URL
  can read the secrets.
- 10 wrong passwords from one IP lock it out for 15 minutes. A strict CSP blocks injected scripts.
- Writes are compare-and-set on a Durable Object, so two devices can't overwrite each other.
- Works offline: the encrypted vault is cached on the device.

There is no password recovery. If you forget the master password, the codes are gone — keep an
export (or the Pi backup plus the password) somewhere safe.

## Use

Open https://2fa.ersincebi.com in Chrome, create the vault, then **⋮ → Add to Home screen**.
Add accounts with **＋**: scan a QR code with the camera, pick a QR image, paste an `otpauth://`
link, or paste a plain secret. To bring over the Mac app's accounts, use its **Export Backup…** and
pick that file here.

## Develop and deploy

```sh
nvm use                # Node 24
npm install
npm test               # TOTP vectors, otpauth parsing, encryption
npm run dev            # http://localhost:8787
npm run deploy
```

## Raspberry Pi backup

`scripts/pi-backup.sh` pulls the encrypted vault to `/mnt/backup/twofa` every night with a
read-only token (`BACKUP_TOKEN` Worker secret). To restore, pick a `vault-*.json` file in the add
dialog; it asks for the master password if it differs.
