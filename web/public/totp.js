const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HASHES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

/** Strips spaces, dashes and padding so secrets copied from websites just work. */
export function normalizeSecret(secret) {
  return secret.toUpperCase().replace(/[\s=-]/g, "");
}

export function base32Decode(input) {
  const cleaned = normalizeSecret(input);
  if (!cleaned) return null;
  let value = 0;
  let bits = 0;
  const out = [];
  for (const char of cleaned) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) return null;
    value = ((value << 5) | index) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return out.length ? new Uint8Array(out) : null;
}

/** RFC 6238 time-based one-time password. */
export async function totp({ secret, digits = 6, period = 30, algorithm = "SHA1" }, now = Date.now()) {
  const counter = Math.floor(now / 1000 / period);
  const message = new DataView(new ArrayBuffer(8));
  message.setUint32(0, Math.floor(counter / 2 ** 32));
  message.setUint32(4, counter >>> 0);

  const key = await crypto.subtle.importKey(
    "raw", base32Decode(secret), { name: "HMAC", hash: HASHES[algorithm] }, false, ["sign"]
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message.buffer));

  // Dynamic truncation (RFC 4226 section 5.3).
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, "0");
}

export function secondsRemaining(period = 30, now = Date.now()) {
  return period - (Math.floor(now / 1000) % period);
}

export function isTotpLink(text) {
  return /^otpauth:\/\/totp\//i.test(text.trim());
}

/** Parses `otpauth://totp/Issuer:name?secret=...` links (e.g. from QR codes). */
export function parseOtpauth(uri) {
  let url;
  try {
    url = new URL(uri.trim());
  } catch {
    return null;
  }
  if (url.protocol !== "otpauth:" || url.host.toLowerCase() !== "totp") return null;

  const params = new Map([...url.searchParams].map(([k, v]) => [k.toLowerCase(), v]));
  const secret = normalizeSecret(params.get("secret") ?? "");
  if (!base32Decode(secret)) return null;

  let label;
  try {
    label = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
  } catch {
    return null;
  }
  const colon = label.indexOf(":");
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : "";
  const name = (colon >= 0 ? label.slice(colon + 1) : label).trim();

  const digits = Number(params.get("digits"));
  const period = Number(params.get("period"));
  const algorithm = (params.get("algorithm") ?? "").toUpperCase();
  return {
    issuer: params.get("issuer") || labelIssuer,
    name,
    secret,
    digits: digits >= 6 && digits <= 8 ? digits : 6,
    period: Number.isInteger(period) && period > 0 ? period : 30,
    algorithm: algorithm in HASHES ? algorithm : "SHA1",
  };
}

/** The standard link for an account, understood by most authenticator apps. */
export function toOtpauth({ issuer, name, secret, digits, period, algorithm }) {
  const label = (issuer ? [issuer, name] : [name]).map(encodeURIComponent).join(":");
  const params = new URLSearchParams({ secret });
  if (issuer) params.set("issuer", issuer);
  params.set("algorithm", algorithm);
  params.set("digits", digits);
  params.set("period", period);
  // Some parsers (e.g. Foundation's URLComponents) don't treat "+" as a space.
  return `otpauth://totp/${label}?${params.toString().replace(/\+/g, "%20")}`;
}
