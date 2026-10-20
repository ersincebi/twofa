// Vault encryption. The master password never leaves the device: PBKDF2 stretches it into a
// master key, and HKDF splits that into an AES-GCM key (stays local) and an auth token (sent to the server).

const ITERATIONS = 600_000;
const encoder = new TextEncoder();

export function toBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

export function randomSalt() {
  return toBase64(crypto.getRandomValues(new Uint8Array(16)));
}

export async function deriveKeys(password, salt) {
  const passwordKey = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const master = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromBase64(salt), iterations: ITERATIONS },
    passwordKey,
    256
  );
  const hkdf = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits", "deriveKey"]);
  const info = (label) => ({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode(label) });

  const encKey = await crypto.subtle.deriveKey(
    info("twofa-encryption"), hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
  const authToken = toBase64(new Uint8Array(await crypto.subtle.deriveBits(info("twofa-auth"), hkdf, 256)));
  return { encKey, authToken };
}

/** Returns base64(iv || ciphertext). */
export async function encrypt(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(value));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv);
  out.set(ciphertext, iv.length);
  return toBase64(out);
}

export async function decrypt(key, data) {
  const bytes = fromBase64(data);
  try {
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.subarray(0, 12) }, key, bytes.subarray(12));
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new Error("Wrong password.");
  }
}
