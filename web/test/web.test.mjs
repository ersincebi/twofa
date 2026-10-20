import assert from "node:assert/strict";
import { test } from "node:test";
import { base32Decode, parseOtpauth, toOtpauth, totp } from "../public/totp.js";
import { decrypt, deriveKeys, encrypt, randomSalt } from "../public/crypto.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(text) {
  let bits = "";
  for (const byte of Buffer.from(text)) bits += byte.toString(2).padStart(8, "0");
  return bits.match(/.{1,5}/g).map((chunk) => ALPHABET[parseInt(chunk.padEnd(5, "0"), 2)]).join("");
}

test("RFC 6238 test vectors", async () => {
  const secrets = {
    SHA1: base32Encode("12345678901234567890"),
    SHA256: base32Encode("12345678901234567890123456789012"),
    SHA512: base32Encode("1234567890123456789012345678901234567890123456789012345678901234"),
  };
  const vectors = [
    [59, { SHA1: "94287082", SHA256: "46119246", SHA512: "90693936" }],
    [1111111109, { SHA1: "07081804", SHA256: "68084774", SHA512: "25091201" }],
    [1111111111, { SHA1: "14050471", SHA256: "67062674", SHA512: "99943326" }],
    [1234567890, { SHA1: "89005924", SHA256: "91819424", SHA512: "93441116" }],
    [2000000000, { SHA1: "69279037", SHA256: "90698825", SHA512: "38618901" }],
    [20000000000, { SHA1: "65353130", SHA256: "77737706", SHA512: "47863826" }],
  ];
  for (const [time, expected] of vectors) {
    for (const [algorithm, code] of Object.entries(expected)) {
      const actual = await totp({ secret: secrets[algorithm], digits: 8, period: 30, algorithm }, time * 1000);
      assert.equal(actual, code, `${algorithm} at ${time}`);
    }
  }
});

test("Base32 ignores formatting and rejects junk", () => {
  assert.deepEqual(base32Decode("gezd gnbv-gy3t qojq===="), base32Decode("GEZDGNBVGY3TQOJQ"));
  assert.equal(base32Decode(""), null);
  assert.equal(base32Decode("NOT-BASE32-1!"), null);
});

test("otpauth links parse and round-trip", () => {
  const parsed = parseOtpauth(
    "otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60"
  );
  assert.deepEqual(parsed, {
    issuer: "ACME Co", name: "john@example.com", secret: "JBSWY3DPEHPK3PXP", digits: 8, period: 60, algorithm: "SHA256",
  });
  assert.deepEqual(parseOtpauth(toOtpauth(parsed)), parsed);
  assert.ok(!toOtpauth(parsed).includes("+"));
  assert.equal(parseOtpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"), null);
  assert.equal(parseOtpauth("https://example.com"), null);
});

test("vault encrypts, decrypts and rejects the wrong password", async () => {
  const salt = randomSalt();
  const right = await deriveKeys("correct horse battery staple", salt);
  const again = await deriveKeys("correct horse battery staple", salt);
  const wrong = await deriveKeys("wrong password", salt);
  assert.equal(right.authToken, again.authToken);
  assert.notEqual(right.authToken, wrong.authToken);

  const vault = { accounts: [{ issuer: "GitHub", secret: "JBSWY3DPEHPK3PXP" }] };
  const data = await encrypt(right.encKey, vault);
  assert.ok(!data.includes("JBSWY3DPEHPK3PXP"));
  assert.deepEqual(await decrypt(again.encKey, data), vault);
  await assert.rejects(decrypt(wrong.encKey, data), /Wrong password/);
});
