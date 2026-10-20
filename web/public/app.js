import { base32Decode, isTotpLink, normalizeSecret, parseOtpauth, secondsRemaining, toOtpauth, totp } from "./totp.js";
import { decrypt, deriveKeys, encrypt, randomSalt } from "./crypto.js";

const $ = (id) => document.getElementById(id);
const CACHE_KEY = "twofa.cache";

let session = null; // { encKey, authToken } — only ever in memory, or in IndexedDB when "remember" is on
let accounts = [];
let version = 0;
let salt = null;
let editing = false;

// ---------- Local storage: ciphertext only ----------

function readCache() {
  try {
    return JSON.parse(localStorage.getItem(CACHE_KEY)) ?? {};
  } catch {
    return {};
  }
}

function writeCache(patch) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({ ...readCache(), ...patch }));
  } catch {
    // Private mode or storage full: we still work online.
  }
}

function idb(mode, run) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("twofa", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("kv");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction("kv", mode);
      const request = run(tx.objectStore("kv"));
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error);
    };
  });
}

// The AES key is non-extractable, so even a stored session can't be read out as raw bytes.
const remembered = {
  get: () => idb("readonly", (store) => store.get("session")).catch(() => null),
  set: (value) => idb("readwrite", (store) => store.put(value, "session")).catch(() => {}),
  clear: () => idb("readwrite", (store) => store.delete("session")).catch(() => {}),
};

// ---------- Server ----------

async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  if (session) headers.Authorization = `Bearer ${session.authToken}`;
  const res = await fetch(path, { method, headers, body: body && JSON.stringify(body), cache: "no-store" });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function applyRemote({ version: remoteVersion, data }) {
  accounts = data ? (await decrypt(session.encKey, data)).accounts : [];
  version = remoteVersion;
  writeCache({ salt, version, data });
}

function setStatus(state) {
  const titles = { synced: "Synced", offline: "Offline — showing saved copy", syncing: "Syncing…", error: "Sync error" };
  $("status").className = state;
  $("status").title = titles[state];
}

async function sync() {
  if (!session) return;
  setStatus("syncing");
  try {
    const res = await api("GET", "/api/vault");
    if (res.status === 401) return forget("Session expired. Unlock again.");
    if (res.status !== 200) return setStatus("error");
    if (res.body.version !== version) {
      await applyRemote(res.body);
      render();
    }
    setStatus("synced");
  } catch {
    setStatus("offline");
  }
}

/** Applies `change` to the account list and saves it, retrying on top of newer server data. */
async function mutate(change) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const next = change(structuredClone(accounts));
    const data = await encrypt(session.encKey, { accounts: next });
    let res;
    try {
      res = await api("PUT", "/api/vault", { version, data });
    } catch {
      setStatus("offline");
      toast("Offline — change not saved.");
      return false;
    }
    if (res.status === 200) {
      accounts = next;
      version = res.body.version;
      writeCache({ version, data });
      setStatus("synced");
      render();
      return true;
    }
    if (res.status === 409) {
      await applyRemote(res.body);
      continue;
    }
    if (res.status === 401) {
      forget("Session expired. Unlock again.");
      return false;
    }
    break;
  }
  toast("Couldn't save. Try again.");
  return false;
}

// ---------- Lock screen ----------

async function showLock(message = "") {
  session = null;
  accounts = [];
  $("main").hidden = true;
  $("lock").hidden = false;

  salt = readCache().salt ?? null;
  if (!salt) {
    try {
      salt = (await api("GET", "/api/salt")).body.salt ?? null;
    } catch {
      // Offline and never set up on this device.
    }
  }

  const setup = !salt;
  $("password2").hidden = !setup;
  $("password2").required = setup;
  $("password").autocomplete = setup ? "new-password" : "current-password";
  $("unlock").textContent = setup ? "Create vault" : "Unlock";
  $("lock-hint").textContent = setup
    ? "Choose a strong master password. It can't be recovered — if you forget it, your codes are gone."
    : "";
  $("password").value = "";
  $("password2").value = "";
  $("lock-error").textContent = message;
  $("password").focus();
}

async function forget(message) {
  await remembered.clear();
  await showLock(message);
}

async function createVault(password) {
  const newSalt = randomSalt();
  session = await deriveKeys(password, newSalt);
  const data = await encrypt(session.encKey, { accounts: [] });
  const res = await api("PUT", "/api/vault", { version: 0, data, salt: newSalt });
  if (res.status !== 200) throw new Error("A vault already exists. Reload the page.");
  salt = newSalt;
  accounts = [];
  version = res.body.version;
  writeCache({ salt, version, data });
  setStatus("synced");
}

async function unlock(password) {
  session = await deriveKeys(password, salt);
  let res = null;
  try {
    res = await api("GET", "/api/vault");
  } catch {
    // Offline: fall back to the cached copy below.
  }
  if (res?.status === 401) throw new Error("Wrong password.");
  if (res?.status === 429) throw new Error("Too many attempts. Try again in 15 minutes.");
  if (res?.status === 200) {
    await applyRemote(res.body);
    setStatus("synced");
    return;
  }
  const cache = readCache();
  if (!cache.data) throw new Error("Can't reach the server.");
  accounts = (await decrypt(session.encKey, cache.data)).accounts;
  version = cache.version;
  setStatus("offline");
}

$("lock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("password").value;
  const setup = !$("password2").hidden;
  const error = (text) => ($("lock-error").textContent = text);

  if (setup && password.length < 10) return error("Use at least 10 characters.");
  if (setup && password !== $("password2").value) return error("Passwords don't match.");

  $("unlock").disabled = true;
  error("");
  try {
    await (setup ? createVault(password) : unlock(password));
    if ($("remember").checked) await remembered.set(session);
    showMain();
  } catch (err) {
    session = null;
    error(err instanceof TypeError ? "You're offline." : err.message);
  } finally {
    $("unlock").disabled = false;
  }
});

// ---------- Account list ----------

function showMain() {
  $("lock").hidden = true;
  $("main").hidden = false;
  render();
}

function render() {
  const query = $("search").value.trim().toLowerCase();
  const list = $("list");
  list.replaceChildren();

  for (const account of accounts) {
    if (query && !`${account.issuer} ${account.name}`.toLowerCase().includes(query)) continue;

    const li = document.createElement("li");
    li.dataset.id = account.id;
    const meta = document.createElement("div");
    meta.className = "meta";
    const issuer = document.createElement("span");
    issuer.className = "issuer";
    issuer.textContent = account.issuer || account.name || "Unnamed";
    meta.append(issuer);
    if (account.issuer && account.name) {
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = account.name;
      meta.append(name);
    }
    const code = document.createElement("span");
    code.className = "code";
    meta.append(code);
    const ring = document.createElement("span");
    ring.className = "ring";
    li.append(meta, ring);

    if (editing) {
      const remove = document.createElement("button");
      remove.className = "delete";
      remove.textContent = "Delete";
      remove.addEventListener("click", (event) => {
        event.stopPropagation();
        if (confirm(`Delete ${issuer.textContent}? Make sure 2FA is turned off or moved for this account first.`)) {
          mutate((current) => current.filter((a) => a.id !== account.id));
        }
      });
      li.append(remove);
    }
    li.addEventListener("click", () => copy(account));
    list.append(li);
  }

  $("empty").hidden = accounts.length > 0;
  tick();
}

const codes = new Map(); // `${id}:${counter}` → code

async function codeFor(account, now) {
  const key = `${account.id}:${Math.floor(now / 1000 / account.period)}`;
  if (!codes.has(key)) {
    if (codes.size > 500) codes.clear();
    codes.set(key, await totp(account, now));
  }
  return codes.get(key);
}

async function tick() {
  const now = Date.now();
  for (const li of $("list").children) {
    const account = accounts.find((a) => a.id === li.dataset.id);
    if (!account) continue;
    const code = await codeFor(account, now);
    const remaining = secondsRemaining(account.period, now);
    const half = Math.ceil(code.length / 2);
    li.querySelector(".code").textContent = `${code.slice(0, half)} ${code.slice(half)}`;
    const ring = li.querySelector(".ring");
    ring.textContent = remaining;
    ring.style.setProperty("--progress", remaining / account.period);
    li.classList.toggle("expiring", remaining <= 5);
  }
}

async function copy(account) {
  try {
    await navigator.clipboard.writeText(await codeFor(account, Date.now()));
    toast("Copied");
  } catch {
    toast("Couldn't copy");
  }
}

let toastTimer;
function toast(message) {
  $("toast").textContent = message;
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("toast").hidden = true), 1800);
}

$("search").addEventListener("input", render);
$("edit-toggle").addEventListener("click", () => {
  editing = !editing;
  $("edit-toggle").classList.toggle("primary", editing);
  render();
});
$("lock-now").addEventListener("click", () => forget());

$("export").addEventListener("click", () => {
  if (!accounts.length) return toast("Nothing to export");
  if (!confirm("The export contains your secrets unencrypted. Keep the file somewhere safe. Continue?")) return;
  const blob = new Blob([accounts.map(toOtpauth).join("\n") + "\n"], { type: "text/plain" });
  const link = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(blob),
    download: "TwoFA Backup.txt",
  });
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});

// ---------- Add dialog ----------

let stream = null;
const addError = (text) => ($("add-error").textContent = text);

function setSecretText(text) {
  $("secret").value = text;
  prefillFromLink();
}

/** A single pasted/scanned link fills the name fields, so they can be adjusted before saving. */
function prefillFromLink() {
  addError("");
  const lines = $("secret").value.trim().split(/\s*\n\s*/);
  const parsed = lines.length === 1 ? parseOtpauth(lines[0]) : null;
  if (parsed) {
    $("issuer").value = parsed.issuer;
    $("name").value = parsed.name;
  }
}

function parseInput() {
  const text = $("secret").value.trim();
  const lines = text.split(/\s*\n\s*/).filter(Boolean);
  if (!lines.length) throw new Error("Paste a secret key or scan a QR code.");
  const issuer = $("issuer").value.trim();
  const name = $("name").value.trim();

  if (lines.some(isTotpLink)) {
    const parsed = lines.map(parseOtpauth).filter(Boolean);
    if (!parsed.length) throw new Error("Couldn't read that link.");
    if (parsed.length === 1) {
      parsed[0].issuer = issuer;
      parsed[0].name = name;
    }
    return parsed;
  }
  if (lines.length > 1 || !base32Decode(text)) throw new Error("Secret must be a valid Base32 key (A–Z, 2–7).");
  if (!issuer && !name) throw new Error("Enter an issuer or account name.");
  return [{ issuer, name, secret: normalizeSecret(text), digits: 6, period: 30, algorithm: "SHA1" }];
}

async function addAccounts(incoming) {
  let added = 0;
  const saved = await mutate((current) => {
    const fresh = incoming.filter((a) => !current.some((c) => c.secret === a.secret));
    added = fresh.length;
    return [...current, ...fresh.map((a) => ({ ...a, id: crypto.randomUUID() }))];
  });
  if (saved) toast(added ? `Added ${added} account${added === 1 ? "" : "s"}` : "Already added");
  return saved;
}

function stopCamera() {
  stream?.getTracks().forEach((track) => track.stop());
  stream = null;
  $("camera").hidden = true;
}

function qrDetector() {
  if (!("BarcodeDetector" in window)) {
    addError("This browser can't read QR codes. Paste the secret key instead.");
    return null;
  }
  return new BarcodeDetector({ formats: ["qr_code"] });
}

$("add-open").addEventListener("click", () => {
  for (const id of ["secret", "issuer", "name"]) $(id).value = "";
  addError("");
  $("add").showModal();
});
$("add-cancel").addEventListener("click", () => $("add").close());
$("add").addEventListener("close", stopCamera);
$("secret").addEventListener("input", prefillFromLink);

$("add-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  let parsed;
  try {
    parsed = parseInput();
  } catch (err) {
    return addError(err.message);
  }
  if (await addAccounts(parsed)) $("add").close();
});

$("scan").addEventListener("click", async () => {
  const detector = qrDetector();
  if (!detector || stream) return;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch {
    return addError("Camera access was denied.");
  }
  const video = $("camera");
  video.srcObject = stream;
  video.hidden = false;
  await video.play();

  const scan = async () => {
    if (!stream) return;
    const found = await detector.detect(video).catch(() => []);
    const link = found.map((code) => code.rawValue).find(isTotpLink);
    if (link) {
      stopCamera();
      setSecretText(link);
    } else {
      setTimeout(scan, 250);
    }
  };
  scan();
});

$("pick-file").addEventListener("click", () => $("file").click());

$("file").addEventListener("change", async () => {
  const file = $("file").files[0];
  $("file").value = "";
  if (!file) return;

  if (file.type.startsWith("image/")) {
    const detector = qrDetector();
    if (!detector) return;
    const found = await detector.detect(await createImageBitmap(file)).catch(() => []);
    const link = found.map((code) => code.rawValue).find(isTotpLink);
    return link ? setSecretText(link) : addError("No TOTP QR code found in the image.");
  }

  const text = await file.text();
  let backup = null;
  try {
    backup = JSON.parse(text);
  } catch {
    // Not JSON: treat as a list of otpauth:// links.
  }
  if (backup?.data && backup?.salt) return restoreBackup(backup);
  setSecretText(text.trim());
});

/** Merges accounts from an encrypted server backup (e.g. the Raspberry Pi copy). */
async function restoreBackup(backup) {
  try {
    let key = session.encKey;
    if (backup.salt !== salt) {
      const password = prompt("Master password of this backup:");
      if (!password) return;
      key = (await deriveKeys(password, backup.salt)).encKey;
    }
    const restored = (await decrypt(key, backup.data)).accounts.map(({ id, ...account }) => account);
    if (await addAccounts(restored)) $("add").close();
  } catch (err) {
    addError(err.message);
  }
}

// ---------- Start ----------

setInterval(() => {
  if (!$("main").hidden) tick();
}, 1000);

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") sync();
});

async function start() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});

  const saved = await remembered.get();
  if (!saved) return showLock();

  session = saved;
  const cache = readCache();
  salt = cache.salt ?? null;
  if (cache.data) {
    try {
      accounts = (await decrypt(session.encKey, cache.data)).accounts;
      version = cache.version;
      showMain();
    } catch {
      return forget();
    }
  }
  await sync();
  if ($("main").hidden && session) showMain();
}

start();
