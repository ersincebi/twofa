import { DurableObject } from "cloudflare:workers";

const MAX_FAILURES = 10;
const LOCK_MS = 15 * 60 * 1000;
const MAX_VAULT_CHARS = 256 * 1024;

/**
 * Holds the single encrypted vault. The server never sees plaintext: clients send
 * AES-GCM ciphertext plus a token derived from the master password, stored here only as a hash.
 */
export class Vault extends DurableObject {
  async salt() {
    return (await this.ctx.storage.get("salt")) ?? null;
  }

  async read(authHash, ip) {
    const auth = await this.#authorize(authHash, ip);
    if (auth !== "ok") return { status: auth };
    const { version = 0, data = null } = Object.fromEntries(await this.ctx.storage.get(["version", "data"]));
    return { status: "ok", version, data };
  }

  /** Compare-and-set: writes only when `expected` matches the stored version. */
  async write(authHash, ip, expected, data, salt) {
    const storage = this.ctx.storage;
    if (await storage.get("authHash")) {
      const auth = await this.#authorize(authHash, ip);
      if (auth !== "ok") return { status: auth };
    } else {
      // The first write creates (claims) the vault.
      if (expected !== 0 || typeof salt !== "string" || !salt) return { status: "denied" };
      await storage.put({ authHash, salt });
    }

    const version = (await storage.get("version")) ?? 0;
    if (expected !== version) {
      return { status: "conflict", version, data: (await storage.get("data")) ?? null };
    }
    await storage.put({ version: version + 1, data });
    return { status: "ok", version: version + 1 };
  }

  /** Ciphertext + salt for off-site backups; useless without the master password. */
  async backup() {
    const { version = 0, data = null, salt = null } = Object.fromEntries(
      await this.ctx.storage.get(["version", "data", "salt"])
    );
    return { version, data, salt, exportedAt: new Date().toISOString() };
  }

  async #authorize(authHash, ip) {
    const storage = this.ctx.storage;
    const failKey = `fail:${ip}`;
    const fails = (await storage.get(failKey)) ?? { count: 0, until: 0 };
    if (fails.until > Date.now()) return "locked";

    const stored = await storage.get("authHash");
    if (stored && stored === authHash) {
      if (fails.count) await storage.delete(failKey);
      return "ok";
    }

    fails.count += 1;
    if (fails.count >= MAX_FAILURES) {
      fails.count = 0;
      fails.until = Date.now() + LOCK_MS;
    }
    await storage.put(failKey, fails);
    return "denied";
  }
}

const STATUS = { ok: 200, denied: 401, locked: 429, conflict: 409 };

function json(body, status = 200) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bearer(request) {
  const match = /^Bearer (.{1,200})$/.exec(request.headers.get("Authorization") ?? "");
  return match?.[1] ?? null;
}

async function safeEqual(a, b) {
  const [x, y] = await Promise.all([a, b].map((s) => crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
  return crypto.subtle.timingSafeEqual(x, y);
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const vault = env.VAULT.get(env.VAULT.idFromName("main"));
    const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";

    if (pathname === "/api/salt" && request.method === "GET") {
      return json({ salt: await vault.salt() });
    }

    if (pathname === "/api/backup" && request.method === "GET") {
      const token = bearer(request);
      if (!env.BACKUP_TOKEN || !token || !(await safeEqual(token, env.BACKUP_TOKEN))) {
        return json({ error: "unauthorized" }, 401);
      }
      return json(await vault.backup());
    }

    if (pathname === "/api/vault") {
      const token = bearer(request);
      if (!token) return json({ error: "unauthorized" }, 401);
      const authHash = await sha256Hex(token);

      let result;
      if (request.method === "GET") {
        result = await vault.read(authHash, ip);
      } else if (request.method === "PUT") {
        const body = await request.json().catch(() => null);
        if (!Number.isInteger(body?.version) || typeof body.data !== "string" || body.data.length > MAX_VAULT_CHARS) {
          return json({ error: "bad request" }, 400);
        }
        result = await vault.write(authHash, ip, body.version, body.data, body.salt);
      } else {
        return json({ error: "method not allowed" }, 405);
      }
      const { status, ...rest } = result;
      return json(status === "ok" || status === "conflict" ? rest : { error: status }, STATUS[status]);
    }

    return json({ error: "not found" }, 404);
  },
};
