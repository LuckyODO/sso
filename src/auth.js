import { randomUrlSafe, timingSafeEqual } from "./crypto.js";
import { normalizeEmail, normalizeInviteCode } from "./store.js";

const encoder = new TextEncoder();
const ITERATIONS = 600000;
const SALT_BYTES = 16;
const KEY_BYTES = 32;
const AUTH_COOKIE = "sso_session";

// ============ Password Hashing (PBKDF2) ============
export async function hashPassword(password) {
  const salt = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(salt);
  const key = await deriveKey(password, salt, ITERATIONS);
  const params = {
    v: 1,
    it: ITERATIONS,
    salt: base64UrlEncode(salt),
    hash: base64UrlEncode(key),
  };
  return `pbkdf2$${JSON.stringify(params)}`;
}

export async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  const [scheme, payload] = storedHash.split("$");
  if (scheme !== "pbkdf2") return false;
  let params;
  try {
    params = JSON.parse(payload);
  } catch {
    return false;
  }
  if (params.v !== 1) return false;
  const salt = base64UrlDecode(params.salt);
  const expectedHash = base64UrlDecode(params.hash);
  const actualHash = await deriveKey(password, salt, params.it || ITERATIONS);
  return timingSafeEqualBytes(actualHash, expectedHash);
}

async function deriveKey(password, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(String(password ?? "")),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    KEY_BYTES * 8
  );
  return new Uint8Array(bits);
}

function timingSafeEqualBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function base64UrlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "="
  );
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

// ============ Session Cookies ============
export function getSessionCookieValue(request) {
  const header = request.headers.get("cookie") ?? "";
  const match = header.match(new RegExp(`(?:^|;)\\s*${AUTH_COOKIE}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : "";
}

export function setSessionCookie(responseHeaders, token, { issuer, secure = true, ttlSeconds = 86400 * 7 }) {
  let host = "";
  try {
    host = new URL(issuer).hostname;
  } catch {}
  const parts = [
    `${AUTH_COOKIE}=${encodeURIComponent(token)}`,
    `Path=/`,
    `Max-Age=${ttlSeconds}`,
    `SameSite=Lax`,
    `HttpOnly`,
  ];
  if (secure && host && host !== "localhost" && !host.endsWith(".local")) {
    parts.push("Secure");
  }
  if (host && host !== "localhost" && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    parts.push(`Domain=${host}`);
  }
  responseHeaders.append("set-cookie", parts.join("; "));
}

export function clearSessionCookie(responseHeaders, { issuer }) {
  let host = "";
  try {
    host = new URL(issuer).hostname;
  } catch {}
  const parts = [
    `${AUTH_COOKIE}=`,
    `Path=/`,
    `Max-Age=0`,
    `Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
    `SameSite=Lax`,
    `HttpOnly`,
  ];
  if (host && host !== "localhost" && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    parts.push(`Domain=${host}`);
  }
  responseHeaders.append("set-cookie", parts.join("; "));
}

// ============ Auth Service ============
export class AuthService {
  constructor({ store, config }) {
    this.store = store;
    this.config = config;
  }

  async registerWithInvite({ account, displayName, password, inviteCode, userAgent, ipAddress }) {
    const resolvedEmail = resolveAccountEmail(account, this.config.defaultAccountDomain);
    const { user, created } = await this.store.createUserWithInvite({
      email: resolvedEmail,
      displayName,
      passwordHash: password ? await hashPassword(password) : null,
      inviteCode: normalizeInviteCode(inviteCode),
    });
    const email = user?.email || resolvedEmail;
    await this.store.updateUserLogin(email);
    await this.store.addAuditLog({
      userId: user.id,
      email,
      action: created ? "user.register" : "user.login",
      ipAddress,
      userAgent,
      details: { via: "invite", created },
    });
    return { user, created };
  }

  async loginWithPassword({ account, password, userAgent, ipAddress }) {
    const email = resolveAccountEmail(account, this.config.defaultAccountDomain);
    const user = await this.store.getUserByEmail(email);
    if (!user) throw new Error("账号不存在");
    if (!user.isActive) throw new Error("账号已被停用");
    if (!user.passwordHash) throw new Error("此账号未设置密码，请使用其他登录方式");
    const ok = await verifyPassword(password, user.passwordHash);
    if (!ok) throw new Error("密码错误");
    await this.store.updateUserLogin(email);
    await this.store.addAuditLog({
      userId: user.id,
      email,
      action: "user.login",
      ipAddress,
      userAgent,
      details: { via: "password" },
    });
    return { user, created: false };
  }

  async loginWithInviteOnly({ account, inviteCode, userAgent, ipAddress }) {
    // 兼容旧的"只凭邀请码+账号注册/登录"模式（无密码）
    const email = resolveAccountEmail(account, this.config.defaultAccountDomain);
    const existing = await this.store.getUserByEmail(email);
    if (existing) {
      if (!existing.isActive) throw new Error("账号已被停用");
      await this.store.updateUserLogin(email);
      await this.store.addAuditLog({
        userId: existing.id,
        email,
        action: "user.login",
        ipAddress,
        userAgent,
        details: { via: "invite-existing" },
      });
      return { user: existing, created: false };
    }
    return this.registerWithInvite({ account, displayName: "", password: "", inviteCode, userAgent, ipAddress });
  }

  async createSession(user, { userAgent, ipAddress }) {
    return this.store.createSession({
      userId: user.id,
      email: user.email,
      userAgent,
      ipAddress,
      ttlSeconds: this.config.sessionTtlSeconds,
    });
  }

  async getSessionFromRequest(request) {
    const token = getSessionCookieValue(request);
    if (!token) return null;
    let session = await this.store.getSession(token);
    if (!session) return null;
    session = await this.store.touchSession(token);
    const user = await this.store.getUserById(session.userId);
    if (!user || !user.isActive) {
      await this.store.deleteSession(token);
      return null;
    }
    return { session, user };
  }

  async logoutSession(request) {
    const token = getSessionCookieValue(request);
    if (token) await this.store.deleteSession(token);
  }

  async validateAdmin(request) {
    const ctx = await this.getSessionFromRequest(request);
    if (ctx && ctx.user.isAdmin) return ctx;
    // fallback: legacy ADMIN_TOKEN via Bearer
    const auth = request.headers.get("authorization") ?? "";
    const m = auth.match(/^Bearer\s+(.+)$/i);
    if (m && this.config.adminToken && timingSafeEqual(m[1], this.config.adminToken)) {
      return { session: null, user: { id: null, email: "api-admin", isAdmin: true } };
    }
    return null;
  }
}

export function resolveAccountEmail(account, accountDomain) {
  const domain = (accountDomain ?? "").toString().trim().toLowerCase().replace(/^@+/, "");
  const normalized = String(account ?? "").trim().toLowerCase();
  if (!normalized) throw new Error("请输入账号");
  if (normalized.includes("@")) {
    if (domain && !normalized.endsWith(`@${domain}`)) {
      throw new Error(`只能使用 @${domain} 账号`);
    }
    return normalizeEmail(normalized);
  }
  if (!/^[a-z0-9._+-]+$/.test(normalized)) {
    throw new Error("账号只能包含英文字母、数字、点、下划线、加号与连字符");
  }
  if (!domain) throw new Error("缺少账号域名配置，请输入完整邮箱");
  return normalizeEmail(`${normalized}@${domain}`);
}

export function validatePasswordStrength(password) {
  const p = String(password ?? "");
  if (p.length < 8) return "密码至少需要 8 位";
  if (!/[A-Za-z]/.test(p) || !/\d/.test(p)) return "密码需要同时包含字母和数字";
  return null;
}

export { randomUrlSafe };
