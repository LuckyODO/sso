import { strict as assert } from "node:assert";
import { before, describe, it } from "node:test";

import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { MemoryStore } from "../src/store.js";
import { hashPassword, verifyPassword, validatePasswordStrength } from "../src/auth.js";

let privateJwk;

before(async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  privateJwk.kid = "sso-test-key";
  privateJwk.alg = "RS256";
  privateJwk.use = "sig";
});

function createTestApp(envOverrides = {}, appOptions = {}) {
  const store = new MemoryStore();
  const config = loadConfig({
    ISSUER: "https://sso.example.com",
    OIDC_CLIENT_ID: "openai-client",
    OIDC_CLIENT_SECRET: "secret",
    ALLOWED_REDIRECT_URIS: "https://auth.openai.com/oidc/callback",
    ACCOUNT_DOMAIN: "example.com",
    PRIVATE_JWK: JSON.stringify(privateJwk),
    ADMIN_TOKEN: "admin-token",
    ADMIN_EMAILS: "admin@example.com",
    SESSION_SECRET: "test-session-secret",
    ...envOverrides
  });
  return { store, config, app: createApp({ store, config, ...appOptions }) };
}

async function withGlobalFetch(fetchImplementation, callback) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImplementation;
  try {
    return await callback();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

// ============================================================
// 密码哈希模块
// ============================================================
describe("密码哈希模块", () => {
  it("PBKDF2 hashPassword 可生成可验证的哈希", async () => {
    const hash = await hashPassword("TestPass123");
    assert.ok(hash.startsWith("pbkdf2$"));
    assert.ok(await verifyPassword("TestPass123", hash));
    assert.ok(!(await verifyPassword("WrongPass1", hash)));
  });

  it("validatePasswordStrength 检查长度和复杂度", () => {
    assert.equal(validatePasswordStrength("abc"), "密码至少需要 8 位");
    assert.equal(validatePasswordStrength("abcdefgh"), "密码需要同时包含字母和数字");
    assert.equal(validatePasswordStrength("12345678"), "密码需要同时包含字母和数字");
    assert.equal(validatePasswordStrength("Abcdefg1"), null);
  });
});

// ============================================================
// Store 层
// ============================================================
describe("Store 数据层", () => {
  it("邀请码 CRUD 正常", async () => {
    const store = new MemoryStore();
    const invite = await store.createInviteCode({ code: "TEST-123", maxUses: 5, createdBy: "admin" });
    assert.equal(invite.code, "TEST-123");
    assert.equal(invite.maxUses, 5);
    assert.equal(invite.usedCount, 0);

    const got = await store.getInviteCode("TEST-123");
    assert.equal(got.code, "TEST-123");

    const list = await store.listInviteCodes();
    assert.equal(list.length, 1);

    await store.updateInviteCode("TEST-123", { enabled: false });
    const disabled = await store.getInviteCode("TEST-123");
    assert.equal(disabled.enabled, false);

    const del = await store.deleteInviteCode("TEST-123");
    assert.equal(del, true);
    assert.equal(await store.getInviteCode("TEST-123"), null);
  });

  it("用户 CRUD 与邀请码注册", async () => {
    const store = new MemoryStore();
    await store.createInviteCode({ code: "INV-NEW", maxUses: 10 });

    const { user, created } = await store.createUserWithInvite({
      email: "alice@example.com",
      displayName: "Alice",
      passwordHash: null,
      inviteCode: "INV-NEW"
    });
    assert.equal(created, true);
    assert.equal(user.email, "alice@example.com");
    assert.equal(user.displayName, "Alice");

    const used = await store.getInviteCode("INV-NEW");
    assert.equal(used.usedCount, 1);

    // 重复注册不会创建新用户
    const again = await store.createUserWithInvite({
      email: "alice@example.com",
      inviteCode: "INV-NEW"
    });
    assert.equal(again.created, false);

    const stats = await store.getStats();
    assert.equal(stats.totalUsers, 1);
    assert.equal(stats.totalInviteCodes, 1);
  });

  it("应用 CRUD 正常", async () => {
    const store = new MemoryStore();
    const app = await store.createApp({
      clientId: "my-app",
      clientSecret: "my-secret",
      name: "我的应用",
      redirectUris: ["https://app.example.com/callback"],
      scopes: ["openid", "email"]
    });
    assert.equal(app.clientId, "my-app");
    assert.equal(app.name, "我的应用");
    assert.deepEqual(app.redirectUris, ["https://app.example.com/callback"]);

    const got = await store.getAppByClientId("my-app");
    assert.equal(got.name, "我的应用");

    const list = await store.listApps();
    assert.equal(list.length, 1);

    await store.updateApp("my-app", { name: "更新后的应用" });
    const updated = await store.getAppByClientId("my-app");
    assert.equal(updated.name, "更新后的应用");

    await store.deleteApp("my-app");
    assert.equal(await store.getAppByClientId("my-app"), null);
  });

  it("会话 CRUD 与过期清理", async () => {
    const store = new MemoryStore();
    const sess = await store.createSession({
      userId: 1, email: "test@example.com", ttlSeconds: 1
    });
    assert.ok(sess.token);
    assert.equal(sess.userId, 1);

    const got = await store.getSession(sess.token);
    assert.equal(got.token, sess.token);

    await store.touchSession(sess.token);

    const list = await store.listSessionsByUserId(1);
    assert.equal(list.length, 1);

    await store.deleteSession(sess.token);
    assert.equal(await store.getSession(sess.token), null);
  });

  it("授权码只能用一次", async () => {
    const store = new MemoryStore();
    const code = await store.saveAuthorizationCode({
      code: "auth-code-1",
      userId: 1,
      email: "a@b.com",
      clientId: "cid",
      redirectUri: "https://example.com/cb",
      scope: "openid email",
      expiresAt: new Date(Date.now() + 300 * 1000).toISOString(),
      createdAt: new Date().toISOString()
    });
    const first = await store.consumeAuthorizationCode("auth-code-1");
    assert.ok(first);
    const second = await store.consumeAuthorizationCode("auth-code-1");
    assert.equal(second, null);
  });

  it("审计日志写入与统计", async () => {
    const store = new MemoryStore();
    await store.addAuditLog({
      userId: 1, email: "a@b.com", action: "user.login", ipAddress: "1.2.3.4"
    });
    await store.addAuditLog({
      userId: 1, email: "a@b.com", action: "admin.user.create", targetType: "user", targetId: "c@d.com"
    });
    const logs = await store.listAuditLogs();
    assert.equal(logs.length, 2);
    const stats = await store.getStats();
    assert.equal(stats.totalAuditLogs, 2);
  });
});

// ============================================================
// OIDC 服务
// ============================================================
describe("OIDC 服务", () => {
  it("validateAuthorizeRequest 接受合法请求并拒绝未知客户端", async () => {
    const { store, config } = createTestApp();
    const { OidcService } = await import("../src/oidc-service.js");
    const oidc = new OidcService({ store, config });

    const meta = oidc.getDiscoveryMetadata();
    assert.equal(meta.issuer, "https://sso.example.com");
    assert.equal(meta.authorization_endpoint, "https://sso.example.com/authorize");
    assert.equal(meta.token_endpoint, "https://sso.example.com/token");
    assert.ok(meta.jwks_uri.endsWith("/jwks.json"));

    const req = new URLSearchParams({
      client_id: "openai-client",
      redirect_uri: "https://auth.openai.com/oidc/callback",
      response_type: "code",
      scope: "openid email"
    });
    const valid = await oidc.validateAuthorizeRequest(req);
    assert.equal(valid.clientId, "openai-client");

    await assert.rejects(
      oidc.validateAuthorizeRequest(new URLSearchParams({
        client_id: "unknown-client",
        redirect_uri: "x", response_type: "code", scope: "openid"
      })),
      /未知的 OIDC 客户端/
    );
  });

  it("授权码交换：可以交换一次且 client_secret 校验", async () => {
    const { store, config } = createTestApp();
    const { OidcService } = await import("../src/oidc-service.js");
    const oidc = new OidcService({ store, config });

    const passwordHash = await hashPassword("UserPass1");
    const user = await store.createUser({
      email: "user1@example.com", displayName: "User1", passwordHash
    });

    const code = await oidc.createAuthorizationCode({
      user,
      clientId: "openai-client",
      redirectUri: "https://auth.openai.com/oidc/callback",
      scope: "openid email profile"
    });

    // 错误 secret
    await assert.rejects(
      oidc.exchangeCode({
        code: code.code,
        clientId: "openai-client",
        clientSecret: "wrong-secret",
        redirectUri: "https://auth.openai.com/oidc/callback"
      }),
      /client_secret/
    );

    // 正确 secret
    const token = await oidc.exchangeCode({
      code: code.code,
      clientId: "openai-client",
      clientSecret: "secret",
      redirectUri: "https://auth.openai.com/oidc/callback"
    });
    assert.ok(token.access_token);
    assert.ok(token.id_token);
    assert.equal(token.token_type, "Bearer");
    assert.equal(token.scope, "openid email profile");

    // 再次使用应该失败
    await assert.rejects(
      oidc.exchangeCode({
        code: code.code,
        clientId: "openai-client",
        clientSecret: "secret",
        redirectUri: "https://auth.openai.com/oidc/callback"
      }),
      /已使用/
    );
  });
});

// ============================================================
// Worker HTTP 端点
// ============================================================
describe("Worker HTTP 端點", () => {
  it("/.well-known/openid-configuration 返回发现文档", async () => {
    const { app } = createTestApp();
    const resp = await app.fetch(new Request("https://sso.example.com/.well-known/openid-configuration"));
    assert.equal(resp.status, 200);
    const body = await resp.json();
    assert.equal(body.issuer, "https://sso.example.com");
    assert.equal(body.authorization_endpoint, "https://sso.example.com/authorize");
  });

  it("/jwks.json 返回标准 JWKS", async () => {
    const { app } = createTestApp();
    const resp = await app.fetch(new Request("https://sso.example.com/jwks.json"));
    assert.equal(resp.status, 200);
    assert.equal(resp.headers.get("content-type"), "application/jwk-set+json; charset=utf-8");
    const body = await resp.json();
    assert.equal(body.keys.length, 1);
    const jwk = body.keys[0];
    assert.equal(jwk.kty, "RSA");
    assert.equal(jwk.alg, "RS256");
    assert.equal(jwk.use, "sig");
    assert.equal(jwk.kid, "sso-test-key");
    assert.ok(jwk.n && jwk.e);
  });

  it("/authorize 显示 SSO 登录表单（带隐藏 OIDC 字段）", async () => {
    const { app } = createTestApp();
    const resp = await app.fetch(
      new Request(
        "https://sso.example.com/authorize?client_id=openai-client&redirect_uri=https%3A%2F%2Fauth.openai.com%2Foidc%2Fcallback&response_type=code&scope=openid%20email&state=abc123"
      )
    );
    assert.equal(resp.status, 200);
    const html = await resp.text();
    assert.match(html, /<title>登录 · Default App<\/title>/);
    assert.match(html, /登录以继续访问/);
    assert.match(html, /name="client_id" value="openai-client"/);
    assert.match(html, /name="redirect_uri" value="https:\/\/auth\.openai\.com\/oidc\/callback"/);
    assert.match(html, /name="state" value="abc123"/);
    assert.match(html, /name="account"/);
    assert.match(html, /name="password"/);
    assert.match(html, /name="invite_code"/);
  });

  it("/authorize 未设置 account domain 时要求完整邮箱", async () => {
    const { app } = createTestApp({ ACCOUNT_DOMAIN: "" });
    const resp = await app.fetch(
      new Request(
        "https://sso.example.com/authorize?client_id=openai-client&redirect_uri=https%3A%2F%2Fauth.openai.com%2Foidc%2Fcallback&response_type=code&scope=openid%20email&state=abc123"
      )
    );
    assert.equal(resp.status, 200);
    const html = await resp.text();
    // 没有 @domain 提示
    assert.doesNotMatch(html, /<span class="domain">@/);
  });

  it("/ 有 openaiLoginUrl 时跳转到 Tile URL", async () => {
    const { app } = createTestApp({
      OPENAI_LOGIN_URL: "https://chatgpt.com/auth/login?sso=true&connection=conn_test"
    });
    const resp = await app.fetch(new Request("https://sso.example.com/"));
    assert.equal(resp.status, 302);
    assert.equal(resp.headers.get("location"), "https://chatgpt.com/auth/login?sso=true&connection=conn_test");
  });

  it("/ 没有 openaiLoginUrl 时跳转到 admin-login", async () => {
    const { app } = createTestApp({ OPENAI_LOGIN_URL: "" });
    const resp = await app.fetch(new Request("https://sso.example.com/"));
    assert.equal(resp.status, 302);
    assert.equal(resp.headers.get("location"), "/admin-login");
  });

  it("/admin-login 显示管理员登录页", async () => {
    const { app } = createTestApp();
    const resp = await app.fetch(new Request("https://sso.example.com/admin-login"));
    assert.equal(resp.status, 200);
    const html = await resp.text();
    assert.match(html, /登录 · SSO 管理后台/);
    assert.match(html, /name="account"/);
    assert.match(html, /name="password"/);
  });

  it("/register 显示注册页", async () => {
    const { app } = createTestApp();
    const resp = await app.fetch(
      new Request(
        "https://sso.example.com/register?client_id=openai-client&redirect_uri=https%3A%2F%2Fauth.openai.com%2Foidc%2Fcallback&response_type=code&scope=openid%20email"
      )
    );
    assert.equal(resp.status, 200);
    const html = await resp.text();
    assert.match(html, /<title>注册账号 · Default App<\/title>/);
    assert.match(html, /name="invite_code"/);
    assert.match(html, /name="display_name"/);
  });

  it("/login 带密码的用户登录流程（无Turnstile）", async () => {
    const { app, store } = createTestApp();
    const passwordHash = await hashPassword("User1234");
    await store.createUser({
      email: "user1@example.com",
      displayName: "User One",
      passwordHash,
      emailVerified: true
    });

    const body = new FormData();
    body.set("client_id", "openai-client");
    body.set("redirect_uri", "https://auth.openai.com/oidc/callback");
    body.set("response_type", "code");
    body.set("scope", "openid email");
    body.set("state", "state123");
    body.set("account", "user1@example.com");
    body.set("password", "User1234");

    const resp = await app.fetch(new Request("https://sso.example.com/login", {
      method: "POST", body
    }));
    const text = await resp.text();
    assert.equal(resp.status, 302, `Expected redirect but got ${resp.status}: ${text}`);
    const location = resp.headers.get("location");
    assert.ok(location.startsWith("https://auth.openai.com/oidc/callback"));
    const u = new URL(location);
    assert.ok(u.searchParams.get("code"));
    assert.equal(u.searchParams.get("state"), "state123");
  });

  it("/login 使用邀请码注册新用户", async () => {
    const { app, store } = createTestApp();
    await store.createInviteCode({ code: "REGISTER-1", maxUses: 10 });

    const body = new FormData();
    body.set("client_id", "openai-client");
    body.set("redirect_uri", "https://auth.openai.com/oidc/callback");
    body.set("response_type", "code");
    body.set("scope", "openid email");
    body.set("state", "s1");
    body.set("account", "newuser@example.com");
    body.set("invite_code", "REGISTER-1");

    const resp = await app.fetch(new Request("https://sso.example.com/login", {
      method: "POST", body
    }));
    const text = await resp.text();
    assert.equal(resp.status, 302, `Expected redirect but got ${resp.status}: ${text}`);
    const u = new URL(resp.headers.get("location"));
    assert.ok(u.searchParams.get("code"));

    const user = await store.getUserByEmail("newuser@example.com");
    assert.ok(user);
    assert.equal(user.displayName, "newuser");
  });

  it("/register 注册成功并跳转到 callback（无Turnstile）", async () => {
    const { app, store } = createTestApp();
    await store.createInviteCode({ code: "REG-NEW", maxUses: 10 });

    const body = new FormData();
    body.set("client_id", "openai-client");
    body.set("redirect_uri", "https://auth.openai.com/oidc/callback");
    body.set("response_type", "code");
    body.set("scope", "openid email");
    body.set("state", "reg-state");
    body.set("account", "reguser@example.com");
    body.set("display_name", "Reg User");
    body.set("invite_code", "REG-NEW");
    body.set("password", "RegPass12");

    const resp = await app.fetch(new Request("https://sso.example.com/register", {
      method: "POST", body
    }));
    const text = await resp.text();
    assert.equal(resp.status, 302, `Expected redirect but got ${resp.status}: ${text}`);
    const u = new URL(resp.headers.get("location"));
    assert.ok(u.searchParams.get("code"));
    assert.equal(u.searchParams.get("state"), "reg-state");

    const user = await store.getUserByEmail("reguser@example.com");
    assert.ok(user);
    assert.equal(user.displayName, "Reg User");
  });

  it("/token 表单换取 token", async () => {
    const { app, store, config } = createTestApp();
    const { OidcService } = await import("../src/oidc-service.js");
    const oidc = new OidcService({ store, config });

    const passwordHash = await hashPassword("UserPass1");
    const user = await store.createUser({
      email: "tokenuser@example.com", displayName: "Token User", passwordHash
    });
    const code = await oidc.createAuthorizationCode({
      user,
      clientId: "openai-client",
      redirectUri: "https://auth.openai.com/oidc/callback",
      scope: "openid email"
    });

    const tokenBody = new FormData();
    tokenBody.set("grant_type", "authorization_code");
    tokenBody.set("code", code.code);
    tokenBody.set("redirect_uri", "https://auth.openai.com/oidc/callback");
    const basicAuth = "Basic " + btoa("openai-client:secret");
    const resp = await app.fetch(new Request("https://sso.example.com/token", {
      method: "POST",
      body: tokenBody,
      headers: { authorization: basicAuth }
    }));
    const text = await resp.text();
    assert.equal(resp.status, 200, `Expected 200 but got ${resp.status}: ${text}`);
    const token = JSON.parse(text);
    assert.ok(token.access_token);
    assert.ok(token.id_token);
    assert.equal(token.token_type, "Bearer");
  });

  it("/userinfo 用 Bearer token 获取用户信息", async () => {
    const { app, store, config } = createTestApp();
    const { OidcService } = await import("../src/oidc-service.js");
    const oidc = new OidcService({ store, config });

    const passwordHash = await hashPassword("UserPass1");
    const user = await store.createUser({
      email: "infouser@example.com", displayName: "Info User", passwordHash, emailVerified: true
    });

    const accessToken = await oidc.createAccessToken(user, "openai-client");
    const resp = await app.fetch(new Request("https://sso.example.com/userinfo", {
      headers: { authorization: `Bearer ${accessToken}` }
    }));
    assert.equal(resp.status, 200);
    const info = await resp.json();
    assert.equal(info.email, "infouser@example.com");
    assert.equal(info.name, "Info User");
    assert.equal(info.email_verified, true);
  });

  it("/admin 需要管理员 session，否则重定向登录", async () => {
    const { app } = createTestApp();
    const resp = await app.fetch(new Request("https://sso.example.com/admin"));
    assert.equal(resp.status, 302);
    assert.ok(resp.headers.get("location").startsWith("/admin-login"));
  });

  it("Turnstile：只配置 site-key 但没 secret 会拒绝登录", async () => {
    const { app, store } = createTestApp({ TURNSTILE_SITE_KEY: "sitekey1", TURNSTILE_SECRET_KEY: "" });
    await store.createInviteCode({ code: "TURN-1", maxUses: 10 });

    const body = new FormData();
    body.set("client_id", "openai-client");
    body.set("redirect_uri", "https://auth.openai.com/oidc/callback");
    body.set("response_type", "code");
    body.set("scope", "openid email");
    body.set("account", "tuser@example.com");
    body.set("invite_code", "TURN-1");

    const resp = await app.fetch(new Request("https://sso.example.com/login", {
      method: "POST", body
    }));
    // 错误可能嵌入在 200 登录页里，或者顶层 errorResponse 返回 400
    const text = await resp.text();
    assert.match(text, /TURNSTILE_SECRET_KEY/);
  });

  it("Turnstile：配置双方但缺少响应 token 会拒绝登录", async () => {
    const { app, store } = createTestApp({ TURNSTILE_SITE_KEY: "sitekey1", TURNSTILE_SECRET_KEY: "secret1" });
    await store.createInviteCode({ code: "TURN-2", maxUses: 10 });

    const body = new FormData();
    body.set("client_id", "openai-client");
    body.set("redirect_uri", "https://auth.openai.com/oidc/callback");
    body.set("response_type", "code");
    body.set("scope", "openid email");
    body.set("account", "tuser2@example.com");
    body.set("invite_code", "TURN-2");

    const resp = await app.fetch(new Request("https://sso.example.com/login", {
      method: "POST", body
    }));
    const text = await resp.text();
    assert.match(text, /人机验证/);
  });

  it("Turnstile：通过 mock fetch 验证成功后放行", async () => {
    const store = new MemoryStore();
    const config = loadConfig({
      ISSUER: "https://sso.example.com",
      OIDC_CLIENT_ID: "openai-client",
      OIDC_CLIENT_SECRET: "secret",
      ALLOWED_REDIRECT_URIS: "https://auth.openai.com/oidc/callback",
      ACCOUNT_DOMAIN: "",
      PRIVATE_JWK: JSON.stringify(privateJwk),
      ADMIN_TOKEN: "admin-token",
      SESSION_SECRET: "test",
      TURNSTILE_SITE_KEY: "sitekey-mock",
      TURNSTILE_SECRET_KEY: "secret-mock"
    });
    await store.createInviteCode({ code: "TURN-OK", maxUses: 10 });

    const mockFetch = async (url, opts) => {
      assert.equal(url.toString(), "https://challenges.cloudflare.com/turnstile/v0/siteverify");
      return new Response(JSON.stringify({ success: true }), {
        headers: { "content-type": "application/json" }
      });
    };
    const app = createApp({ store, config, turnstileFetch: mockFetch });

    const body = new FormData();
    body.set("client_id", "openai-client");
    body.set("redirect_uri", "https://auth.openai.com/oidc/callback");
    body.set("response_type", "code");
    body.set("scope", "openid email");
    body.set("state", "s");
    body.set("account", "turnuser@example.com");
    body.set("invite_code", "TURN-OK");
    body.set("cf-turnstile-response", "valid-response-token");

    const resp = await app.fetch(new Request("https://sso.example.com/login", {
      method: "POST", body
    }));
    assert.equal(resp.status, 302, `Expected redirect but got ${resp.status}: ${await resp.text()}`);
  });

  it("Turnstile：mock 返回验证失败时拒绝登录", async () => {
    const store = new MemoryStore();
    const config = loadConfig({
      ISSUER: "https://sso.example.com",
      OIDC_CLIENT_ID: "openai-client",
      OIDC_CLIENT_SECRET: "secret",
      ALLOWED_REDIRECT_URIS: "https://auth.openai.com/oidc/callback",
      ACCOUNT_DOMAIN: "",
      PRIVATE_JWK: JSON.stringify(privateJwk),
      ADMIN_TOKEN: "admin-token",
      SESSION_SECRET: "test",
      TURNSTILE_SITE_KEY: "sitekey-mock",
      TURNSTILE_SECRET_KEY: "secret-mock"
    });
    await store.createInviteCode({ code: "TURN-FAIL", maxUses: 10 });

    let mockCalled = false;
    const mockFetch = async () => {
      mockCalled = true;
      return new Response(
        JSON.stringify({ success: false }),
        { headers: { "content-type": "application/json" } }
      );
    };
    const app = createApp({ store, config, turnstileFetch: mockFetch });

    const body = new FormData();
    body.set("client_id", "openai-client");
    body.set("redirect_uri", "https://auth.openai.com/oidc/callback");
    body.set("response_type", "code");
    body.set("scope", "openid email");
    body.set("state", "s");
    body.set("account", "fuser@example.com");
    body.set("invite_code", "TURN-FAIL");
    body.set("cf-turnstile-response", "bad");

    const resp = await app.fetch(new Request("https://sso.example.com/register", {
      method: "POST", body
    }));
    assert.ok(mockCalled, "mock fetch should be called");
    // errorResponse 返回 400，嵌入式错误返回 200；两者都应该显示错误信息
    const text = await resp.text();
    assert.match(text, /人机验证失败/);
  });

  it("管理员登录后访问仪表盘", async () => {
    const { app, store } = createTestApp();
    const passwordHash = await hashPassword("Admin1234");
    await store.createUser({
      email: "admin@example.com",
      displayName: "超级管理员",
      passwordHash,
      isAdmin: true,
      emailVerified: true
    });

    const loginBody = new FormData();
    loginBody.set("account", "admin@example.com");
    loginBody.set("password", "Admin1234");
    loginBody.set("redirect", "/admin");

    const loginResp = await app.fetch(new Request("https://sso.example.com/admin-login", {
      method: "POST", body: loginBody
    }));
    assert.equal(loginResp.status, 302, `Expected redirect but got ${loginResp.status}: ${await loginResp.text()}`);
    assert.equal(loginResp.headers.get("location"), "/admin");

    const cookie = loginResp.headers.getSetCookie()[0];
    assert.ok(cookie, "should have set cookie");
    assert.match(cookie, /sso_session=/);

    const dashResp = await app.fetch(new Request("https://sso.example.com/admin", {
      headers: { cookie }
    }));
    assert.equal(dashResp.status, 200);
    const html = await dashResp.text();
    assert.match(html, /仪表盘/);
    assert.match(html, /总用户数/);
    assert.match(html, /admin@example\.com/);
  });

  it("404 页面返回友好错误", async () => {
    const { app } = createTestApp();
    const resp = await app.fetch(new Request("https://sso.example.com/not/exist"));
    assert.equal(resp.status, 404);
    assert.match(await resp.text(), /找不到页面/);
  });
});
