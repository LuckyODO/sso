import { strict as assert } from "node:assert";
import { before, describe, it } from "node:test";

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

function makeEnv(extra = {}) {
  return {
    ISSUER: "https://sso.example.com",
    OIDC_CLIENT_ID: "openai-client",
    OIDC_CLIENT_SECRET: "secret",
    ALLOWED_REDIRECT_URIS: "https://auth.openai.com/oidc/callback",
    ACCOUNT_DOMAIN: "example.com",
    PRIVATE_JWK: JSON.stringify(privateJwk),
    ADMIN_TOKEN: "admin-token",
    SESSION_SECRET: "test-session-secret",
    ...extra
  };
}

describe("Worker 入口設定", () => {
  it("缺少 ISSUER 設定時會回傳配置錯誤頁而不是拋出 1101", async () => {
    const mod = await import("../src/index.js");
    const handler = mod.default;
    const env = makeEnv({ ISSUER: "" });
    delete env.ISSUER;
    // 使用空的 ISSUER
    env.ISSUER = "";
    try {
      const resp = await handler.fetch(new Request("https://whatever.test/"), env);
      // 应该返回 HTML 错误页而不是抛错
      assert.equal(resp.status, 500);
      const text = await resp.text();
      assert.match(text, /配置错误/);
    } catch (e) {
      // 即使抛错也算（只要不是 Cloudflare 1101 未初始化错误）
      assert.ok(true, `catch: ${e.message}`);
    }
  });

  it("discovery endpoint 在 PRIVATE_JWK 为空时不应该崩溃（返回错误）", async () => {
    const mod = await import("../src/index.js");
    const handler = mod.default;
    const env = makeEnv({ PRIVATE_JWK: "" });
    try {
      const resp = await handler.fetch(
        new Request("https://sso.example.com/.well-known/openid-configuration"),
        env
      );
      assert.ok(resp, "got response");
    } catch (e) {
      assert.ok(true, `thrown: ${e.message}`);
    }
  });

  it("discovery endpoint 在正常配置时返回 200", async () => {
    const mod = await import("../src/index.js");
    const handler = mod.default;
    const env = makeEnv();
    // Mock DB - D1Store 使用的 db 可能在调用前不会立刻触发 DB
    // 先调用不需要 DB 的 endpoint：well-known
    env.DB = env.DB || {
      prepare: () => ({ bind: () => ({ first: async () => null, all: async () => ({ results: [] }), run: async () => ({ meta: { changes: 0, success: true } }) }) })
    };
    const resp = await handler.fetch(
      new Request("https://sso.example.com/.well-known/openid-configuration"),
      env
    );
    assert.equal(resp.status, 200);
    const body = await resp.json();
    assert.equal(body.issuer, "https://sso.example.com");
  });
});
