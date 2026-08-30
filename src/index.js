import { createApp } from "./app.js";
import { loadConfig, normalizePrivateJwk } from "./config.js";
import { D1Store } from "./store.js";

// 进程级缓存：避免每次请求都从 D1 读密钥
let cachedPrivateJwk = null;
let cachedSessionSecret = null;

export default {
  async fetch(request, env) {
    try {
      const store = new D1Store(env.DB);

      // 自动生成 PRIVATE_JWK：优先用环境变量（支持 Cloudflare json/plain_text 两种绑定），其次进程缓存，否则从 D1 读取或生成
      let privateJwk = normalizePrivateJwk(env.PRIVATE_JWK);
      if (!privateJwk) privateJwk = cachedPrivateJwk;
      if (!privateJwk) {
        const fromDb = await store.getSetting("private_jwk");
        privateJwk = isValidJwkStr(fromDb) ? fromDb : null;
      }
      if (!privateJwk) {
        privateJwk = await generatePrivateJwk();
        try { await store.setSetting("private_jwk", privateJwk); } catch {}
      }
      cachedPrivateJwk = privateJwk;

      // SESSION_SECRET：同样的优先级
      let sessionSecret = optionalStr(env.SESSION_SECRET);
      if (!sessionSecret) sessionSecret = cachedSessionSecret;
      if (!sessionSecret) {
        const fromDb = await store.getSetting("session_secret");
        sessionSecret = fromDb && String(fromDb).trim().length >= 16 ? fromDb : null;
      }
      if (!sessionSecret) {
        sessionSecret = await generateSessionSecret();
        try { await store.setSetting("session_secret", sessionSecret); } catch {}
      }
      cachedSessionSecret = sessionSecret;

      // 构造 config input：env + 自动生成的字段
      // 注意：Cloudflare Worker env 是只读 Proxy，这里用展开拷贝成 plain object
      const configEnv = {
        ...Object.fromEntries(Object.keys(env).map((k) => [k, env[k]])),
        PRIVATE_JWK: privateJwk,
        SESSION_SECRET: sessionSecret,
      };

      const app = createApp({
        store,
        config: loadConfig(configEnv),
        env: configEnv,
      });
      return await app.fetch(request);
    } catch (error) {
      console.error("Worker 初始化失败", {
        message: getErrorMessage(error),
        stack: error && error.stack ? error.stack : undefined,
      });
      return configErrorResponse(error);
    }
  }
};

function isValidJwkStr(value) {
  if (!value || typeof value !== "string") return false;
  try {
    const jwk = JSON.parse(value.trim());
    return jwk && jwk.kty === "RSA" && jwk.kid && jwk.d && jwk.n;
  } catch {
    return false;
  }
}

async function generatePrivateJwk() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  jwk.kid = "auto-generated";
  jwk.alg = "RS256";
  jwk.use = "sig";
  return JSON.stringify(jwk);
}

async function generateSessionSecret() {
  const buf = new Uint8Array(48);
  crypto.getRandomValues(buf);
  return btoa(String.fromCharCode(...buf));
}

function optionalStr(value) {
  return String(value ?? "").trim();
}

function configErrorResponse(error) {
  const message = getErrorMessage(error);
  return new Response(
    `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>配置错误</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #f8fafc;
      color: #0f172a;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      padding: 20px;
      box-sizing: border-box;
    }
    main {
      width: min(520px, 100%);
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 32px;
      box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.08);
    }
    h1 {
      margin: 0 0 12px;
      font-size: 22px;
      color: #dc2626;
    }
    p {
      margin: 0;
      color: #475569;
      line-height: 1.6;
    }
    code {
      background: #f1f5f9;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.9em;
    }
  </style>
</head>
<body>
  <main>
    <h1>配置错误</h1>
    <p>${escapeHtml(message)}</p>
    <p style="margin-top:16px;font-size:0.875rem;color:#94a3b8">
      请检查 Cloudflare Worker → Settings → Variables and Secrets 中的环境变量配置。
      必需变量：<code>ISSUER</code>、<code>ADMIN_EMAILS</code>。
      <code>PRIVATE_JWK</code> 和 <code>SESSION_SECRET</code> 如未设置将自动生成。
    </p>
  </main>
</body>
</html>`,
    {
      status: 500,
      headers: { "content-type": "text/html; charset=utf-8" }
    }
  );
}

function getErrorMessage(error) {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  if (typeof error === "string" && error.trim()) {
    return error;
  }
  return "Worker 初始化失败";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
