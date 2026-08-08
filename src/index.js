import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { D1Store } from "./store.js";

export default {
  async fetch(request, env) {
    try {
      const store = new D1Store(env.DB);

      // 自动建表（幂等，已存在则跳过）
      await store.ensureSchema();

      // 自动生成 PRIVATE_JWK：优先用环境变量，否则从 D1 读取，都没有就生成一个
      let privateJwk = optionalStr(env.PRIVATE_JWK);
      if (!privateJwk) {
        privateJwk = await store.getSetting("private_jwk");
        if (!privateJwk) {
          privateJwk = await generatePrivateJwk();
          await store.setSetting("private_jwk", privateJwk);
        }
        // 把自动生成的 JWK 注入 env，让 loadConfig 能读到
        env.PRIVATE_JWK = privateJwk;
      }

      const app = createApp({
        store,
        config: loadConfig(env),
        env: env,
      });
      return await app.fetch(request);
    } catch (error) {
      console.error("Worker 初始化失败", {
        message: getErrorMessage(error)
      });
      return configErrorResponse(error);
    }
  }
};

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
