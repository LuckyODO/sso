import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { D1Store } from "./store.js";

export default {
  async fetch(request, env) {
    try {
      const app = createApp({
        store: new D1Store(env.DB),
        config: loadConfig(env),
        env: env  // ← 添加这一行，把 env 传给 createApp
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
      width: min(420px, 100%);
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
  </style>
</head>
<body>
  <main>
    <h1>配置错误</h1>
    <p>${escapeHtml(message)}</p>
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