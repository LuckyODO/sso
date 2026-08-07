// src/microsoft.js
import { signJwt } from "./crypto.js";

// 从环境变量读取微软配置
function getMicrosoftConfig(env) {
  return {
    clientId: env.MICROSOFT_CLIENT_ID || "e94e6c36-5fe2-4617-b918-e93cc0125b33",
    clientSecret: env.MICROSOFT_CLIENT_SECRET || "",
    tenantId: env.MICROSOFT_TENANT_ID || "b3d47cd3-2f3f-487b-9fee-9b415566acb4",
    redirectUri: env.MICROSOFT_REDIRECT_URI || "https://sso.catfix.top/auth/microsoft/callback",
    scope: "openid email profile",
  };
}

// 第一步：跳转到微软登录页
export function handleMicrosoftLogin(env) {
  const config = getMicrosoftConfig(env);
  const authUrl = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/authorize?` +
    `client_id=${config.clientId}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(config.redirectUri)}` +
    `&scope=${encodeURIComponent(config.scope)}` +
    `&response_mode=query`;

  return Response.redirect(authUrl, 302);
}

// 第二步：微软回调，换取用户信息
export async function handleMicrosoftCallback(request, env) {
  const config = getMicrosoftConfig(env);
  const url = new URL(request.url);
  const code = url.searchParams.get("code");

  if (!code) {
    return new Response("缺少授权码", { status: 400 });
  }

  // 用 code 换 token
  const tokenResponse = await fetch(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code: code,
      redirect_uri: config.redirectUri,
      grant_type: "authorization_code",
    }),
  });

  const tokenData = await tokenResponse.json();

  if (!tokenData.access_token) {
    console.error("Token exchange failed:", tokenData);
    return new Response("登录失败，请重试", { status: 400 });
  }

  // 获取用户信息
  const userResponse = await fetch("https://graph.microsoft.com/v1.0/me", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });

  const userData = await userResponse.json();

  const email = userData.mail || userData.userPrincipalName;

  if (!email) {
    return new Response("无法获取用户邮箱", { status: 400 });
  }

  // 查找或创建用户
  let user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();

  if (!user) {
    const username = email.split("@")[0];
    const result = await env.DB.prepare(
      `INSERT INTO users (username, email, password_hash, invited_by, created_at)
       VALUES (?, ?, ?, ?, datetime('now'))`
    ).bind(username, email, null, null).run();

    const userId = result.meta?.last_row_id;
    user = {
      id: userId,
      username: username,
      email: email,
    };
  }

  // 生成 id_token
  const displayName = userData.displayName || user.username;
  const issuer = env.ISSUER || "https://sso.catfix.top";
  const clientId = env.OIDC_CLIENT_ID || "my-app";

  if (!env.PRIVATE_JWK) {
    console.error("PRIVATE_JWK 未设置");
    return new Response("服务器配置错误", { status: 500 });
  }
  const privateJwk = JSON.parse(env.PRIVATE_JWK);

  const idToken = await signJwt({
    privateJwk: privateJwk,
    claims: {
      sub: String(user.id),
      email: user.email,
      name: displayName,
      iss: issuer,
      aud: clientId,
    },
    ttlSeconds: 3600,
  });

  const openaiLoginUrl = env.OPENAI_LOGIN_URL || "https://pan.catfix.top";
  const redirectUrl = new URL(openaiLoginUrl);
  redirectUrl.searchParams.set("id_token", idToken);

  return Response.redirect(redirectUrl.toString(), 302);
}