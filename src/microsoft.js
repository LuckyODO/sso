// src/microsoft.js
import { signJwt } from "./crypto.js";

function getMicrosoftConfig(env) {
  return {
    clientId: env.MICROSOFT_CLIENT_ID || "e94e6c36-5fe2-4617-b918-e93cc0125b33",
    clientSecret: env.MICROSOFT_CLIENT_SECRET || "",
    tenantId: env.MICROSOFT_TENANT_ID || "b3d47cd3-2f3f-487b-9fee-9b415566acb4",
    redirectUri: env.MICROSOFT_REDIRECT_URI || "https://sso.catfix.top/auth/microsoft/callback",
    scope: "openid email profile",
  };
}

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

  // ========== 查找或创建用户 ==========
  // 直接使用 env.DB 操作
  let user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();

  if (!user) {
    // 检查 users 表结构，如果没有 display_name 则用 username
    const username = email.split("@")[0];
    const displayName = userData.displayName || username;
    
    // 先检查 invite_codes 是否有可用的邀请码，如果没有则创建一个
    let inviteCode = "microsoft-auto";
    
    // 尝试创建一个自动邀请码（如果表支持的话）
    try {
      // 先检查是否已有 microsoft-auto 邀请码
      const existingInvite = await env.DB.prepare(
        "SELECT code FROM invite_codes WHERE code = ?"
      ).bind(inviteCode).first();
      
      if (!existingInvite) {
        // 创建一个无限使用的邀请码
        await env.DB.prepare(
          `INSERT INTO invite_codes (code, max_uses, used_count, enabled, created_at)
           VALUES (?, 9999, 0, 1, datetime('now'))`
        ).bind(inviteCode).run();
      }
    } catch (e) {
      // 如果 invite_codes 表没有 created_at 字段，用简单方式
      console.log("邀请码创建跳过，直接插入用户");
    }

    // 插入用户，根据表结构调整字段
    try {
      // 先看 users 表有哪些字段
      const tableInfo = await env.DB.prepare("PRAGMA table_info(users)").all();
      const columns = tableInfo.results.map(r => r.name);
      
      let insertSql = "INSERT INTO users (";
      let placeholders = "";
      const values = [];
      
      if (columns.includes("email")) {
        insertSql += "email, ";
        values.push(email);
      }
      if (columns.includes("username")) {
        insertSql += "username, ";
        values.push(username);
      }
      if (columns.includes("display_name")) {
        insertSql += "display_name, ";
        values.push(displayName);
      }
      if (columns.includes("password_hash")) {
        insertSql += "password_hash, ";
        values.push(null);
      }
      if (columns.includes("invite_code") || columns.includes("invited_by")) {
        // 用 invite_code 字段
        if (columns.includes("invite_code")) {
          insertSql += "invite_code, ";
          values.push(inviteCode);
        }
      }
      if (columns.includes("created_at")) {
        insertSql += "created_at, ";
        values.push(new Date().toISOString());
      }
      if (columns.includes("last_login_at")) {
        insertSql += "last_login_at, ";
        values.push(new Date().toISOString());
      }
      
      // 去掉最后的逗号
      insertSql = insertSql.replace(/, $/, "");
      placeholders = values.map(() => "?").join(", ");
      insertSql += `) VALUES (${placeholders})`;
      
      await env.DB.prepare(insertSql).bind(...values).run();
      
    } catch (e) {
      console.error("创建用户失败:", e);
      // 尝试最简插入
      try {
        await env.DB.prepare(
          `INSERT INTO users (email, username, created_at)
           VALUES (?, ?, datetime('now'))`
        ).bind(email, username).run();
      } catch (e2) {
        console.error("最简插入也失败:", e2);
        return new Response("创建用户失败，请联系管理员", { status: 500 });
      }
    }

    // 重新查询用户
    user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  }

  if (!user) {
    return new Response("用户创建或查询失败", { status: 500 });
  }
  // =====================================

  // 生成 id_token
  const displayName = userData.displayName || user.username || user.display_name || email.split("@")[0];
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
      sub: String(user.id || user.email),
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