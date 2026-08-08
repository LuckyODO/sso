export function loadConfig(env = {}) {
  const issuer = requiredUrl(env.ISSUER, "ISSUER").replace(/\/+$/, "");
  const adminEmails = parseList(env.ADMIN_EMAILS);

  // PRIVATE_JWK 可能是 Cloudflare Dashboard 保存为 JSON 类型（object）
  const privateJwk = normalizePrivateJwk(env.PRIVATE_JWK);

  // SESSION_SECRET 优先，其次从其他密钥派生
  const sessionSecretRaw = env.SESSION_SECRET || env.ADMIN_TOKEN || privateJwk;
  const sessionSecret = sessionSecretRaw ? String(sessionSecretRaw).trim() : "";

  return {
    issuer,
    adminEmails,
    sessionSecret,
    privateJwk,
    adminToken: optional(env.ADMIN_TOKEN),
    turnstileSiteKey: optional(env.TURNSTILE_SITE_KEY),
    turnstileSecretKey: optional(env.TURNSTILE_SECRET_KEY),
    authorizationCodeTtlSeconds: Number(env.AUTHORIZATION_CODE_TTL_SECONDS ?? 300),
    tokenTtlSeconds: Number(env.TOKEN_TTL_SECONDS ?? 3600),
    sessionTtlSeconds: Number(env.SESSION_TTL_SECONDS ?? 86400 * 7),
    // 兼容 ACCOUNT_DOMAIN 和 DEFAULT_ACCOUNT_DOMAIN 两种命名
    defaultAccountDomain: optionalDomain(env.DEFAULT_ACCOUNT_DOMAIN || env.ACCOUNT_DOMAIN),
    // 向后兼容：单应用模式
    legacyClientId: optional(env.OIDC_CLIENT_ID),
    legacyClientSecret: optional(env.OIDC_CLIENT_SECRET),
    legacyRedirectUris: parseList(env.ALLOWED_REDIRECT_URIS),
    openaiLoginUrl: optional(env.OPENAI_LOGIN_URL),
  };
}

export function isAdminEmail(config, email) {
  if (!email) return false;
  const normalized = String(email).toLowerCase().trim();
  return config.adminEmails.some((admin) => admin.toLowerCase() === normalized);
}

function parseList(value) {
  return String(value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function optional(value) {
  return String(value ?? "").trim();
}

// PRIVATE_JWK 绑定在 Cloudflare Dashboard 可能是 JSON 类型（object），也可能是 plain text string
// - object: 直接 JSON.stringify 成标准字符串
// - string: trim 后原样返回
// - 其它: 返回 ""（视为未配置）
export function normalizePrivateJwk(value) {
  if (typeof value === "string") {
    return value.trim();
  }
  if (value && typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return "";
    }
  }
  return "";
}

function required(value, name) {
  const normalized = String(value ?? "").trim();
  if (!normalized) {
    throw new Error(`缺少必要設定：${name}`);
  }
  return normalized;
}

function requiredUrl(value, name) {
  const normalized = required(value, name);
  try {
    return new URL(normalized).toString();
  } catch {
    throw new Error(`${name} 必須是有效 URL`);
  }
}

function optionalUrl(value, name) {
  const normalized = optional(value);
  if (!normalized) {
    return "";
  }
  try {
    return new URL(normalized).toString();
  } catch {
    throw new Error(`${name} 必須是有效 URL`);
  }
}

function optionalDomain(value) {
  const normalized = optional(value);
  if (!normalized) return "";
  return normalized.toLowerCase().replace(/^@+/, "").replace(/\.+$/, "");
}
