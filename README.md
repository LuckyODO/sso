# Cloudflare Workers SSO 授权登录系统

这是一个部署在 Cloudflare Workers 上的 **完整 OIDC SSO 授权服务**，支持多应用（多 OIDC 客户端）、密码认证、邀请码注册、管理员控制台、会话管理和审计日志。

## 功能

### 🔐 OIDC 协议
- `/.well-known/openid-configuration` —— OIDC Discovery 端点
- `/jwks.json` —— JWKS 公钥集端点（RS256）
- `/authorize` —— 授权端点（Authorization Code Flow）
- `/token` —— Token 端点（换取 access_token / id_token）
- `/userinfo` —— UserInfo 端点（读取已登录用户信息）
- 支持 PKCE（`code_challenge` / `code_challenge_method`）

### 👥 用户体系
- **密码 + 邮箱**登录注册（PBKDF2 哈希，兼容邀请码模式）
- **邀请码模式**：新用户凭邀请码建立账号
- 完整邮箱或短账号（`ACCOUNT_DOMAIN` 自动补尾缀）两种输入方式
- 账号启用/停用标记、邮箱校验状态

### 🧩 多应用（多 OIDC 客户端）
- 一个 SSO 服务对接 **多个应用**（如 OpenAI、内部系统等）
- 每个应用独立的 client_id / client_secret / redirect_uris
- 支持 Public / Confidential 两种客户端类型
- 可随时启用/停用某个应用

### 🖥 管理员 Web 控制台 `/admin`
- **仪表盘**：总用户数、应用数、邀请码、活跃会话、审计事件统计
- **用户管理**：创建、编辑、停用/启用、设为管理员、重置密码
- **应用管理**：新建、编辑、启用/停用、查看/重置 client_secret、redirect_uris 配置
- **邀请码管理**：生成、停用、查看使用次数、设置过期
- **审计日志**：登录、注册、管理员操作完整记录
- Session Cookie 登录，无需每次调用 API token

### 🔒 安全
- 密码使用 PBKDF2-HMAC-SHA256 加盐哈希（12 万次迭代）
- Cookie Session：HttpOnly / SameSite=Lax / Secure / 自动过期
- Cloudflare Turnstile 人机验证开关式接入
- 会话独立存储，可在后台强制登出
- OIDC 授权码 5 分钟过期，token 默认 1 小时

## 快速部署

推荐使用 **Cloudflare Dashboard + GitHub 自动部署**。仓库中的 `wrangler.toml` 只保留安全占位：
- `keep_vars = true` —— 不覆盖 Dashboard 里的变量
- 不包含 `[vars]` 与正式 `database_id`

### 1. 建立 D1 Database 并初始化表

1. Cloudflare Dashboard → **Storage & Databases → D1** → **Create database**
2. 建议命名：`openai_oidc_sso`
3. 复制 `database_id`，稍后在构建变量中使用
4. 打开 **Console**，粘贴仓库中的 [schema.sql](schema.sql) 全部内容并执行
5. 确认表已创建：`users`, `invite_codes`, `authorization_codes`, `apps`, `sessions`, `audit_logs`

### 2. 连接 GitHub 仓库并配置部署命令

1. 在 **Workers & Pages → Create application** 导入本仓库
2. 进入 Worker 的 **Settings → Builds**，确保：

| 字段 | 值 |
| --- | --- |
| Root directory | `/`（或留空） |
| Build command | 留空 |
| Deploy command | `npm run deploy` |
| Version command | `npm run deploy:version` |

### 3. 配置 Build Variables

在 **Settings → Builds → Variables and Secrets** 中填写：

| 名称 | 必填 | 说明 |
| --- | --- | --- |
| `D1_DATABASE_ID` | ✅ | 刚建立的 D1 database id |
| `D1_DATABASE_NAME` | ❌ | D1 名称，默认 `openai_oidc_sso` |
| `WORKER_NAME` | ❌ | Worker 名称，默认 `sso` |

### 4. 配置 Runtime Variables & Secrets

进入 Worker **Settings → Variables and Secrets**：

| 名称 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `ISSUER` | Text | ✅ | Worker 对外 HTTPS URL，如 `https://auth.example.com`（不要 `/` 结尾） |
| `ADMIN_EMAILS` | Text | ✅ | 管理员邮箱，多值用逗号分隔。登录后直接进控制台 |
| `SESSION_SECRET` | Secret | ✅ | 会话签名密钥。建议随机字符串 ≥ 32 字节 |
| `PRIVATE_JWK` | Secret | ✅ | RS256 私钥 JWK（单行 JSON，含 `kid`） |
| `SESSION_TTL_SECONDS` | Text | ❌ | 会话有效期（秒），默认 `604800`（7 天） |
| `TOKEN_TTL_SECONDS` | Text | ❌ | Token 有效期，默认 `3600`（1 小时） |
| `AUTHORIZATION_CODE_TTL_SECONDS` | Text | ❌ | 授权码有效期，默认 `300`（5 分钟） |
| `DEFAULT_ACCOUNT_DOMAIN` | Text | ❌ | 未填完整邮箱时自动补的域名，如 `example.com` |
| `TURNSTILE_SITE_KEY` | Text | ❌ | Turnstile 前端 Site Key |
| `TURNSTILE_SECRET_KEY` | Secret | ❌ | Turnstile 后端 Secret Key |
| `ADMIN_TOKEN` | Secret | ❌ | 用于 legacy API `/admin/invite-codes`（不推荐） |

#### 向后兼容（单应用模式）

如果你只需要对接一个应用（比如 OpenAI），可以使用 legacy 环境变量直接启动，而不必先建 admin 记录：

| 名称 | 类型 | 说明 |
| --- | --- | --- |
| `OIDC_CLIENT_ID` | Text | 单应用 client_id |
| `OIDC_CLIENT_SECRET` | Secret | 单应用 client_secret |
| `ALLOWED_REDIRECT_URIS` | Text | 允许的 callback URL，多个逗号分隔 |
| `OPENAI_LOGIN_URL` | Text | 访问 `/` 时的跳转地址（Tile URL） |

### 5. 生成 RS256 私钥 JWK

本机 Node 运行：

```bash
node -e "crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(j=>{j.kid='sso-key';j.alg='RS256';j.use='sig';console.log(JSON.stringify(j))})"
```

把输出整段 JSON 粘贴到 `PRIVATE_JWK` Secret（**保持单行**）。

### 6. 自定义域名

1. **Settings → Domains & Routes → Add Custom Domain**：绑定如 `auth.example.com`
2. 把 `ISSUER` 更新成正式域名（无 `/` 结尾）
3. 重新部署

### 7. 建立第一位管理员

在 Dashboard 绑定的 D1 Console 中执行：

```sql
-- 先插入一个管理员用户（密码稍后在 Web 上改也可以）
INSERT INTO users (email, display_name, is_admin, is_active, email_verified, created_at, last_login_at)
VALUES ('you@example.com', '超级管理员', 1, 1, 1, datetime('now'), datetime('now'));
```

或者直接在 `/register` 页面凭邀请码注册一个账号，然后把 `you@example.com` 填到 `ADMIN_EMAILS` 环境变量里并重新部署。

### 8. 建立第一个 SSO 应用

1. 登录 `https://你的域名/admin-login`
2. 进入 **应用** 标签 → **新建应用**
3. 填写：
   - 应用名称（如 `OpenAI`）
   - Client ID（如 `openai-client`）
   - Client Secret（建议用系统生成的随机值）
   - Redirect URIs：粘贴上游（OpenAI）后台的 callback URL，每行一个
   - Scope 默认：`openid email profile`
4. 保存后，你会在应用详情看到 client_secret。把这些信息连同下面的端点配置到上游。

## 典型上游对接端点

| 字段 | 值 |
| --- | --- |
| Issuer | `https://你的域名` |
| Authorization endpoint | `https://你的域名/authorize` |
| Token endpoint | `https://你的域名/token` |
| JWKS URI | `https://你的域名/jwks.json` |
| UserInfo endpoint | `https://你的域名/userinfo` |

## 管理员控制台功能

访问 `https://你的域名/admin`，必须是 `ADMIN_EMAILS` 中列出的邮箱或 `users.is_admin=1` 的用户登录后才可进入。

### 仪表盘
- 总用户数 / 7 日活跃
- 应用数量、邀请码数量
- 活跃会话、审计事件统计

### 用户管理 `/admin/users`
- 新建用户（可指定是否管理员、设置密码）
- 编辑用户：昵称、邮箱、启用/停用、设为管理员
- 重置密码（生成临时密码并展示）
- 查看用户注册时间、最后登录时间

### 应用管理 `/admin/apps`
- 新建 OIDC 客户端：名称 / client_id / client_secret / redirect_uris / scopes
- 编辑客户端：启用/停用、修改 redirect_uris / scopes
- 重置 client_secret（展示新值）
- Public 客户端（不需要 client_secret 认证 token 端点）

### 邀请码管理 `/admin/invite-codes`
- 新建邀请码：自定义或系统生成，支持使用次数上限 / 过期时间
- 启用/停用、查看已用次数 / 剩余次数
- 删除邀请码

### 审计日志 `/admin/logs`
- 所有关键动作的时间线：user.login / user.register / app.create / user.toggle_admin 等
- 按操作者筛选

## Turnstile 人机验证

同时设置 `TURNSTILE_SITE_KEY` 与 `TURNSTILE_SECRET_KEY` 即自动启用登录/注册页的 Turnstile 验证。任一为空会在验证阶段报错。

## 本地开发与测试

```bash
# 安装（仅 wrangler 依赖）
npm install

# 运行全部 38 个测试
npm test

# 语法检查
npm run check
```

## 部署后快速自检

依次打开：
1. `https://你的域名/.well-known/openid-configuration` —— 应显示 JSON
2. `https://你的域名/jwks.json` —— 应显示 JWK Set
3. `https://你的域名/admin-login` —— 应显示管理员登录页
4. 登录管理员后访问 `/admin` —— 应显示仪表盘

## 常见问题

| 症状 | 排查 |
| --- | --- |
| D1 binding `DB` references `00000000...` | 部署命令仍用 `npx wrangler deploy`；请改为 `npm run deploy`，并确认 Build variable `D1_DATABASE_ID` 正确 |
| `缺少必要配置：PRIVATE_JWK` | Secret 未填或尚未重新部署新版本 |
| `/authorize` 报「未知的 OIDC 客户端」 | 未在 **应用管理** 里创建，或未在环境变量中设置 `OIDC_CLIENT_ID`（legacy） |
| `/authorize` 报「不允许的 redirect_uri」 | 应用里的 Redirect URIs 没有包含当前请求值 |
| 登录报「缺少 TURNSTILE_SECRET_KEY 配置」 | 只填了 Site Key 没填 Secret Key |

## 技术栈

- Cloudflare **Workers**（serverless runtime）
- Cloudflare **D1**（SQLite）
- Node 原生 `WebCrypto`（PBKDF2、RSASSA-PKCS1-v1_5 JWT/JWKS）
- 纯 Vanilla JS HTML 渲染（无前端框架，直接在 Worker 里输出）
- 全部 38 个单元测试用 Node `node:test` 运行（无需额外框架）
