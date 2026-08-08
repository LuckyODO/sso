import { randomUrlSafe } from "./crypto.js";

export const DEFAULT_DISPLAY_NAME = "User";

export function normalizeEmail(email) {
  const normalized = String(email ?? "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    throw new Error("请输入有效的电子邮件地址");
  }
  return normalized;
}

export function normalizeInviteCode(code) {
  const normalized = String(code ?? "").trim();
  if (!normalized) {
    throw new Error("请输入邀请码");
  }
  return normalized;
}

function normalizeDisplayName(displayName, email) {
  const normalized = String(displayName ?? "").trim();
  if (normalized) return normalized;
  if (email) return email.split("@")[0];
  return DEFAULT_DISPLAY_NAME;
}

function parseJsonOr(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

// ================ Memory Store ================
export class MemoryStore {
  constructor(now = () => new Date()) {
    this.now = now;
    this.users = new Map();
    this.userIdCounter = 1;
    this.inviteCodes = new Map();
    this.apps = new Map();
    this.appIdCounter = 1;
    this.sessions = new Map();
    this.authorizationCodes = new Map();
    this.auditLogs = [];
    this.auditLogIdCounter = 1;
    this.settings = new Map();
  }

  // ----- Schema (no-op for MemoryStore) -----
  async ensureSchema() {}

  // ----- Settings -----
  async getSetting(key) {
    return this.settings.get(String(key)) ?? null;
  }

  async setSetting(key, value) {
    this.settings.set(String(key), String(value));
  }

  // ----- Invite Codes -----
  async createInviteCode({ code, maxUses = 100, enabled = true, createdBy, expiresAt }) {
    const normalizedCode = normalizeInviteCode(code);
    const now = this.now().toISOString();
    const record = {
      code: normalizedCode,
      maxUses,
      usedCount: 0,
      enabled,
      createdBy: createdBy ?? null,
      createdAt: now,
      expiresAt: expiresAt ?? null,
    };
    this.inviteCodes.set(normalizedCode, record);
    return { ...record };
  }

  async getInviteCode(code) {
    const record = this.inviteCodes.get(normalizeInviteCode(code));
    return record ? { ...record } : null;
  }

  async listInviteCodes(limit = 100, offset = 0) {
    const arr = Array.from(this.inviteCodes.values()).slice(offset, offset + limit);
    return arr.map((r) => ({ ...r }));
  }

  async updateInviteCode(code, updates) {
    const normalized = normalizeInviteCode(code);
    const record = this.inviteCodes.get(normalized);
    if (!record) return null;
    if (updates.maxUses !== undefined) record.maxUses = Number(updates.maxUses);
    if (updates.enabled !== undefined) record.enabled = Boolean(updates.enabled);
    if (updates.expiresAt !== undefined) record.expiresAt = updates.expiresAt;
    return { ...record };
  }

  async deleteInviteCode(code) {
    return this.inviteCodes.delete(normalizeInviteCode(code));
  }

  // ----- Users -----
  async getUserByEmail(email) {
    const record = this.users.get(normalizeEmail(email));
    return record ? userToJson(record) : null;
  }

  async getUserById(id) {
    for (const record of this.users.values()) {
      if (record.id === Number(id)) return userToJson(record);
    }
    return null;
  }

  async listUsers(limit = 100, offset = 0) {
    const arr = Array.from(this.users.values()).slice(offset, offset + limit);
    return arr.map(userToJson);
  }

  async countUsers() {
    return this.users.size;
  }

  async createUser({ email, displayName, passwordHash, inviteCode, isAdmin = false, emailVerified = false }) {
    const normalizedEmail = normalizeEmail(email);
    if (this.users.has(normalizedEmail)) {
      throw new Error("用户已存在");
    }
    const now = this.now().toISOString();
    const record = {
      id: this.userIdCounter++,
      email: normalizedEmail,
      displayName: normalizeDisplayName(displayName, normalizedEmail),
      passwordHash: passwordHash ?? null,
      inviteCode: inviteCode ?? null,
      isAdmin: isAdmin ? 1 : 0,
      isActive: 1,
      emailVerified: emailVerified ? 1 : 0,
      createdAt: now,
      lastLoginAt: now,
    };
    this.users.set(normalizedEmail, record);
    return userToJson(record);
  }

  async createUserWithInvite({ email, displayName, passwordHash, inviteCode }) {
    const normalizedEmail = normalizeEmail(email);
    const normalizedCode = normalizeInviteCode(inviteCode);
    const existingUser = this.users.get(normalizedEmail);
    if (existingUser) {
      return { user: userToJson(existingUser), created: false };
    }

    const invite = this.inviteCodes.get(normalizedCode);
    if (!invite || !invite.enabled) {
      throw new Error("邀请码无效或已停用");
    }
    if (invite.expiresAt && new Date(invite.expiresAt).getTime() < this.now().getTime()) {
      throw new Error("邀请码已过期");
    }
    if (invite.usedCount >= invite.maxUses) {
      throw new Error("邀请码使用次数已达上限");
    }

    const now = this.now().toISOString();
    const user = {
      id: this.userIdCounter++,
      email: normalizedEmail,
      displayName: normalizeDisplayName(displayName, normalizedEmail),
      passwordHash: passwordHash ?? null,
      inviteCode: normalizedCode,
      isAdmin: 0,
      isActive: 1,
      emailVerified: 0,
      createdAt: now,
      lastLoginAt: now,
    };
    invite.usedCount += 1;
    this.users.set(normalizedEmail, user);
    return { user: userToJson(user), created: true };
  }

  async updateUser(email, updates) {
    const normalizedEmail = normalizeEmail(email);
    const record = this.users.get(normalizedEmail);
    if (!record) return null;
    if (updates.displayName !== undefined) record.displayName = normalizeDisplayName(updates.displayName, normalizedEmail);
    if (updates.passwordHash !== undefined) record.passwordHash = updates.passwordHash;
    if (updates.isAdmin !== undefined) record.isAdmin = updates.isAdmin ? 1 : 0;
    if (updates.isActive !== undefined) record.isActive = updates.isActive ? 1 : 0;
    if (updates.emailVerified !== undefined) record.emailVerified = updates.emailVerified ? 1 : 0;
    return userToJson(record);
  }

  async updateUserLogin(email) {
    const normalizedEmail = normalizeEmail(email);
    const user = this.users.get(normalizedEmail);
    if (!user) return null;
    user.lastLoginAt = this.now().toISOString();
    return userToJson(user);
  }

  async deleteUser(email) {
    return this.users.delete(normalizeEmail(email));
  }

  // ----- Apps -----
  async createApp({ clientId, clientSecret, name, description, logoUrl, redirectUris, scopes, isPublic = false, createdBy }) {
    const now = this.now().toISOString();
    const id = this.appIdCounter++;
    const record = {
      id,
      clientId,
      clientSecret,
      name,
      description: description ?? null,
      logoUrl: logoUrl ?? null,
      redirectUris: JSON.stringify(redirectUris),
      scopes: JSON.stringify(scopes ?? ["openid", "email", "profile"]),
      isActive: 1,
      isPublic: isPublic ? 1 : 0,
      createdBy: createdBy ?? null,
      createdAt: now,
      updatedAt: now,
    };
    this.apps.set(clientId, record);
    return appToJson(record);
  }

  async getAppByClientId(clientId) {
    const record = this.apps.get(String(clientId ?? ""));
    return record ? appToJson(record) : null;
  }

  async getAppById(id) {
    for (const record of this.apps.values()) {
      if (record.id === Number(id)) return appToJson(record);
    }
    return null;
  }

  async listApps(limit = 100, offset = 0) {
    const arr = Array.from(this.apps.values()).slice(offset, offset + limit);
    return arr.map(appToJson);
  }

  async countApps() {
    return this.apps.size;
  }

  async updateApp(clientId, updates) {
    const record = this.apps.get(String(clientId ?? ""));
    if (!record) return null;
    record.updatedAt = this.now().toISOString();
    if (updates.name !== undefined) record.name = updates.name;
    if (updates.description !== undefined) record.description = updates.description ?? null;
    if (updates.logoUrl !== undefined) record.logoUrl = updates.logoUrl ?? null;
    if (updates.clientSecret !== undefined) record.clientSecret = updates.clientSecret;
    if (updates.redirectUris !== undefined) record.redirectUris = JSON.stringify(updates.redirectUris);
    if (updates.scopes !== undefined) record.scopes = JSON.stringify(updates.scopes);
    if (updates.isActive !== undefined) record.isActive = updates.isActive ? 1 : 0;
    if (updates.isPublic !== undefined) record.isPublic = updates.isPublic ? 1 : 0;
    return appToJson(record);
  }

  async deleteApp(clientId) {
    return this.apps.delete(String(clientId ?? ""));
  }

  // ----- Sessions -----
  async createSession({ userId, email, userAgent, ipAddress, ttlSeconds = 86400 * 7 }) {
    const now = this.now();
    const token = randomUrlSafe(48);
    const record = {
      token,
      userId: Number(userId),
      email,
      userAgent: userAgent ?? null,
      ipAddress: ipAddress ?? null,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
      lastSeenAt: now.toISOString(),
    };
    this.sessions.set(token, record);
    return { ...record };
  }

  async getSession(token) {
    const record = this.sessions.get(String(token ?? ""));
    if (!record) return null;
    if (new Date(record.expiresAt).getTime() < this.now().getTime()) {
      this.sessions.delete(token);
      return null;
    }
    return { ...record };
  }

  async touchSession(token) {
    const record = this.sessions.get(String(token ?? ""));
    if (!record) return null;
    record.lastSeenAt = this.now().toISOString();
    return { ...record };
  }

  async deleteSession(token) {
    return this.sessions.delete(String(token ?? ""));
  }

  async listSessionsByUserId(userId, limit = 100) {
    const arr = [];
    for (const record of this.sessions.values()) {
      if (record.userId === Number(userId)) {
        arr.push({ ...record });
        if (arr.length >= limit) break;
      }
    }
    return arr;
  }

  async deleteSessionsByUserId(userId) {
    let count = 0;
    for (const [token, record] of this.sessions) {
      if (record.userId === Number(userId)) {
        this.sessions.delete(token);
        count++;
      }
    }
    return count;
  }

  // ----- Authorization Codes -----
  async saveAuthorizationCode(record) {
    this.authorizationCodes.set(record.code, { ...record });
    return { ...record };
  }

  async consumeAuthorizationCode(code) {
    const record = this.authorizationCodes.get(code);
    if (!record || record.usedAt) return null;
    const consumed = { ...record, usedAt: this.now().toISOString() };
    this.authorizationCodes.set(code, consumed);
    return consumed;
  }

  // ----- Audit Logs -----
  async addAuditLog({ userId, email, action, targetType, targetId, details, ipAddress, userAgent }) {
    const now = this.now().toISOString();
    const record = {
      id: this.auditLogIdCounter++,
      userId: userId ?? null,
      email: email ?? null,
      action,
      targetType: targetType ?? null,
      targetId: targetId ?? null,
      details: details ? JSON.stringify(details) : null,
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      createdAt: now,
    };
    this.auditLogs.push(record);
    return { ...record };
  }

  async listAuditLogs(limit = 100, offset = 0) {
    const arr = this.auditLogs
      .slice()
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .slice(offset, offset + limit);
    return arr.map((r) => ({ ...r, details: r.details ? parseJsonOr(r.details, null) : null }));
  }

  async countAuditLogs() {
    return this.auditLogs.length;
  }

  // ----- Stats -----
  async getStats() {
    const now = this.now().toISOString();
    const weekAgo = new Date(this.now().getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

    let activeUsers7d = 0;
    for (const u of this.users.values()) {
      if (u.lastLoginAt >= weekAgo) activeUsers7d++;
    }

    return {
      totalUsers: this.users.size,
      totalApps: this.apps.size,
      totalInviteCodes: this.inviteCodes.size,
      activeSessions: this.sessions.size,
      activeUsers7d,
      totalAuditLogs: this.auditLogs.length,
    };
  }
}

// ================ D1 Store ================
export class D1Store {
  constructor(db) {
    this.db = db;
  }

  // ----- Schema Auto-Init -----
  //
  // 设计目标：兼容以下历史部署状态：
  //   1) 全新 D1：无任何表 → 直接建表
  //   2) 旧的「邀请码 + 微软 AAD」时代：只有 users / invite_codes 等表，
  //      且 users 可能没有 id INTEGER PRIMARY KEY（email 直接当主键）
  //   3) 本仓库更近期版本：表已存在但缺少部分新增列
  //
  // 迁移策略（对每个需要 id INTEGER PRIMARY KEY 的表，即 users / apps / audit_logs）：
  //   A. PRAGMA table_info 取当前列；若 id 列不存在或不是 PK → 全表重建
  //      (ALTER old → new__tmp → INSERT ... SELECT → DROP old → RENAME new__tmp)
  //   B. 否则：CREATE TABLE IF NOT EXISTS 保证新表存在
  //   C. 对其余列逐列探测，缺失则 ALTER TABLE ADD
  //   D. 最后统一建索引
  async ensureSchema() {
    const ident = (s) => `"${String(s).replace(/[^a-zA-Z0-9_]/g, "_")}"`;

    // ---- 目标表定义（含要求的主键列） ----
    // requiresPkId: true 表示必须存在 id INTEGER PRIMARY KEY，否则需要重建
    const targetTables = [
      {
        name: "users",
        requiresPkId: true,
        createSql: `CREATE TABLE __new__ (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT UNIQUE NOT NULL,
          display_name TEXT NOT NULL,
          password_hash TEXT,
          invite_code TEXT,
          is_admin INTEGER NOT NULL DEFAULT 0,
          is_active INTEGER NOT NULL DEFAULT 1,
          email_verified INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          last_login_at TEXT NOT NULL
        )`,
        columns: {
          display_name: "TEXT NOT NULL DEFAULT 'User'",
          password_hash: "TEXT",
          invite_code: "TEXT",
          is_admin: "INTEGER NOT NULL DEFAULT 0",
          is_active: "INTEGER NOT NULL DEFAULT 1",
          email_verified: "INTEGER NOT NULL DEFAULT 0",
          created_at: "TEXT NOT NULL DEFAULT ''",
          last_login_at: "TEXT NOT NULL DEFAULT ''",
        },
        legacyDefaults: {
          // 用于重建时，如果旧行缺列，给一个合理的默认值，比列默认值更贴近语义
          display_name: (row) => row?.email ? String(row.email).split("@")[0] : "User",
          created_at: () => new Date(0).toISOString(),
          last_login_at: () => new Date(0).toISOString(),
        },
      },
      {
        name: "invite_codes",
        requiresPkId: false,
        createSql: `CREATE TABLE IF NOT EXISTS invite_codes (
          code TEXT PRIMARY KEY,
          max_uses INTEGER NOT NULL DEFAULT 100,
          used_count INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_by TEXT,
          created_at TEXT NOT NULL,
          expires_at TEXT
        )`,
        columns: {
          max_uses: "INTEGER NOT NULL DEFAULT 100",
          used_count: "INTEGER NOT NULL DEFAULT 0",
          enabled: "INTEGER NOT NULL DEFAULT 1",
          created_by: "TEXT",
          created_at: "TEXT NOT NULL DEFAULT ''",
          expires_at: "TEXT",
        },
      },
      {
        name: "apps",
        requiresPkId: true,
        createSql: `CREATE TABLE __new__ (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          client_id TEXT UNIQUE NOT NULL,
          client_secret TEXT NOT NULL,
          name TEXT NOT NULL,
          description TEXT,
          logo_url TEXT,
          redirect_uris TEXT NOT NULL,
          scopes TEXT NOT NULL DEFAULT '["openid","email","profile"]',
          is_active INTEGER NOT NULL DEFAULT 1,
          is_public INTEGER NOT NULL DEFAULT 0,
          created_by TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`,
        columns: {
          client_secret: "TEXT NOT NULL DEFAULT ''",
          name: "TEXT NOT NULL DEFAULT 'App'",
          description: "TEXT",
          logo_url: "TEXT",
          redirect_uris: "TEXT NOT NULL DEFAULT '[]'",
          scopes: "TEXT NOT NULL DEFAULT '[\"openid\",\"email\",\"profile\"]'",
          is_active: "INTEGER NOT NULL DEFAULT 1",
          is_public: "INTEGER NOT NULL DEFAULT 0",
          created_by: "TEXT",
          created_at: "TEXT NOT NULL DEFAULT ''",
          updated_at: "TEXT NOT NULL DEFAULT ''",
        },
        legacyDefaults: {
          created_at: () => new Date(0).toISOString(),
          updated_at: () => new Date(0).toISOString(),
        },
      },
      {
        name: "sessions",
        requiresPkId: false,
        createSql: `CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          email TEXT NOT NULL,
          user_agent TEXT,
          ip_address TEXT,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )`,
        columns: {
          user_id: "INTEGER NOT NULL DEFAULT 0",
          email: "TEXT NOT NULL DEFAULT ''",
          created_at: "TEXT NOT NULL DEFAULT ''",
          expires_at: "TEXT NOT NULL DEFAULT ''",
          last_seen_at: "TEXT NOT NULL DEFAULT ''",
          user_agent: "TEXT",
          ip_address: "TEXT",
        },
      },
      {
        name: "authorization_codes",
        requiresPkId: false,
        createSql: `CREATE TABLE IF NOT EXISTS authorization_codes (
          code TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          email TEXT NOT NULL,
          client_id TEXT NOT NULL,
          redirect_uri TEXT NOT NULL,
          scope TEXT NOT NULL,
          nonce TEXT,
          code_challenge TEXT,
          code_challenge_method TEXT,
          expires_at TEXT NOT NULL,
          used_at TEXT,
          created_at TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )`,
        columns: {
          user_id: "INTEGER NOT NULL DEFAULT 0",
          email: "TEXT NOT NULL DEFAULT ''",
          client_id: "TEXT NOT NULL DEFAULT ''",
          redirect_uri: "TEXT NOT NULL DEFAULT ''",
          scope: "TEXT NOT NULL DEFAULT ''",
          nonce: "TEXT",
          code_challenge: "TEXT",
          code_challenge_method: "TEXT",
          expires_at: "TEXT NOT NULL DEFAULT ''",
          used_at: "TEXT",
          created_at: "TEXT NOT NULL DEFAULT ''",
        },
      },
      {
        name: "audit_logs",
        requiresPkId: true,
        createSql: `CREATE TABLE __new__ (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          email TEXT,
          action TEXT NOT NULL,
          target_type TEXT,
          target_id TEXT,
          details TEXT,
          ip_address TEXT,
          user_agent TEXT,
          created_at TEXT NOT NULL
        )`,
        columns: {
          user_id: "INTEGER",
          email: "TEXT",
          action: "TEXT NOT NULL DEFAULT ''",
          target_type: "TEXT",
          target_id: "TEXT",
          details: "TEXT",
          ip_address: "TEXT",
          user_agent: "TEXT",
          created_at: "TEXT NOT NULL DEFAULT ''",
        },
        legacyDefaults: {
          created_at: () => new Date(0).toISOString(),
        },
      },
      {
        name: "settings",
        requiresPkId: false,
        createSql: `CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`,
        columns: {
          value: "TEXT NOT NULL DEFAULT ''",
          updated_at: "TEXT NOT NULL DEFAULT ''",
        },
      },
    ];

    // Phase A & B: 建表 / 重建表
    // 注意：当 env.DB 在测试中未绑定时，this.db 可能为 undefined，
    // 上层 index.js 会统一捕获并渲染配置错误页；这里仅作防御式保护。
    if (!this.db || typeof this.db.prepare !== "function") {
      throw new Error("D1 数据库绑定缺失。请在 Cloudflare Worker → Settings → D1 Database 绑定一个名称为 DB 的 D1 数据库。");
    }
    for (const t of targetTables) {
      if (t.requiresPkId) {
        await this._rebuildIfMissingPkId(t);
      } else {
        await this.db.prepare(t.createSql).run();
      }
    }

    // Phase C: ALTER TABLE 补齐缺失列（即使刚重建的表也幂等）
    for (const t of targetTables) {
      for (const [col, def] of Object.entries(t.columns)) {
        const alter = await this._maybeAlterAddColumn(t.name, col, def);
        if (!alter) continue;
        try {
          await this.db.prepare(alter).run();
        } catch (e) {
          if (!String(e.message || "").toLowerCase().includes("duplicate column")) throw e;
        }
      }
    }

    // Phase D: 索引
    const indexStatements = [
      `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
      `CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users(is_admin)`,
      `CREATE INDEX IF NOT EXISTS idx_invite_codes_code ON invite_codes(code)`,
      `CREATE INDEX IF NOT EXISTS idx_apps_client_id ON apps(client_id)`,
      `CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes(client_id)`,
      `CREATE INDEX IF NOT EXISTS idx_authorization_codes_email ON authorization_codes(email)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`,
    ];
    for (const sql of indexStatements) {
      try {
        await this.db.prepare(sql).run();
      } catch (e) {
        console.warn("create index skipped:", sql, e?.message ?? String(e));
      }
    }
  }

  // 对要求必须有 id INTEGER PRIMARY KEY 的表进行重建（如 users / apps / audit_logs）。
  // 重建规则：
  //   - 表不存在 → 直接 CREATE TABLE
  //   - 表存在但没有 id 列，或 id 列不是 INTEGER PRIMARY KEY → 重命名→建新→数据迁移→删旧→改回
  //   - 表存在且 id 是正确 PK → 跳过
  async _rebuildIfMissingPkId({ name, createSql, columns, legacyDefaults }) {
    const info = await this._pragmaTableInfo(name);
    if (info.length === 0) {
      // 表不存在：直接用真实表名创建
      const realCreate = createSql.replace("CREATE TABLE __new__", `CREATE TABLE IF NOT EXISTS "${name}"`);
      await this.db.prepare(realCreate).run();
      return;
    }
    const idCol = info.find((c) => String(c.name || "").toLowerCase() === "id");
    const idIsPk = !!idCol && idCol.pk === 1 && /int/i.test(String(idCol.type || ""));
    if (idIsPk) {
      return; // 正常，无需重建
    }

    const ident = (s) => `"${String(s).replace(/[^a-zA-Z0-9_]/g, "_")}"`;
    const tmpTable = `${name}__schema_migrate_tmp`;
    const nowStr = new Date().toISOString();

    // 1. 先删旧的临时表（上次崩溃残留）
    try { await this.db.prepare(`DROP TABLE IF EXISTS "${tmpTable}"`).run(); } catch {}

    // 2. 建新表到临时名
    const createTmp = createSql.replace("CREATE TABLE __new__", `CREATE TABLE "${tmpTable}"`);
    await this.db.prepare(createTmp).run();

    // 3. 复制旧数据
    //    旧表里有哪些列，我们能直接映射；没有的列用 legacyDefaults 或列默认值。
    const oldCols = info.map((c) => c.name);
    const newColDefs = [
      { name: "id" }, // 始终第一列，AUTOINCREMENT 会自动赋值（让我们传入 NULL）
      ...Object.keys(columns).map((n) => ({ name: n })),
    ];
    // 为了兼容极旧的场景（apps 可能 client_id 也缺等），我们先用 INSERT SELECT
    // 只选两边都存在的列，其它列用默认值。
    const shared = newColDefs
      .map((c) => c.name)
      .filter((n) => n !== "id" && oldCols.includes(n));
    // id 传 NULL 让 SQLite 自动编号
    const insertCols = ["id", ...shared];
    const selectExpr = ["NULL", ...shared.map((n) => ident(n))];
    try {
      await this.db
        .prepare(
          `INSERT INTO "${tmpTable}" (${insertCols.map(ident).join(", ")})
           SELECT ${selectExpr.join(", ")} FROM "${name}"`
        )
        .run();
    } catch (firstErr) {
      // 若共享列还不够（例如 NOT NULL 无默认值列在旧表缺失则直接 INSERT 失败），
      // 退化为逐行手动迁移并填充 legacyDefaults。
      console.warn(`rebuild ${name} shared-cols insert 失败，逐行迁移:`, firstErr?.message ?? String(firstErr));
      const oldRows = await this.db.prepare(`SELECT * FROM "${name}"`).all();
      const allNewCols = Object.keys(columns);
      const placeholders = ["?", ...allNewCols.map(() => "?")].join(", ");
      const stmt = this.db.prepare(
        `INSERT INTO "${tmpTable}" (id, ${allNewCols.map(ident).join(", ")}) VALUES (${placeholders})`
      );
      const rows = oldRows.results || oldRows;
      for (const r of rows) {
        const vals = [null]; // id
        for (const col of allNewCols) {
          let v = r[col];
          if (v === undefined || v === null) {
            const fn = legacyDefaults?.[col];
            if (typeof fn === "function") v = fn(r);
            else v = null;
          }
          // 列默认值兜底（NOT NULL 列要避免 NULL）
          const definition = columns[col] || "";
          if ((v === undefined || v === null) && /NOT NULL/i.test(definition)) {
            const m = /DEFAULT\s+('.*?'|\d+)/i.exec(definition);
            if (m) {
              const d = m[1];
              v = d.startsWith("'") ? d.slice(1, -1).replace(/''/g, "'") : Number(d);
            } else {
              v = /INTEGER/i.test(definition) ? 0 : /TEXT/i.test(definition) ? "" : null;
            }
          }
          vals.push(v);
        }
        try {
          await stmt.bind(...vals).run();
        } catch (rowErr) {
          console.error(`rebuild ${name} 跳过一行:`, rowErr?.message ?? String(rowErr));
        }
      }
    }

    // 4. 替换旧表
    await this.db.prepare(`DROP TABLE "${name}"`).run();
    await this.db.prepare(`ALTER TABLE "${tmpTable}" RENAME TO "${name}"`).run();
    console.warn(`rebuilt table ${name} (migrated ${info.length} legacy columns)`);
  }

  async _pragmaTableInfo(tableName) {
    const safe = String(tableName).replace(/[^a-zA-Z0-9_]/g, "_");
    try {
      const res = await this.db.prepare(`PRAGMA table_info("${safe}")`).all();
      return res.results || res || [];
    } catch {
      return [];
    }
  }

  // 返回 ALTER TABLE SQL（当列缺失时）；否则返回 null
  async _maybeAlterAddColumn(table, column, definition) {
    const ident = (s) => s.replace(/[^a-zA-Z0-9_]/g, "_");
    try {
      await this.db.prepare(`SELECT ${ident(column)} FROM ${ident(table)} LIMIT 0`).run();
      return null;
    } catch {
      return `ALTER TABLE "${ident(table)}" ADD COLUMN "${ident(column)}" ${definition}`;
    }
  }

  // ----- Settings -----
  async getSetting(key) {
    const row = await this.db.prepare("SELECT value FROM settings WHERE key = ?").bind(String(key)).first();
    return row && row.value !== undefined && row.value !== null ? String(row.value) : null;
  }

  async setSetting(key, value) {
    const now = new Date().toISOString();
    const safeValue = typeof value === "string" ? value : JSON.stringify(value);
    await this.db
      .prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
      .bind(String(key), safeValue, now)
      .run();
  }

  // ----- Invite Codes -----
  async createInviteCode({ code, maxUses = 100, enabled = true, createdBy, expiresAt }) {
    const normalizedCode = normalizeInviteCode(code);
    const now = new Date().toISOString();
    await this.db
      .prepare(
        `INSERT INTO invite_codes (code, max_uses, used_count, enabled, created_by, created_at, expires_at)
         VALUES (?, ?, 0, ?, ?, ?, ?)
         ON CONFLICT(code) DO UPDATE SET
           max_uses = excluded.max_uses,
           enabled = excluded.enabled,
           expires_at = excluded.expires_at`
      )
      .bind(
        normalizedCode,
        maxUses,
        enabled ? 1 : 0,
        createdBy ?? null,
        now,
        expiresAt ?? null
      )
      .run();
    return this.getInviteCode(normalizedCode);
  }

  async getInviteCode(code) {
    const row = await this.db
      .prepare(
        `SELECT code, max_uses, used_count, enabled, created_by, created_at, expires_at
         FROM invite_codes WHERE code = ?`
      )
      .bind(normalizeInviteCode(code))
      .first();
    return row ? inviteFromRow(row) : null;
  }

  async listInviteCodes(limit = 100, offset = 0) {
    const rows = await this.db
      .prepare(
        `SELECT code, max_uses, used_count, enabled, created_by, created_at, expires_at
         FROM invite_codes ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .bind(Number(limit), Number(offset))
      .all();
    return rows.results.map(inviteFromRow);
  }

  async updateInviteCode(code, updates) {
    const normalized = normalizeInviteCode(code);
    const existing = await this.getInviteCode(normalized);
    if (!existing) return null;
    const sets = [];
    const vals = [];
    if (updates.maxUses !== undefined) {
      sets.push("max_uses = ?");
      vals.push(Number(updates.maxUses));
    }
    if (updates.enabled !== undefined) {
      sets.push("enabled = ?");
      vals.push(updates.enabled ? 1 : 0);
    }
    if (updates.expiresAt !== undefined) {
      sets.push("expires_at = ?");
      vals.push(updates.expiresAt);
    }
    if (sets.length) {
      vals.push(normalized);
      await this.db.prepare(`UPDATE invite_codes SET ${sets.join(", ")} WHERE code = ?`).bind(...vals).run();
    }
    return this.getInviteCode(normalized);
  }

  async deleteInviteCode(code) {
    const result = await this.db.prepare("DELETE FROM invite_codes WHERE code = ?").bind(normalizeInviteCode(code)).run();
    return result.meta.changes > 0;
  }

  // ----- Users -----
  async getUserByEmail(email) {
    const row = await this.db
      .prepare(
        `SELECT id, email, display_name, password_hash, invite_code, is_admin, is_active,
                email_verified, created_at, last_login_at
         FROM users WHERE email = ?`
      )
      .bind(normalizeEmail(email))
      .first();
    return row ? userFromRow(row) : null;
  }

  async getUserById(id) {
    const row = await this.db
      .prepare(
        `SELECT id, email, display_name, password_hash, invite_code, is_admin, is_active,
                email_verified, created_at, last_login_at
         FROM users WHERE id = ?`
      )
      .bind(Number(id))
      .first();
    return row ? userFromRow(row) : null;
  }

  async listUsers(limit = 100, offset = 0) {
    const rows = await this.db
      .prepare(
        `SELECT id, email, display_name, password_hash, invite_code, is_admin, is_active,
                email_verified, created_at, last_login_at
         FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .bind(Number(limit), Number(offset))
      .all();
    return rows.results.map(userFromRow);
  }

  async countUsers() {
    const row = await this.db.prepare("SELECT COUNT(*) AS c FROM users").first();
    return row?.c ?? 0;
  }

  async createUser({ email, displayName, passwordHash, inviteCode, isAdmin = false, emailVerified = false }) {
    const normalizedEmail = normalizeEmail(email);
    const now = new Date().toISOString();
    const result = await this.db
      .prepare(
        `INSERT INTO users (email, display_name, password_hash, invite_code, is_admin, is_active,
                            email_verified, created_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)`
      )
      .bind(
        normalizedEmail,
        normalizeDisplayName(displayName, normalizedEmail),
        passwordHash ?? null,
        inviteCode ?? null,
        isAdmin ? 1 : 0,
        emailVerified ? 1 : 0,
        now,
        now
      )
      .run();
    if (!result.meta.success) throw new Error("创建用户失败");
    return this.getUserByEmail(normalizedEmail);
  }

  async createUserWithInvite({ email, displayName, passwordHash, inviteCode }) {
    const normalizedEmail = normalizeEmail(email);
    const normalizedCode = normalizeInviteCode(inviteCode);
    const existingUser = await this.getUserByEmail(normalizedEmail);
    if (existingUser) {
      return { user: existingUser, created: false };
    }

    const now = new Date().toISOString();
    const inviteUpdate = await this.db
      .prepare(
        `UPDATE invite_codes SET used_count = used_count + 1
         WHERE code = ? AND enabled = 1 AND used_count < max_uses
           AND (expires_at IS NULL OR expires_at > ?)`
      )
      .bind(normalizedCode, now)
      .run();
    if (inviteUpdate.meta.changes !== 1) {
      throw new Error("邀请码无效、过期或使用次数已达上限");
    }

    const insert = await this.db
      .prepare(
        `INSERT OR IGNORE INTO users (email, display_name, password_hash, invite_code, is_admin, is_active,
                                      email_verified, created_at, last_login_at)
         VALUES (?, ?, ?, ?, 0, 1, 0, ?, ?)`
      )
      .bind(
        normalizedEmail,
        normalizeDisplayName(displayName, normalizedEmail),
        passwordHash ?? null,
        normalizedCode,
        now,
        now
      )
      .run();

    if (insert.meta.changes === 1) {
      return { user: await this.getUserByEmail(normalizedEmail), created: true };
    }
    const user = await this.getUserByEmail(normalizedEmail);
    if (user) return { user, created: false };
    throw new Error("创建用户失败");
  }

  async updateUser(email, updates) {
    const normalizedEmail = normalizeEmail(email);
    const existing = await this.getUserByEmail(normalizedEmail);
    if (!existing) return null;
    const sets = [];
    const vals = [];
    if (updates.displayName !== undefined) {
      sets.push("display_name = ?");
      vals.push(normalizeDisplayName(updates.displayName, normalizedEmail));
    }
    if (updates.passwordHash !== undefined) {
      sets.push("password_hash = ?");
      vals.push(updates.passwordHash);
    }
    if (updates.isAdmin !== undefined) {
      sets.push("is_admin = ?");
      vals.push(updates.isAdmin ? 1 : 0);
    }
    if (updates.isActive !== undefined) {
      sets.push("is_active = ?");
      vals.push(updates.isActive ? 1 : 0);
    }
    if (updates.emailVerified !== undefined) {
      sets.push("email_verified = ?");
      vals.push(updates.emailVerified ? 1 : 0);
    }
    if (sets.length) {
      vals.push(normalizedEmail);
      await this.db.prepare(`UPDATE users SET ${sets.join(", ")} WHERE email = ?`).bind(...vals).run();
    }
    return this.getUserByEmail(normalizedEmail);
  }

  async updateUserLogin(email) {
    const normalizedEmail = normalizeEmail(email);
    const now = new Date().toISOString();
    await this.db.prepare("UPDATE users SET last_login_at = ? WHERE email = ?").bind(now, normalizedEmail).run();
    return this.getUserByEmail(normalizedEmail);
  }

  async deleteUser(email) {
    const result = await this.db.prepare("DELETE FROM users WHERE email = ?").bind(normalizeEmail(email)).run();
    return result.meta.changes > 0;
  }

  // ----- Apps -----
  async createApp({ clientId, clientSecret, name, description, logoUrl, redirectUris, scopes, isPublic = false, createdBy }) {
    const now = new Date().toISOString();
    await this.db
      .prepare(
        `INSERT INTO apps (client_id, client_secret, name, description, logo_url, redirect_uris,
                           scopes, is_active, is_public, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`
      )
      .bind(
        clientId,
        clientSecret,
        name,
        description ?? null,
        logoUrl ?? null,
        JSON.stringify(redirectUris),
        JSON.stringify(scopes ?? ["openid", "email", "profile"]),
        isPublic ? 1 : 0,
        createdBy ?? null,
        now,
        now
      )
      .run();
    return this.getAppByClientId(clientId);
  }

  async getAppByClientId(clientId) {
    const row = await this.db
      .prepare(
        `SELECT id, client_id, client_secret, name, description, logo_url, redirect_uris,
                scopes, is_active, is_public, created_by, created_at, updated_at
         FROM apps WHERE client_id = ?`
      )
      .bind(String(clientId ?? ""))
      .first();
    return row ? appFromRow(row) : null;
  }

  async getAppById(id) {
    const row = await this.db
      .prepare(
        `SELECT id, client_id, client_secret, name, description, logo_url, redirect_uris,
                scopes, is_active, is_public, created_by, created_at, updated_at
         FROM apps WHERE id = ?`
      )
      .bind(Number(id))
      .first();
    return row ? appFromRow(row) : null;
  }

  async listApps(limit = 100, offset = 0) {
    const rows = await this.db
      .prepare(
        `SELECT id, client_id, client_secret, name, description, logo_url, redirect_uris,
                scopes, is_active, is_public, created_by, created_at, updated_at
         FROM apps ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .bind(Number(limit), Number(offset))
      .all();
    return rows.results.map(appFromRow);
  }

  async countApps() {
    const row = await this.db.prepare("SELECT COUNT(*) AS c FROM apps").first();
    return row?.c ?? 0;
  }

  async updateApp(clientId, updates) {
    const existing = await this.getAppByClientId(clientId);
    if (!existing) return null;
    const sets = ["updated_at = ?"];
    const vals = [new Date().toISOString()];
    if (updates.name !== undefined) { sets.push("name = ?"); vals.push(updates.name); }
    if (updates.description !== undefined) { sets.push("description = ?"); vals.push(updates.description ?? null); }
    if (updates.logoUrl !== undefined) { sets.push("logo_url = ?"); vals.push(updates.logoUrl ?? null); }
    if (updates.clientSecret !== undefined) { sets.push("client_secret = ?"); vals.push(updates.clientSecret); }
    if (updates.redirectUris !== undefined) { sets.push("redirect_uris = ?"); vals.push(JSON.stringify(updates.redirectUris)); }
    if (updates.scopes !== undefined) { sets.push("scopes = ?"); vals.push(JSON.stringify(updates.scopes)); }
    if (updates.isActive !== undefined) { sets.push("is_active = ?"); vals.push(updates.isActive ? 1 : 0); }
    if (updates.isPublic !== undefined) { sets.push("is_public = ?"); vals.push(updates.isPublic ? 1 : 0); }
    vals.push(String(clientId ?? ""));
    await this.db.prepare(`UPDATE apps SET ${sets.join(", ")} WHERE client_id = ?`).bind(...vals).run();
    return this.getAppByClientId(clientId);
  }

  async deleteApp(clientId) {
    const result = await this.db.prepare("DELETE FROM apps WHERE client_id = ?").bind(String(clientId ?? "")).run();
    return result.meta.changes > 0;
  }

  // ----- Sessions -----
  async createSession({ userId, email, userAgent, ipAddress, ttlSeconds = 86400 * 7 }) {
    const now = new Date();
    const token = randomUrlSafe(48);
    await this.db
      .prepare(
        `INSERT INTO sessions (token, user_id, email, user_agent, ip_address, created_at, expires_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        token,
        Number(userId),
        email,
        userAgent ?? null,
        ipAddress ?? null,
        now.toISOString(),
        new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
        now.toISOString()
      )
      .run();
    return this.getSession(token);
  }

  async getSession(token) {
    const now = new Date().toISOString();
    const row = await this.db
      .prepare(
        `SELECT token, user_id, email, user_agent, ip_address, created_at, expires_at, last_seen_at
         FROM sessions WHERE token = ? AND expires_at > ?`
      )
      .bind(String(token ?? ""), now)
      .first();
    return row ? sessionFromRow(row) : null;
  }

  async touchSession(token) {
    const now = new Date().toISOString();
    await this.db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token = ?").bind(now, String(token ?? "")).run();
    return this.getSession(token);
  }

  async deleteSession(token) {
    const result = await this.db.prepare("DELETE FROM sessions WHERE token = ?").bind(String(token ?? "")).run();
    return result.meta.changes > 0;
  }

  async listSessionsByUserId(userId, limit = 100) {
    const rows = await this.db
      .prepare(
        `SELECT token, user_id, email, user_agent, ip_address, created_at, expires_at, last_seen_at
         FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC LIMIT ?`
      )
      .bind(Number(userId), Number(limit))
      .all();
    return rows.results.map(sessionFromRow);
  }

  async deleteSessionsByUserId(userId) {
    const result = await this.db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(Number(userId)).run();
    return result.meta.changes ?? 0;
  }

  // ----- Authorization Codes -----
  async saveAuthorizationCode(record) {
    await this.db
      .prepare(
        `INSERT INTO authorization_codes
          (code, user_id, email, client_id, redirect_uri, scope, nonce, code_challenge,
           code_challenge_method, expires_at, used_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`
      )
      .bind(
        record.code,
        Number(record.userId),
        record.email,
        record.clientId,
        record.redirectUri,
        record.scope,
        record.nonce ?? null,
        record.codeChallenge ?? null,
        record.codeChallengeMethod ?? null,
        record.expiresAt,
        record.createdAt
      )
      .run();
    return { ...record };
  }

  async consumeAuthorizationCode(code) {
    const now = new Date().toISOString();
    const row = await this.db
      .prepare(
        `SELECT code, user_id, email, client_id, redirect_uri, scope, nonce,
                code_challenge, code_challenge_method, expires_at, used_at, created_at
         FROM authorization_codes WHERE code = ?`
      )
      .bind(code)
      .first();
    if (!row || row.used_at) return null;
    await this.db
      .prepare("UPDATE authorization_codes SET used_at = ? WHERE code = ? AND used_at IS NULL")
      .bind(now, code)
      .run();
    return authorizationCodeFromRow({ ...row, used_at: now });
  }

  // ----- Audit Logs -----
  async addAuditLog({ userId, email, action, targetType, targetId, details, ipAddress, userAgent }) {
    const now = new Date().toISOString();
    const result = await this.db
      .prepare(
        `INSERT INTO audit_logs (user_id, email, action, target_type, target_id, details, ip_address, user_agent, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        userId ? Number(userId) : null,
        email ?? null,
        action,
        targetType ?? null,
        targetId ?? null,
        details ? JSON.stringify(details) : null,
        ipAddress ?? null,
        userAgent ?? null,
        now
      )
      .run();
    return { id: result.meta.lastRowId, userId, email, action, targetType, targetId, details, ipAddress, userAgent, createdAt: now };
  }

  async listAuditLogs(limit = 100, offset = 0) {
    const rows = await this.db
      .prepare(
        `SELECT id, user_id, email, action, target_type, target_id, details, ip_address, user_agent, created_at
         FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .bind(Number(limit), Number(offset))
      .all();
    return rows.results.map((r) => ({
      ...r,
      userId: r.user_id,
      targetType: r.target_type,
      targetId: r.target_id,
      details: r.details ? parseJsonOr(r.details, null) : null,
      ipAddress: r.ip_address,
      userAgent: r.user_agent,
      createdAt: r.created_at,
    }));
  }

  async countAuditLogs() {
    const row = await this.db.prepare("SELECT COUNT(*) AS c FROM audit_logs").first();
    return row?.c ?? 0;
  }

  // ----- Stats -----
  async getStats() {
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const [totalUsers, totalApps, totalInviteCodes, activeSessions, activeUsers7d, totalAuditLogs] = await Promise.all([
      this.countUsers(),
      this.countApps(),
      (async () => {
        const r = await this.db.prepare("SELECT COUNT(*) AS c FROM invite_codes").first();
        return r?.c ?? 0;
      })(),
      (async () => {
        const r = await this.db.prepare("SELECT COUNT(*) AS c FROM sessions WHERE expires_at > ?").bind(new Date().toISOString()).first();
        return r?.c ?? 0;
      })(),
      (async () => {
        const r = await this.db.prepare("SELECT COUNT(*) AS c FROM users WHERE last_login_at >= ?").bind(weekAgo).first();
        return r?.c ?? 0;
      })(),
      this.countAuditLogs(),
    ]);
    return { totalUsers, totalApps, totalInviteCodes, activeSessions, activeUsers7d, totalAuditLogs };
  }
}

// ================ Row Mappers ================
function userFromRow(row) {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    passwordHash: row.password_hash,
    inviteCode: row.invite_code,
    isAdmin: Boolean(row.is_admin),
    isActive: Boolean(row.is_active),
    emailVerified: Boolean(row.email_verified),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  };
}

function userToJson(record) {
  return {
    id: record.id,
    email: record.email,
    displayName: record.displayName,
    passwordHash: record.passwordHash,
    inviteCode: record.inviteCode,
    isAdmin: Boolean(record.isAdmin),
    isActive: Boolean(record.isActive),
    emailVerified: Boolean(record.emailVerified),
    createdAt: record.createdAt,
    lastLoginAt: record.lastLoginAt,
  };
}

function inviteFromRow(row) {
  return {
    code: row.code,
    maxUses: row.max_uses,
    usedCount: row.used_count,
    enabled: Boolean(row.enabled),
    createdBy: row.created_by,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

function appFromRow(row) {
  return {
    id: row.id,
    clientId: row.client_id,
    clientSecret: row.client_secret,
    name: row.name,
    description: row.description,
    logoUrl: row.logo_url,
    redirectUris: parseJsonOr(row.redirect_uris, []),
    scopes: parseJsonOr(row.scopes, ["openid", "email", "profile"]),
    isActive: Boolean(row.is_active),
    isPublic: Boolean(row.is_public),
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function appToJson(record) {
  return {
    id: record.id,
    clientId: record.clientId,
    clientSecret: record.clientSecret,
    name: record.name,
    description: record.description,
    logoUrl: record.logoUrl,
    redirectUris: parseJsonOr(record.redirectUris, []),
    scopes: parseJsonOr(record.scopes, ["openid", "email", "profile"]),
    isActive: Boolean(record.isActive),
    isPublic: Boolean(record.isPublic),
    createdBy: record.createdBy,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

function sessionFromRow(row) {
  return {
    token: row.token,
    userId: row.user_id,
    email: row.email,
    userAgent: row.user_agent,
    ipAddress: row.ip_address,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastSeenAt: row.last_seen_at,
  };
}

function authorizationCodeFromRow(row) {
  return {
    code: row.code,
    userId: row.user_id,
    email: row.email,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    scope: row.scope,
    nonce: row.nonce,
    codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
    createdAt: row.created_at,
  };
}
