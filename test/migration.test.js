// 针对真实 SQLite 的 schema 迁移测试
// 模拟生产环境：users 表存在但无 id 列（旧邀请码模式），验证 ensureSchema 能正确重建
import { DatabaseSync } from "node:sqlite";
import { strict as assert } from "node:assert";
import { D1Store } from "../src/store.js";

// 用 node:sqlite 模拟 D1 的最小子集
// 注意：D1 的 API 是 prepare(sql).bind(...vals).run() 链式调用，
// 而 node:sqlite 是 prepare(sql) 后直接 run(...vals) / get(...vals) / all(...vals)。
// 这里做适配：bind 捕获参数，run/get/all 时透传给 node:sqlite。
class SqliteAsD1 {
  constructor(db) { this.db = db; }
  prepare(sql) {
    const stmt = this.db.prepare(sql);
    const normalize = (v) => {
      if (typeof v === "number" && !Number.isFinite(v)) return null;
      if (typeof v === "bigint") return Number(v);
      return v;
    };
    return {
      bind(...args) {
        const vals = args.map(normalize);
        return {
          run: () => {
            const r = stmt.run(...vals);
            return { meta: { changes: r.changes ?? 0, success: true, lastRowId: r.lastInsertRowid ?? null } };
          },
          first: () => { const r = stmt.get(...vals); return r === undefined ? null : r; },
          all: () => ({ results: stmt.all(...vals) }),
        };
      },
      run: () => {
        const r = stmt.run();
        return { meta: { changes: r.changes ?? 0, success: true, lastRowId: r.lastInsertRowid ?? null } };
      },
      first: () => { const r = stmt.get(); return r === undefined ? null : r; },
      all: () => ({ results: stmt.all() }),
    };
  }
}

const tmpPath = ":memory:";
const rawDb = new DatabaseSync(tmpPath);
rawDb.exec(`
  -- 模拟生产环境：先关闭外键约束（旧表创建时 FK 未启用）
  PRAGMA foreign_keys = OFF;

  -- 旧版 users 表：email 当主键，没有 id / display_name / password_hash 等列
  CREATE TABLE users (
    email TEXT PRIMARY KEY,
    invite_code TEXT
  );
  INSERT INTO users (email, invite_code) VALUES ('alice@example.com','OLD-CODE-1');
  INSERT INTO users (email, invite_code) VALUES ('bob@example.com','OLD-CODE-2');

  -- 旧版 invite_codes 表（结构尚可）
  CREATE TABLE invite_codes (code TEXT PRIMARY KEY, used_count INTEGER NOT NULL DEFAULT 0);

  -- 故意留一个空 apps 表（无 id 列，无任何业务列）
  CREATE TABLE apps (client_id TEXT PRIMARY KEY);

  -- 旧版 sessions 表：FK 定义存在但因 users 无 id 列而被忽略，
  -- user_id 存的是旧的隐式 rowid（重建后会变成孤立引用）
  CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  -- 插入一条引用 user_id=999 的会话（users 重建后这个 id 不存在）
  INSERT INTO sessions (token, user_id, email, created_at, expires_at, last_seen_at)
    VALUES ('stale-token', 999, 'ghost@example.com', '2020-01-01T00:00:00Z', '2099-01-01T00:00:00Z', '2020-01-01T00:00:00Z');

  -- 现在开启外键约束（模拟 D1 默认行为，后续 ensureSchema 会遇到 FK 报错）
  PRAGMA foreign_keys = ON;
`);
const d1 = new SqliteAsD1(rawDb);
const store = new D1Store(d1);

await store.ensureSchema();

// 验证 users 表已重建并带 id INTEGER PRIMARY KEY
const usersCols = rawDb.prepare("PRAGMA table_info(users)").all().map((c) => c.name);
assert.ok(usersCols.includes("id"), "users 表现在有 id 列");
assert.ok(usersCols.includes("display_name"), "users 表有 display_name");
assert.ok(usersCols.includes("password_hash"), "users 表有 password_hash");
assert.ok(usersCols.includes("is_admin"), "users 表有 is_admin");

// 验证 id 是主键
const idCol = rawDb.prepare("PRAGMA table_info(users)").all().find((c) => c.name === "id");
assert.equal(idCol.pk, 1, "id 是主键");

// 验证旧数据已迁移
// 注意：批量 INSERT SELECT 时，旧表没有的列用列 DEFAULT 填充（display_name → 'User'），
// 而 legacyDefaults（email 前缀兜底）只在逐行迁移退化路径中生效。
const alice = rawDb.prepare("SELECT id, email, display_name, invite_code, is_admin FROM users WHERE email='alice@example.com'").get();
assert.ok(alice && typeof alice.id === "number" && alice.id > 0, "alice 有新 id");
assert.equal(alice.invite_code, "OLD-CODE-1", "alice 的旧 invite_code 保留");
assert.equal(alice.display_name, "User", "display_name 用列 DEFAULT 'User' 填充");
assert.equal(alice.is_admin, 0, "is_admin 默认 0");

const bob = rawDb.prepare("SELECT id, email FROM users WHERE email='bob@example.com'").get();
assert.ok(bob && bob.id > alice.id, "bob 的 id 自增");

// 验证 apps 表也重建了
const appsCols = rawDb.prepare("PRAGMA table_info(apps)").all().map((c) => c.name);
assert.ok(appsCols.includes("id") && appsCols.includes("client_secret") && appsCols.includes("redirect_uris"), "apps 表重建");

// 验证 createUser / getUserByEmail 可用
const newUser = await store.createUser({ email: "carol@example.com", displayName: "Carol", passwordHash: "h", isAdmin: false });
assert.ok(newUser.id > 0, "createUser 返回带 id 的用户");
const fetched = await store.getUserByEmail("carol@example.com");
assert.equal(fetched.email, "carol@example.com");

// 验证可重复执行（幂等）
await store.ensureSchema();
const alice2 = rawDb.prepare("SELECT id, email FROM users WHERE email='alice@example.com'").get();
assert.equal(alice2.id, alice.id, "再次迁移不丢数据、id 不变");

// 验证孤立会话已被清理（user_id=999 不存在于新 users 表）
const staleSession = rawDb.prepare("SELECT token FROM sessions WHERE token='stale-token'").get();
assert.equal(staleSession, undefined, "孤立会话（user_id 不存在）已被清理");

console.log("✅ 真实 SQLite 迁移测试通过（旧 users 表无 id → 重建并迁移数据 + 清理孤立会话）");
rawDb.close();
