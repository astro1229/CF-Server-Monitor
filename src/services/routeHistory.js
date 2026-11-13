// 路由探测历史：VPS 上的 route_detect.py 每小时推送一次，面板详情页读取展示。
// 与 metrics_history 分开存：数据量小（11 台 × 7 天 × 24 条 ≈ 1848 行），
// 不需要分区主键方案。
// 主键是 (server_id, timestamp, ip_version)：脚本在探测结束时连着存两次
// （先 v4 后 v6），ts_unix 常常落在同一秒，只用 (server_id, timestamp)
// 当主键时 INSERT OR REPLACE 会让后推的 v6 覆盖先推的 v4，v4 记录无声丢失。
// 隐私：traceroute 里的 IP 是 VPS 到运营商目标的中间跳 IP，不含用户真实 IP；
// 面板按登录状态打码（与详情页 IP 隐私规则一致，见主题）。

export const ROUTE_HISTORY_KEEP_HOURS = 168; // 7 天，和延迟/丢包历史一致
export const ROUTE_HISTORY_ALLOWED_HOURS = [0.167, 0.5, 1, 6, 12, 24, 48, 96, 168];

export function createRouteHistoryTableSql() {
  return `
    CREATE TABLE IF NOT EXISTS route_history (
      server_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      routes_tag TEXT DEFAULT '',
      carriers TEXT DEFAULT '{}',
      ip_version TEXT DEFAULT 'v4',
      PRIMARY KEY (server_id, timestamp, ip_version)
    )
  `;
}

// 已有库迁移：建表（新库直接用新主键）→ 缺列补 ip_version →
// 旧主键 (server_id, timestamp) 的表用建新表-导数据-改名重建为主键
// (server_id, timestamp, ip_version)。已是新主键时什么都不做。
export async function ensureRouteHistorySchema(db) {
  await db.prepare(createRouteHistoryTableSql()).run();

  const { results: columns = [] } = await db.prepare(`PRAGMA table_info(route_history)`).all();
  const colNames = new Set(columns.map(column => column.name));
  if (!colNames.has('ip_version')) {
    await db.prepare(`ALTER TABLE route_history ADD COLUMN ip_version TEXT DEFAULT 'v4'`).run();
  }

  const def = await db.prepare(
    `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'route_history'`
  ).first();
  if (String(def?.sql || '').includes('PRIMARY KEY (server_id, timestamp, ip_version)')) {
    return;
  }
  await db.prepare(`
    CREATE TABLE route_history_new (
      server_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      routes_tag TEXT DEFAULT '',
      carriers TEXT DEFAULT '{}',
      ip_version TEXT DEFAULT 'v4',
      PRIMARY KEY (server_id, timestamp, ip_version)
    )
  `).run();
  await db.prepare(`
    INSERT INTO route_history_new (server_id, timestamp, routes_tag, carriers, ip_version)
    SELECT server_id, timestamp, routes_tag, carriers, COALESCE(ip_version, 'v4') FROM route_history
  `).run();
  await db.prepare(`DROP TABLE route_history`).run();
  await db.prepare(`ALTER TABLE route_history_new RENAME TO route_history`).run();
}

export async function saveRouteHistory(db, serverId, timestamp, routesTag, carriers, ipVersion = 'v4') {
  const carriersJson = typeof carriers === 'string'
    ? carriers
    : JSON.stringify(carriers || {});
  const normalizedIpVersion = ipVersion === 'v6' ? 'v6' : 'v4';
  await db.prepare(
    'INSERT OR REPLACE INTO route_history (server_id, timestamp, routes_tag, carriers, ip_version) VALUES (?, ?, ?, ?, ?)'
  ).bind(serverId, timestamp, routesTag || '', carriersJson, normalizedIpVersion).run();
  // 顺手清理这台机器 7 天前的旧记录。
  const cutoff = timestamp - ROUTE_HISTORY_KEEP_HOURS * 3600;
  await db.prepare(
    'DELETE FROM route_history WHERE server_id = ? AND timestamp < ?'
  ).bind(serverId, cutoff).run();
}

export async function getRouteHistory(db, serverId, hours) {
  const clampedHours = Math.min(hours, ROUTE_HISTORY_KEEP_HOURS);
  const since = Math.floor(Date.now() / 1000) - Math.floor(clampedHours * 3600);
  const rows = await db.prepare(
    'SELECT timestamp, routes_tag, carriers, ip_version FROM route_history WHERE server_id = ? AND timestamp >= ? ORDER BY timestamp ASC'
  ).bind(serverId, since).all();
  return (rows.results || []).map((row) => {
    let carriers = {};
    try {
      carriers = JSON.parse(row.carriers || '{}');
    } catch (_) {
      carriers = {};
    }
    return {
      timestamp: row.timestamp,
      routes_tag: row.routes_tag,
      carriers,
      ip_version: row.ip_version === 'v6' ? 'v6' : 'v4'
    };
  });
}
