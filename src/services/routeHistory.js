// 路由探测历史：VPS 上的 route_detect.py 每小时推送一次，面板详情页读取展示。
// 与 metrics_history 分开存：数据量小（11 台 × 7 天 × 24 条 ≈ 1848 行），
// 不需要分区主键方案，用 (server_id, timestamp) 复合主键即可。
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
      PRIMARY KEY (server_id, timestamp)
    )
  `;
}

export async function saveRouteHistory(db, serverId, timestamp, routesTag, carriers) {
  const carriersJson = typeof carriers === 'string'
    ? carriers
    : JSON.stringify(carriers || {});
  await db.prepare(
    'INSERT OR REPLACE INTO route_history (server_id, timestamp, routes_tag, carriers) VALUES (?, ?, ?, ?)'
  ).bind(serverId, timestamp, routesTag || '', carriersJson).run();
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
    'SELECT timestamp, routes_tag, carriers FROM route_history WHERE server_id = ? AND timestamp >= ? ORDER BY timestamp ASC'
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
      carriers
    };
  });
}
