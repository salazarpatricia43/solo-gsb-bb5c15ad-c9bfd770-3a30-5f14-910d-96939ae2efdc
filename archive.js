'use strict';

// ---------------------------------------------------------------------------
// 可验证复盘归档（只读）模块
//
// 在「演出复盘」只读解析器之上，把单个已结束场次（session-start →
// sequence-finished 完整闭合的一段）打包为单个 JSON 归档，供下载与离线校验：
//   format    —— 格式版本（cue-archive/1）
//   session   —— 场次摘要（起止时间、时长、口令数、事件数、确认时限）
//   sequence  —— 冻结序列（本场开始时冻结的口令快照，按 seq 升序）
//   events    —— 有效事件（按日志行序，保留原始行号 line / 时间戳 ts / 类型 / detail）
//   warnings  —— 本场行区间内的逐行坏数据告警
//   manifest  —— { algorithm, eventCount, digest }：事件数与哈希链最终摘要
//
// 哈希链（与浏览器端 public/archive.js 同一份实现，见该文件头部注释）：
//   h0 为 32 字节零值；事件经 canonical JSON（对象键递归排序、数组保序）
// 编码为 UTF-8 字节后，hi = SHA-256(h(i-1) 字节串接当前事件字节)。
//
// 只读保证：本模块仅经 replay.js 的只读解析器读取 data 目录事件日志，
// 绝不打开写流、绝不追加/修改事件日志，不引用 server.js 的当前演出状态，
// 也不连接或广播 WebSocket。同一日志文件重复导出逐字节一致（归档不含生成时刻）。
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const replay = require('./replay');
// 与浏览器端共用的 canonical JSON / 哈希链实现（UMD，Node 中走 module.exports）
const chain = require('./public/archive.js');

function sha256Sync(bytes) {
  return new Uint8Array(crypto.createHash('sha256').update(Buffer.from(bytes)).digest());
}

// GET /api/archive/sessions/:fileId/:runId：构造单场可验证归档
// 返回归档对象，或 { error: 'badId' | 'notFound' | 'readFailed' }
function buildArchive(dataDir, fileId, runId) {
  if (!replay.isValidFileId(fileId)) return { error: 'badId' };
  const id = Number(runId);
  if (!Number.isInteger(id) || id < 0) return { error: 'badId' };

  // 复用复盘只读解析器：逐行解析（坏行跳过并告警）、切分闭合场次、提取冻结序列
  const data = replay.getSession(dataDir, fileId, String(id));
  if (data.error) return { error: data.error };

  // 有效事件：只保留日志原始内容（行号 / ISO 时间戳 / 事件类型 / detail），
  // 派生字段（相对偏移 t、岗位聚合 positions）不入归档、不参与哈希
  const events = data.events.map((e) => ({
    line: e.line,
    ts: e.ts,
    event: e.event,
    detail: e.detail,
  }));

  return {
    format: chain.FORMAT,
    session: data.session, // { fileId, runId, startedAt, finishedAt, durationMs, cueCount, eventCount, timeoutSec }
    sequence: data.sequence, // 冻结序列 [{ seq, text, targets }]，按 seq 升序
    events,
    warnings: data.warnings, // 本场行区间内的逐行告警 [{ line, reason, raw }]
    manifest: {
      algorithm: chain.ALGORITHM,
      eventCount: events.length,
      digest: chain.computeChainHexSync(events, sha256Sync),
    },
  };
}

module.exports = { buildArchive };
