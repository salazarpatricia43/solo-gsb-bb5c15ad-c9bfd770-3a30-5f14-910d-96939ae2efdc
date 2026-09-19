/* 可验证复盘归档测试：canonical JSON、哈希链、归档结构、本地校验器定位与只读 HTTP 接口。
 *
 * 运行前提：服务已在 localhost:3000 启动（npm start）。
 * 归档构造 / 校验部分直接调用 archive.js 与 public/archive.js（合成日志写入临时目录），
 * HTTP 接口部分对真实 data 目录断言。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

const archiveMod = require('../archive');
const Chain = require('../public/archive.js'); // 与浏览器端共用的同一份实现（UMD）

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else { failed++; console.log(`  ✘ ${name}`); }
}

const SESSION_ID = 'cccccccc-1111-2222-3333-444444444444';

// 构造一个含损坏行的闭合场次（含修订、暂停、替岗、超时、迟到确认）
function writeSynthLog(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const lines = [
    ['2026-09-19T10:00:00.000Z', 'sequence-set', { version: 1, count: 2, timeoutSec: 5, cues: [
      { seq: 1, text: '口令甲', targets: ['灯光', '音响'] }, { seq: 2, text: '口令乙', targets: ['道具'] }] }],
    ['2026-09-19T10:00:01.000Z', 'session-start', {}],
    ['2026-09-19T10:00:01.000Z', 'cue-started', { seq: 1, text: '口令甲', targets: ['灯光', '音响'], revision: 1, attemptId: 'a1' }],
    ['2026-09-19T10:00:02.000Z', 'confirm', { seq: 1, position: '灯光' }],
    '{坏数据', // 非法 JSON：解析器跳过并告警，归档 warnings 中应出现
    ['2026-09-19T10:00:03.000Z', 'cue-paused', { seq: 1, reason: '设备调试' }],
    ['2026-09-19T10:00:04.000Z', 'cue-resumed', { seq: 1 }],
    ['2026-09-19T10:00:05.000Z', 'cue-recalled', { seq: 1, oldRevision: 1, newRevision: 2, reason: '措辞修正', newText: '口令甲（修订）' }],
    ['2026-09-19T10:00:05.000Z', 'cue-resent', { seq: 1, text: '口令甲（修订）', reason: '措辞修正', revision: 2, attemptId: 'a2' }],
    ['2026-09-19T10:00:06.000Z', 'confirm', { seq: 1, position: '灯光' }],
    ['2026-09-19T10:00:07.000Z', 'confirm', { seq: 1, position: '音响' }],
    ['2026-09-19T10:00:07.500Z', 'cue-completed', { seq: 1 }],
    ['2026-09-19T10:00:07.500Z', 'cue-started', { seq: 2, text: '口令乙', targets: ['道具'], revision: 1, attemptId: 'b1' }],
    ['2026-09-19T10:00:12.600Z', 'cue-timeout', { seq: 2, missing: ['道具'] }],
    ['2026-09-19T10:00:13.000Z', 'position-substituted', { seq: 2, from: '道具', to: '灯光' }],
    ['2026-09-19T10:00:14.000Z', 'confirm-late', { seq: 2, position: '灯光' }],
    ['2026-09-19T10:00:14.500Z', 'cue-completed', { seq: 2 }],
    ['2026-09-19T10:00:14.500Z', 'sequence-finished', {}],
    ['2026-09-19T10:00:15.000Z', 'session-reset', {}],
  ];
  const body = lines.map((l) => (typeof l === 'string' ? l : JSON.stringify({ ts: l[0], event: l[1], detail: l[2] }))).join('\n') + '\n';
  fs.writeFileSync(path.join(dir, `events-${SESSION_ID}.jsonl`), body);
}

// 测试内独立实现的哈希链（不经过被测模块的链循环，仅复用其 canonicalize 口径做交叉验证）
function independentDigest(events) {
  let h = Buffer.alloc(32);
  for (const ev of events) {
    const bytes = Buffer.from(Chain.canonicalize(ev), 'utf8');
    h = crypto.createHash('sha256').update(Buffer.concat([h, bytes])).digest();
  }
  return h.toString('hex');
}

// 模拟客户端完整校验流程（结构 → 摘要），返回首个失败或 ok
function fullVerify(a) {
  const st = Chain.verifyArchiveStructure(a);
  if (!st.ok) return st;
  const digest = Chain.computeChainHexSync(a.events, (b) =>
    new Uint8Array(crypto.createHash('sha256').update(Buffer.from(b)).digest()));
  return Chain.verifyDigest(a, digest);
}

function httpGet(urlPath) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:3000${urlPath}`, (res) => {
      let buf = '';
      res.on('data', (c) => { buf += c; });
      res.on('end', () => {
        let json = null;
        try { json = buf ? JSON.parse(buf) : null; } catch { /* 非 JSON 响应（如 HTML 页面） */ }
        resolve({ status: res.statusCode, headers: res.headers, body: buf, json });
      });
    }).on('error', reject);
  });
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cue-archive-'));
  writeSynthLog(dir);

  console.log('一、canonical JSON：键递归排序、数组保序、UTF-8');
  check('对象键按字典序输出', Chain.canonicalize({ b: 1, a: 2 }) === '{"a":2,"b":1}');
  check('嵌套对象键递归排序',
    Chain.canonicalize({ z: { y: 1, a: [3, 2, 1] }, a: 'x' }) === '{"a":"x","z":{"a":[3,2,1],"y":1}}');
  check('数组保持原顺序', Chain.canonicalize({ arr: [3, 1, 2] }) === '{"arr":[3,1,2]}');
  check('中文等字符串原样输出（UTF-8 编码在字节层完成）',
    Chain.canonicalize({ t: '口令甲' }) === '{"t":"口令甲"}');
  check('null / 布尔 / 数字字面量', Chain.canonicalize({ n: null, b: true, x: 1.5 }) === '{"b":true,"n":null,"x":1.5}');
  check('空对象与空数组', Chain.canonicalize({ o: {}, a: [] }) === '{"a":[],"o":{}}');
  check('不可序列化类型抛错（不静默改写）', (() => { try { Chain.canonicalize({ u: undefined }); return false; } catch { return true; } })());
  const utf8 = Chain.utf8Bytes('{"t":"口令"}');
  check('UTF-8 字节编码正确', Buffer.from(utf8).equals(Buffer.from('{"t":"口令"}', 'utf8')));

  console.log('二、归档构造：结构、边界与哈希链');
  const a = archiveMod.buildArchive(dir, SESSION_ID, '0');
  check('格式版本为 cue-archive/1', a.format === 'cue-archive/1');
  check('场次摘要完整（起止 / 时长 / 口令数 / 事件数 / 时限）',
    a.session.startedAt === '2026-09-19T10:00:01.000Z' &&
    a.session.finishedAt === '2026-09-19T10:00:14.500Z' &&
    a.session.durationMs === 13500 && a.session.cueCount === 2 &&
    a.session.eventCount === 16 && a.session.timeoutSec === 5);
  check('冻结序列按 seq 升序且为原始口令', a.sequence.length === 2 && a.sequence[0].text === '口令甲' &&
    JSON.stringify(a.sequence[0].targets) === JSON.stringify(['灯光', '音响']));
  check('有效事件保持日志行序且首末为场次边界',
    a.events.length === 16 && a.events[0].event === 'session-start' &&
    a.events[a.events.length - 1].event === 'sequence-finished');
  check('事件保留原始行号与时间戳（sequence-set 与 session-reset 不在场内）',
    a.events[0].line === 2 && a.events[0].ts === '2026-09-19T10:00:01.000Z' &&
    !a.events.some((e) => e.event === 'sequence-set' || e.event === 'session-reset'));
  check('事件不含派生字段（t / positions 不入归档）',
    a.events.every((e) => !('t' in e) && !('positions' in e)));
  check('逐行告警限于本场行区间（坏行第 5 行）',
    a.warnings.length === 1 && a.warnings[0].line === 5 && /解析失败/.test(a.warnings[0].reason));
  check('manifest 保存算法 / 事件数 / 最终摘要',
    a.manifest.algorithm === 'SHA-256' && a.manifest.eventCount === 16 && /^[0-9a-f]{64}$/.test(a.manifest.digest));
  check('最终摘要与独立重算一致（h0 零值、串接哈希）', a.manifest.digest === independentDigest(a.events));
  check('h0 为 32 字节零值', Chain.ZERO_HASH.length === 32 && Chain.ZERO_HASH.every((b) => b === 0));
  const again = archiveMod.buildArchive(dir, SESSION_ID, '0');
  check('同一日志重复导出逐字节一致（归档确定性）', JSON.stringify(again) === JSON.stringify(a));
  check('非法 fileId 被拒', archiveMod.buildArchive(dir, '../evil', '0').error === 'badId');
  check('越界 runId 返回 notFound', archiveMod.buildArchive(dir, SESSION_ID, '9').error === 'notFound');
  check('不存在文件返回 notFound',
    archiveMod.buildArchive(dir, '99999999-9999-9999-9999-999999999999', '0').error === 'notFound');

  console.log('三、本地校验器：合法归档通过，篡改逐项定位');
  const okArchive = JSON.parse(JSON.stringify(a));
  check('合法归档完整校验通过', fullVerify(okArchive).ok === true);

  // 篡改事件内容：结构仍合法，但摘要重算不匹配 → 定位 manifest.digest
  const tamperedEvent = JSON.parse(JSON.stringify(a));
  tamperedEvent.events[3].detail.position = '音响';
  const r1 = fullVerify(tamperedEvent);
  check('篡改事件内容 → 定位字段 manifest.digest',
    !r1.ok && r1.where === 'field' && r1.field === 'manifest.digest');

  // 删除一个事件：计数先于摘要不匹配 → 定位 manifest.eventCount
  const dropped = JSON.parse(JSON.stringify(a));
  dropped.events.splice(3, 1);
  const r2 = fullVerify(dropped);
  check('删除事件 → 定位字段 manifest.eventCount', !r2.ok && r2.field === 'manifest.eventCount');

  // 伪造清单事件数 → 定位 manifest.eventCount
  const badCount = JSON.parse(JSON.stringify(a));
  badCount.manifest.eventCount += 1;
  const r3 = fullVerify(badCount);
  check('伪造清单事件数 → 定位字段 manifest.eventCount', !r3.ok && r3.field === 'manifest.eventCount');

  // 伪造场次摘要事件数 → 定位 session.eventCount
  const badSessionCount = JSON.parse(JSON.stringify(a));
  badSessionCount.session.eventCount += 1;
  const r4 = fullVerify(badSessionCount);
  check('伪造摘要事件数 → 定位字段 session.eventCount', !r4.ok && r4.field === 'session.eventCount');

  // 破坏场次边界：首事件被替换 → 定位事件索引 0
  const badStart = JSON.parse(JSON.stringify(a));
  badStart.events[0].event = 'cue-started';
  const r5 = fullVerify(badStart);
  check('首事件非 session-start → 定位事件索引 0',
    !r5.ok && r5.where === 'event' && r5.index === 0);

  // 破坏场次边界：末事件被替换 → 定位末位事件索引
  const badEnd = JSON.parse(JSON.stringify(a));
  badEnd.events[badEnd.events.length - 1].event = 'cue-completed';
  const r6 = fullVerify(badEnd);
  check('末事件非 sequence-finished → 定位末位事件索引',
    !r6.ok && r6.where === 'event' && r6.index === badEnd.events.length - 1);

  // 边界事件混入场次内部 → 定位该事件索引
  const innerBoundary = JSON.parse(JSON.stringify(a));
  innerBoundary.events[4].event = 'sequence-finished';
  const r7 = fullVerify(innerBoundary);
  check('边界事件混入内部 → 定位事件索引 4', !r7.ok && r7.where === 'event' && r7.index === 4);

  // 事件结构损坏（detail 不是对象）→ 定位该事件索引
  const badDetail = JSON.parse(JSON.stringify(a));
  badDetail.events[2].detail = ['not-an-object'];
  const r8 = fullVerify(badDetail);
  check('事件 detail 非对象 → 定位事件索引 2', !r8.ok && r8.where === 'event' && r8.index === 2);

  // 格式版本错误 → 定位 format 字段
  const badFormat = JSON.parse(JSON.stringify(a));
  badFormat.format = 'cue-archive/0';
  const r9 = fullVerify(badFormat);
  check('格式版本错误 → 定位字段 format', !r9.ok && r9.field === 'format');

  // 冻结序列序号不连续 → 定位 sequence[i].seq
  const badSeq = JSON.parse(JSON.stringify(a));
  badSeq.sequence[1].seq = 7;
  const r10 = fullVerify(badSeq);
  check('冻结序列序号不连续 → 定位字段 sequence[1].seq', !r10.ok && r10.field === 'sequence[1].seq');

  // 摘要形状非法 → 定位 manifest.digest
  const badDigestShape = JSON.parse(JSON.stringify(a));
  badDigestShape.manifest.digest = 'XYZ';
  const r11 = fullVerify(badDigestShape);
  check('摘要形状非法 → 定位字段 manifest.digest', !r11.ok && r11.field === 'manifest.digest');

  // 伪造最终摘要（形状合法但值错误）→ 重算比对失败，定位 manifest.digest
  const forged = JSON.parse(JSON.stringify(a));
  forged.manifest.digest = '0'.repeat(64);
  const r12 = fullVerify(forged);
  check('伪造最终摘要 → 重算比对失败并定位 manifest.digest', !r12.ok && r12.field === 'manifest.digest');

  console.log('四、HTTP 接口（只读 GET）');
  const apiList = await httpGet('/api/replay/sessions');
  check('场次列表可用（归档页数据源）', apiList.status === 200 && Array.isArray(apiList.json.sessions));
  if (apiList.json.sessions.length) {
    const s0 = apiList.json.sessions[0];
    const got = await httpGet(`/api/archive/sessions/${s0.fileId}/${s0.runId}`);
    check('GET 归档 200 且为附件下载',
      got.status === 200 && /attachment/.test(got.headers['content-disposition'] || ''));
    check('归档含 format/session/sequence/events/warnings/manifest',
      got.json && got.json.format === 'cue-archive/1' && Array.isArray(got.json.events) &&
      Array.isArray(got.json.sequence) && Array.isArray(got.json.warnings) &&
      got.json.manifest && typeof got.json.manifest.digest === 'string');
    check('接口归档通过完整校验（与本地重算一致）', got.json && fullVerify(got.json).ok === true);
  }
  const badId = await httpGet('/api/archive/sessions/..%2F..%2Fetc%2Fpasswd/0');
  check('路径穿越 / 非法 ID 返回 400', badId.status === 400);
  const missing = await httpGet('/api/archive/sessions/99999999-9999-9999-9999-999999999999/0');
  check('不存在场次返回 404', missing.status === 404);
  const page = await httpGet('/archive.html');
  check('归档页面可访问且不含 WebSocket 代码',
    page.status === 200 && !/new WebSocket|CueClient\.connect/.test(page.body));
  check('归档页下载链接按 fileId / runId 两段分别编码',
    page.body.includes("indexOf('/')") && page.body.includes('/api/archive/sessions/'));
  if (apiList.json.sessions.length) {
    const s0 = apiList.json.sessions[0];
    const combined = await httpGet(`/api/archive/sessions/${encodeURIComponent(`${s0.fileId}/${s0.runId}`)}`);
    check('整体编码为单段的 URL 不匹配路由（返回 404，页面必须分段拼接）', combined.status === 404);
  }

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n结果：${passed} 通过，${failed} 失败`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
