/* 可验证复盘归档：canonical JSON、哈希链与归档校验器。
 *
 * 本文件是浏览器端（archive.html 本地校验）与服务端（archive.js 生成归档）
 * 共用的同一份实现（UMD：浏览器挂全局 Archive，Node 中 module.exports），
 * 保证「导出时的哈希计算」与「上传后的本地重算」逐字节一致。
 *
 * 哈希链规则（归档格式 cue-archive/1）：
 *   - 每个事件对象先编码为 canonical JSON：对象键递归排序（UTF-16 码元字典序）、
 *     数组保持原顺序，再编码为 UTF-8 字节；
 *   - h0 为 32 字节零值；hi = SHA-256(h(i-1) 字节串接第 i 个事件的 UTF-8 字节)；
 *   - manifest.digest 保存最终摘要 hN 的小写 hex，manifest.eventCount 保存事件数 N。
 *
 * 只读：本文件只做纯计算，不发起网络请求、不读写存储、不连接 WebSocket。
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else root.Archive = mod;
})(typeof self !== 'undefined' ? self : globalThis, () => {
  'use strict';

  const FORMAT = 'cue-archive/1';
  const ALGORITHM = 'SHA-256';
  const HEX_RE = /^[0-9a-f]{64}$/;

  // -------------------------------------------------------------------------
  // canonical JSON：对象键递归排序、数组保序。
  // 输入必须来自 JSON.parse（只含 string/number/boolean/null/数组/对象），
  // 遇到不可序列化的值直接抛错（归档数据不应出现，静默改写会破坏可验证性）。
  // -------------------------------------------------------------------------
  function canonicalize(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) {
      return '[' + value.map((item) => canonicalize(item)).join(',') + ']';
    }
    const t = typeof value;
    if (t === 'object') {
      const keys = Object.keys(value).sort(); // 默认按 UTF-16 码元字典序，确定性
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
    }
    if (t === 'string' || t === 'number' || t === 'boolean') {
      return JSON.stringify(value);
    }
    throw new TypeError(`canonical JSON 不支持该类型：${t}`);
  }

  // UTF-8 编码（TextEncoder 在浏览器与 Node ≥ 18 均为全局可用）
  function utf8Bytes(str) {
    return new TextEncoder().encode(str);
  }

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  function toHex(bytes) {
    let s = '';
    for (const b of bytes) s += b.toString(16).padStart(2, '0');
    return s;
  }

  const ZERO_HASH = new Uint8Array(32); // h0：32 字节零值

  // 单个链步的待哈希字节：h(i-1) 字节串接当前事件的 canonical JSON UTF-8 字节
  function chainInputBytes(prevHash, event) {
    return concatBytes(prevHash, utf8Bytes(canonicalize(event)));
  }

  // 服务端（Node）用：注入同步 sha256（crypto.createHash），返回最终摘要 hex
  function computeChainHexSync(events, sha256Sync) {
    let h = ZERO_HASH;
    for (const ev of events) h = sha256Sync(chainInputBytes(h, ev));
    return toHex(h);
  }

  // 浏览器用：WebCrypto 异步 SHA-256，返回最终摘要 hex
  async function computeChainHex(events) {
    let h = ZERO_HASH;
    for (const ev of events) {
      const digest = await crypto.subtle.digest(ALGORITHM, chainInputBytes(h, ev));
      h = new Uint8Array(digest);
    }
    return toHex(h);
  }

  // -------------------------------------------------------------------------
  // 归档校验（摘要重算之外的全部检查）。
  // 按固定顺序逐项检查，首个失败即返回并定位到具体字段或事件索引：
  //   { ok: false, where: 'field', field, message }
  //   { ok: false, where: 'event', index, message }（index 为 0 基事件索引）
  // -------------------------------------------------------------------------
  function failField(field, message) {
    return { ok: false, where: 'field', field, message };
  }
  function failEvent(index, message) {
    return { ok: false, where: 'event', index, message };
  }
  function isPlainObject(v) {
    return !!v && typeof v === 'object' && !Array.isArray(v);
  }
  function isFiniteNumber(v) {
    return typeof v === 'number' && Number.isFinite(v);
  }
  function isPositiveInt(v) {
    return Number.isInteger(v) && v > 0;
  }
  function isNonNegativeInt(v) {
    return Number.isInteger(v) && v >= 0;
  }
  function isIsoDate(v) {
    return typeof v === 'string' && Number.isFinite(Date.parse(v));
  }

  function verifyArchiveStructure(a) {
    // 1. 根对象与格式版本
    if (!isPlainObject(a)) return failField('(root)', '归档不是 JSON 对象');
    if (a.format !== FORMAT) {
      return failField('format', `格式版本不匹配：期望「${FORMAT}」，实际为 ${JSON.stringify(a.format == null ? null : a.format)}`);
    }

    // 2. 场次摘要
    if (!isPlainObject(a.session)) return failField('session', '缺少场次摘要对象 session');
    const s = a.session;
    if (!isIsoDate(s.startedAt)) return failField('session.startedAt', '场次开始时间缺失或不是合法时间戳');
    if (!isIsoDate(s.finishedAt)) return failField('session.finishedAt', '场次结束时间缺失或不是合法时间戳');
    if (!isFiniteNumber(s.durationMs)) return failField('session.durationMs', '场次时长缺失或不是数值');
    if (!isNonNegativeInt(s.cueCount)) return failField('session.cueCount', '口令数缺失或不是非负整数');
    if (!isNonNegativeInt(s.eventCount)) return failField('session.eventCount', '事件数缺失或不是非负整数');
    if (!isFiniteNumber(s.timeoutSec)) return failField('session.timeoutSec', '确认时限缺失或不是数值');

    // 3. 冻结序列：seq 必须从 1 开始连续递增，text 为字符串，targets 为字符串数组
    if (!Array.isArray(a.sequence)) return failField('sequence', '缺少冻结序列数组 sequence');
    for (let i = 0; i < a.sequence.length; i++) {
      const c = a.sequence[i];
      const at = `sequence[${i}]`;
      if (!isPlainObject(c)) return failField(at, '冻结序列条目不是对象');
      if (!isPositiveInt(c.seq)) return failField(`${at}.seq`, '口令序号缺失或不是正整数');
      if (c.seq !== i + 1) return failField(`${at}.seq`, `口令序号不连续：第 ${i + 1} 条的 seq 为 ${c.seq}`);
      if (typeof c.text !== 'string') return failField(`${at}.text`, '口令文本缺失或不是字符串');
      if (!Array.isArray(c.targets) || c.targets.some((t) => typeof t !== 'string')) {
        return failField(`${at}.targets`, '目标岗位缺失或不是字符串数组');
      }
    }

    // 4. 有效事件：逐条校验结构（首个坏事件即定位其 0 基索引）
    if (!Array.isArray(a.events) || a.events.length === 0) {
      return failField('events', '缺少有效事件数组 events 或事件为空');
    }
    for (let i = 0; i < a.events.length; i++) {
      const ev = a.events[i];
      if (!isPlainObject(ev)) return failEvent(i, '事件不是 JSON 对象');
      if (!isPositiveInt(ev.line)) return failEvent(i, '事件缺少原始日志行号 line（正整数）');
      if (!isIsoDate(ev.ts)) return failEvent(i, '事件缺少合法的时间戳 ts');
      if (typeof ev.event !== 'string' || ev.event === '') return failEvent(i, '事件缺少合法的 event 字段');
      if (!isPlainObject(ev.detail)) return failEvent(i, '事件 detail 字段缺失或不是对象');
    }

    // 5. 场次边界：session-start 开场、sequence-finished 闭合，且边界事件不得在段内重现
    const n = a.events.length;
    if (a.events[0].event !== 'session-start') {
      return failEvent(0, `场次边界不完整：首个事件应为 session-start，实际为「${a.events[0].event}」`);
    }
    if (a.events[n - 1].event !== 'sequence-finished') {
      return failEvent(n - 1, `场次边界不完整：末个事件应为 sequence-finished，实际为「${a.events[n - 1].event}」`);
    }
    for (let i = 1; i < n - 1; i++) {
      const name = a.events[i].event;
      if (name === 'session-start' || name === 'sequence-finished') {
        return failEvent(i, `场次边界被破坏：边界事件「${name}」出现在场次内部`);
      }
    }

    // 6. 逐行告警结构
    if (!Array.isArray(a.warnings)) return failField('warnings', '缺少逐行告警数组 warnings');
    for (let i = 0; i < a.warnings.length; i++) {
      const w = a.warnings[i];
      const at = `warnings[${i}]`;
      if (!isPlainObject(w)) return failField(at, '告警条目不是对象');
      if (!isPositiveInt(w.line)) return failField(`${at}.line`, '告警缺少原始日志行号 line（正整数）');
      if (typeof w.reason !== 'string') return failField(`${at}.reason`, '告警缺少原因 reason');
      if (typeof w.raw !== 'string') return failField(`${at}.raw`, '告警缺少坏行原文 raw');
    }

    // 7. manifest：算法、事件数与最终摘要的形状
    if (!isPlainObject(a.manifest)) return failField('manifest', '缺少清单对象 manifest');
    const m = a.manifest;
    if (m.algorithm !== ALGORITHM) {
      return failField('manifest.algorithm', `哈希算法不匹配：期望「${ALGORITHM}」，实际为 ${JSON.stringify(m.algorithm == null ? null : m.algorithm)}`);
    }
    if (!isNonNegativeInt(m.eventCount)) return failField('manifest.eventCount', '清单事件数缺失或不是非负整数');
    if (typeof m.digest !== 'string' || !HEX_RE.test(m.digest)) {
      return failField('manifest.digest', '最终摘要缺失或不是 64 位小写十六进制');
    }

    // 8. 计数一致性：manifest / 场次摘要与实际内容逐项核对
    if (m.eventCount !== a.events.length) {
      return failField('manifest.eventCount', `清单事件数 ${m.eventCount} 与实际事件数 ${a.events.length} 不一致`);
    }
    if (s.eventCount !== a.events.length) {
      return failField('session.eventCount', `场次摘要事件数 ${s.eventCount} 与实际事件数 ${a.events.length} 不一致`);
    }
    if (s.cueCount !== a.sequence.length) {
      return failField('session.cueCount', `场次摘要口令数 ${s.cueCount} 与冻结序列条数 ${a.sequence.length} 不一致`);
    }
    return { ok: true };
  }

  // 摘要校验：调用方重算出实际摘要（浏览器 WebCrypto / Node crypto）后与声明值比对
  function verifyDigest(archive, actualHex) {
    const declared = archive && archive.manifest && archive.manifest.digest;
    if (actualHex !== declared) {
      return failField('manifest.digest',
        `最终摘要不匹配：归档声明 ${declared}，逐项重算得 ${actualHex}（事件内容已被篡改或损坏）`);
    }
    return { ok: true };
  }

  return {
    FORMAT,
    ALGORITHM,
    ZERO_HASH,
    canonicalize,
    utf8Bytes,
    concatBytes,
    toHex,
    chainInputBytes,
    computeChainHexSync,
    computeChainHex,
    verifyArchiveStructure,
    verifyDigest,
  };
});
