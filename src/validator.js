'use strict';

/**
 * LDP Graceful Restart 状态校验器(离线分析,不建立真实 LDP 会话)。
 *
 * 输入:会话、邻接、FEC→标签映射、标签保留计时器、下一跳、LSP 路径、
 *      重启标记与恢复事件(按 time 排序的时间线)。
 * 输出:每个 FEC 在每个阶段的可用状态、保留标签、恢复路径与黑洞原因。
 */

const FLAP_WINDOW = 60;        // 秒,会话抖动统计窗口
const FLAP_THRESHOLD = 3;      // 窗口内 down 次数达到该值则阻尼

const REASON = {
  OK: null,
  NO_BINDING: 'no-binding',
  STALE_ONLY: 'stale-binding-retained-no-new-traffic',
  STALE_TIMEOUT: 'stale-timeout',
  LABEL_REUSED: 'label-reused-conflict',
  NEXTHOP_UNREACHABLE: 'next-hop-unreachable',
  PATH_BROKEN: 'path-broken',
  SESSION_FLAPPING: 'session-flapping',
};

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

class LdpGrValidator {
  constructor(input) {
    this.sessions = new Map();
    for (const s of input.sessions || []) {
      this.sessions.set(s.id, {
        id: s.id,
        local: s.local,
        peer: s.peer,
        state: s.state || 'established',
        grCapable: s.grCapable !== false,
        recoveryTime: s.recoveryTime ?? 60,
        downTimes: [],
        dampened: false,
      });
    }

    this.adjacencies = new Map();
    for (const a of input.adjacencies || []) {
      this.adjacencies.set(a.id, { ...a, state: a.state || 'up' });
    }

    this.fecs = new Map();
    for (const f of input.fecs || []) {
      this.fecs.set(f.id, { id: f.id, prefix: f.prefix });
    }

    // key: `${session}|${fec}`
    this.mappings = new Map();
    for (const m of input.mappings || []) {
      const key = `${m.session}|${m.fec}`;
      this.mappings.set(key, {
        fec: m.fec,
        session: m.session,
        label: m.label,
        state: m.state || 'active', // active | stale | withdrawn
        staleSince: null,
        expiresAt: null,
        advertisedAt: m.advertisedAt ?? 0,
      });
    }

    // 每个 FEC 的下一跳候选,数组顺序即优先级
    this.nextHops = new Map();
    for (const n of input.nextHops || []) {
      if (!this.nextHops.has(n.fec)) this.nextHops.set(n.fec, []);
      this.nextHops.get(n.fec).push({ via: n.via, reachable: n.reachable !== false });
    }

    this.lspPaths = new Map();
    for (const p of input.lspPaths || []) {
      this.lspPaths.set(p.fec, { path: p.path || [], state: p.state || 'up' });
    }

    this.restarting = new Set();
    for (const r of input.restartFlags || []) {
      if (r.restarting) this.restarting.add(r.router);
    }

    this.events = (input.events || [])
      .map((e, i) => ({ ...e, _seq: i }))
      .sort((a, b) => (a.time - b.time) || (a._seq - b._seq));

    this.now = input.now ?? (this.events.length ? this.events[this.events.length - 1].time : 0);
    this.phases = [];
  }

  run() {
    this.expireStale(0);
    for (const event of this.events) {
      this.applyEvent(event);
      this.expireStale(event.time);
      this.phases.push({
        time: event.time,
        event: this.describeEvent(event),
        fecs: this.evaluateAll(),
      });
    }
    this.expireStale(this.now);
    return {
      now: this.now,
      phases: this.phases,
      summary: this.evaluateAll(),
    };
  }

  describeEvent(event) {
    const { _seq, ...rest } = event;
    return rest;
  }

  applyEvent(event) {
    switch (event.type) {
      case 'session-down': return this.onSessionDown(event);
      case 'session-up': return this.onSessionUp(event);
      case 'mapping': return this.onMapping(event);
      case 'withdraw': return this.onWithdraw(event);
      case 'path-change': return this.onPathChange(event);
      case 'nexthop-change': return this.onNextHopChange(event);
      case 'restart': {
        if (event.restarting === false) this.restarting.delete(event.router);
        else this.restarting.add(event.router);
        return;
      }
      default:
        throw new Error(`unknown event type: ${event.type}`);
    }
  }

  onSessionDown(event) {
    const session = this.sessions.get(event.session);
    if (!session) throw new Error(`unknown session: ${event.session}`);
    session.state = 'down';
    session.downTimes.push(event.time);
    session.downTimes = session.downTimes.filter((t) => event.time - t <= FLAP_WINDOW);
    if (session.downTimes.length >= FLAP_THRESHOLD) session.dampened = true;

    const graceful = session.grCapable &&
      (this.restarting.has(session.peer) || event.restart === true);
    for (const m of this.mappings.values()) {
      if (m.session !== session.id || m.state !== 'active') continue;
      if (graceful) {
        // GR:保留旧标签为 stale,启动标签保留计时器;stale 不得承载新流量
        m.state = 'stale';
        m.staleSince = event.time;
        m.expiresAt = event.time + session.recoveryTime;
      } else {
        m.state = 'withdrawn';
      }
    }
  }

  onSessionUp(event) {
    const session = this.sessions.get(event.session);
    if (!session) throw new Error(`unknown session: ${event.session}`);
    session.state = 'established';
    // 握手成功不代表恢复完成:stale 映射必须等重新通告或超时,
    // 且整条 LSP 路径仍需重新校验(见 evaluateFec)。
  }

  onMapping(event) {
    const session = this.sessions.get(event.session);
    if (!session) throw new Error(`unknown session: ${event.session}`);
    const key = `${event.session}|${event.fec}`;
    const existing = this.mappings.get(key);

    // 旧标签被复用:新映射的标签仍被其它 FEC 的 stale 绑定占用
    for (const m of this.mappings.values()) {
      if (m.session === event.session && m.fec !== event.fec &&
          m.state === 'stale' && m.label === event.label) {
        m.state = 'withdrawn';
        m.conflict = REASON.LABEL_REUSED;
      }
    }

    if (existing && existing.state !== 'withdrawn') {
      // 重启端提前发送新映射:替换 stale 绑定,旧标签立即释放
      existing.label = event.label;
      existing.state = session.state === 'established' ? 'active' : existing.state;
      existing.staleSince = null;
      existing.expiresAt = null;
      existing.advertisedAt = event.time;
    } else {
      this.mappings.set(key, {
        fec: event.fec,
        session: event.session,
        label: event.label,
        state: session.state === 'established' ? 'active' : 'stale',
        staleSince: null,
        expiresAt: null,
        advertisedAt: event.time,
      });
    }
  }

  onWithdraw(event) {
    const key = `${event.session}|${event.fec}`;
    const m = this.mappings.get(key);
    if (m) m.state = 'withdrawn';
  }

  onPathChange(event) {
    const current = this.lspPaths.get(event.fec) || { path: [], state: 'up' };
    this.lspPaths.set(event.fec, {
      path: event.path !== undefined ? event.path : current.path,
      state: event.state || current.state,
    });
  }

  onNextHopChange(event) {
    const list = this.nextHops.get(event.fec) || [];
    const entry = list.find((n) => n.via === event.via);
    if (entry) entry.reachable = event.reachable !== false;
    else list.push({ via: event.via, reachable: event.reachable !== false });
    this.nextHops.set(event.fec, list);
  }

  expireStale(time) {
    for (const m of this.mappings.values()) {
      if (m.state === 'stale' && m.expiresAt !== null && m.expiresAt <= time) {
        m.state = 'withdrawn';
        m.conflict = REASON.STALE_TIMEOUT;
      }
    }
  }

  sessionForMapping(m) {
    return this.sessions.get(m.session);
  }

  evaluateAll() {
    const result = {};
    for (const fecId of this.fecs.keys()) {
      result[fecId] = this.evaluateFec(fecId);
    }
    return result;
  }

  evaluateFec(fecId) {
    const all = [...this.mappings.values()].filter((m) => m.fec === fecId);
    const live = all.filter((m) => m.state !== 'withdrawn');
    const stale = live.filter((m) => m.state === 'stale');
    const timedOut = all.some((m) => m.conflict === REASON.STALE_TIMEOUT);
    const reused = all.some((m) => m.conflict === REASON.LABEL_REUSED);

    const active = live.filter((m) => {
      const s = this.sessionForMapping(m);
      return m.state === 'active' && s.state === 'established';
    });
    const usable = active.filter((m) => !this.sessionForMapping(m).dampened);

    const report = {
      prefix: this.fecs.get(fecId)?.prefix,
      status: 'down',
      available: false,
      retainedLabel: null,
      recoveryPath: null,
      blackholeReason: null,
    };

    if (usable.length > 0) {
      // 按下一跳优先级选择(双归切换):优先列表里排前的下一跳
      const nhList = this.nextHops.get(fecId) || [];
      const rank = (m) => {
        const peer = this.sessionForMapping(m).peer;
        const idx = nhList.findIndex((n) => n.via === peer);
        return idx === -1 ? nhList.length : idx;
      };
      usable.sort((a, b) => rank(a) - rank(b));
      const chosen = usable[0];
      const peer = this.sessionForMapping(chosen).peer;
      const nh = nhList.find((n) => n.via === peer);
      const path = this.lspPaths.get(fecId);

      report.retainedLabel = chosen.label;
      report.via = peer;

      if (nh && !nh.reachable) {
        report.blackholeReason = REASON.NEXTHOP_UNREACHABLE;
      } else if (!path || path.state !== 'up') {
        // 恢复后必须校验整条路径,而不仅是邻居握手成功
        report.blackholeReason = REASON.PATH_BROKEN;
        report.recoveryPath = path ? clone(path.path) : null;
      } else {
        report.status = 'available';
        report.available = true;
        report.recoveryPath = clone(path.path);
        report.blackholeReason = REASON.OK;
      }
      return report;
    }

    if (stale.length > 0) {
      // 仅剩 stale 绑定:标签保留用于控制面恢复,不得继续发布新流量
      report.status = 'stale-only';
      report.retainedLabel = stale[0].label;
      report.blackholeReason = REASON.STALE_ONLY;
      return report;
    }

    if (active.length > 0) {
      // 映射存在但会话被抖动阻尼,不再信任其标签
      report.blackholeReason = REASON.SESSION_FLAPPING;
      return report;
    }

    if (reused) report.blackholeReason = REASON.LABEL_REUSED;
    else if (timedOut) report.blackholeReason = REASON.STALE_TIMEOUT;
    else report.blackholeReason = REASON.NO_BINDING;
    return report;
  }
}

module.exports = { LdpGrValidator, REASON, FLAP_WINDOW, FLAP_THRESHOLD };
