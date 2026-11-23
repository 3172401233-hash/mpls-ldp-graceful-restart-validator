'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { LdpGrValidator, REASON } = require('../src/validator');

function baseInput(overrides = {}) {
  return {
    sessions: [
      { id: 's1', local: 'R1', peer: 'R2', grCapable: true, recoveryTime: 60 },
      { id: 's2', local: 'R1', peer: 'R3', grCapable: true, recoveryTime: 60 },
    ],
    adjacencies: [
      { id: 'a1', session: 's1', interface: 'eth0' },
      { id: 'a2', session: 's2', interface: 'eth1' },
    ],
    fecs: [{ id: 'fec1', prefix: '10.0.0.0/24' }],
    mappings: [
      { fec: 'fec1', session: 's1', label: 100 },
      { fec: 'fec1', session: 's2', label: 200 },
    ],
    nextHops: [
      { fec: 'fec1', via: 'R2' },
      { fec: 'fec1', via: 'R3' },
    ],
    lspPaths: [{ fec: 'fec1', path: ['R1', 'R2', 'R4'], state: 'up' }],
    restartFlags: [],
    events: [],
    ...overrides,
  };
}

test('双归恢复:主邻居重启后切换到备份邻居,恢复后切回', () => {
  const report = new LdpGrValidator(baseInput({
    restartFlags: [{ router: 'R2', restarting: true }],
    events: [
      { type: 'session-down', session: 's1', time: 10 },
      { type: 'path-change', fec: 'fec1', path: ['R1', 'R3', 'R4'], state: 'up', time: 12 },
      { type: 'session-up', session: 's1', time: 40 },
      { type: 'mapping', fec: 'fec1', session: 's1', label: 100, time: 45 },
      { type: 'path-change', fec: 'fec1', path: ['R1', 'R2', 'R4'], state: 'up', time: 50 },
    ],
  })).run();

  const afterDown = report.phases[0].fecs.fec1;
  assert.equal(afterDown.status, 'available');
  assert.equal(afterDown.via, 'R3');
  assert.equal(afterDown.retainedLabel, 200);

  const final = report.summary.fec1;
  assert.equal(final.status, 'available');
  assert.equal(final.via, 'R2');
  assert.equal(final.retainedLabel, 100);
  assert.deepEqual(final.recoveryPath, ['R1', 'R2', 'R4']);
  assert.equal(final.blackholeReason, null);
});

test('双归切换失败:备份路径不可用时报黑洞', () => {
  const report = new LdpGrValidator(baseInput({
    restartFlags: [{ router: 'R2', restarting: true }],
    events: [
      { type: 'session-down', session: 's1', time: 10 },
      { type: 'session-down', session: 's2', time: 11 },
    ],
  })).run();

  const fec1 = report.summary.fec1;
  assert.equal(fec1.available, false);
  assert.equal(fec1.status, 'stale-only');
  assert.equal(fec1.blackholeReason, REASON.STALE_ONLY);
});

test('stale 绑定保留标签但不得发布新流量', () => {
  const input = baseInput({
    restartFlags: [{ router: 'R2', restarting: true }],
    events: [{ type: 'session-down', session: 's1', time: 10 }],
  });
  input.mappings = [{ fec: 'fec1', session: 's1', label: 100 }];
  input.nextHops = [{ fec: 'fec1', via: 'R2' }];

  const fec1 = new LdpGrValidator(input).run().summary.fec1;
  assert.equal(fec1.status, 'stale-only');
  assert.equal(fec1.available, false);
  assert.equal(fec1.retainedLabel, 100);
  assert.equal(fec1.blackholeReason, REASON.STALE_ONLY);
});

test('stale 超时:保留计时器到期后旧标签被清除', () => {
  const input = baseInput({
    now: 100,
    restartFlags: [{ router: 'R2', restarting: true }],
    events: [{ type: 'session-down', session: 's1', time: 10 }],
  });
  input.mappings = [{ fec: 'fec1', session: 's1', label: 100 }];
  input.nextHops = [{ fec: 'fec1', via: 'R2' }];

  const fec1 = new LdpGrValidator(input).run().summary.fec1;
  assert.equal(fec1.status, 'down');
  assert.equal(fec1.retainedLabel, null);
  assert.equal(fec1.blackholeReason, REASON.STALE_TIMEOUT);
});

test('映射冲突:旧标签被其它 FEC 复用,原 stale 绑定失效', () => {
  const input = baseInput({
    restartFlags: [{ router: 'R2', restarting: true }],
    events: [
      { type: 'session-down', session: 's1', time: 10 },
      { type: 'session-up', session: 's1', time: 20 },
      { type: 'mapping', fec: 'fec2', session: 's1', label: 100, time: 25 },
    ],
  });
  input.fecs.push({ id: 'fec2', prefix: '10.0.1.0/24' });
  input.mappings = [{ fec: 'fec1', session: 's1', label: 100 }];
  input.nextHops = [{ fec: 'fec1', via: 'R2' }, { fec: 'fec2', via: 'R2' }];
  input.lspPaths.push({ fec: 'fec2', path: ['R1', 'R2', 'R5'], state: 'up' });

  const report = new LdpGrValidator(input).run();
  const fec1 = report.summary.fec1;
  assert.equal(fec1.available, false);
  assert.equal(fec1.blackholeReason, REASON.LABEL_REUSED);

  const fec2 = report.summary.fec2;
  assert.equal(fec2.status, 'available');
  assert.equal(fec2.retainedLabel, 100);
});

test('重启端提前发送新映射:stale 未到期即被新标签替换', () => {
  const input = baseInput({
    restartFlags: [{ router: 'R2', restarting: true }],
    events: [
      { type: 'session-down', session: 's1', time: 10 },
      { type: 'session-up', session: 's1', time: 20 },
      { type: 'mapping', fec: 'fec1', session: 's1', label: 160, time: 25 },
    ],
  });
  input.mappings = [{ fec: 'fec1', session: 's1', label: 100 }];
  input.nextHops = [{ fec: 'fec1', via: 'R2' }];

  const fec1 = new LdpGrValidator(input).run().summary.fec1;
  assert.equal(fec1.status, 'available');
  assert.equal(fec1.retainedLabel, 160);
  assert.equal(fec1.blackholeReason, null);
});

test('路径撤销:握手成功但 LSP 路径未恢复仍是黑洞', () => {
  const input = baseInput({
    restartFlags: [{ router: 'R2', restarting: true }],
    events: [
      { type: 'session-down', session: 's1', time: 10 },
      { type: 'path-change', fec: 'fec1', state: 'down', time: 11 },
      { type: 'session-up', session: 's1', time: 20 },
      { type: 'mapping', fec: 'fec1', session: 's1', label: 100, time: 25 },
    ],
  });
  input.mappings = [{ fec: 'fec1', session: 's1', label: 100 }];
  input.nextHops = [{ fec: 'fec1', via: 'R2' }];

  const fec1 = new LdpGrValidator(input).run().summary.fec1;
  assert.equal(fec1.available, false);
  assert.equal(fec1.blackholeReason, REASON.PATH_BROKEN);
});

test('下一跳不可达:映射有效但转发黑洞', () => {
  const input = baseInput({
    events: [{ type: 'nexthop-change', fec: 'fec1', via: 'R2', reachable: false, time: 5 }],
  });
  input.mappings = [{ fec: 'fec1', session: 's1', label: 100 }];
  input.nextHops = [{ fec: 'fec1', via: 'R2' }];

  const fec1 = new LdpGrValidator(input).run().summary.fec1;
  assert.equal(fec1.available, false);
  assert.equal(fec1.blackholeReason, REASON.NEXTHOP_UNREACHABLE);
});

test('会话抖动:窗口内反复 down 触发阻尼,映射不再可用', () => {
  const input = baseInput({
    restartFlags: [{ router: 'R2', restarting: true }],
    events: [
      { type: 'session-down', session: 's1', time: 10 },
      { type: 'session-up', session: 's1', time: 15 },
      { type: 'mapping', fec: 'fec1', session: 's1', label: 100, time: 16 },
      { type: 'session-down', session: 's1', time: 20 },
      { type: 'session-up', session: 's1', time: 25 },
      { type: 'mapping', fec: 'fec1', session: 's1', label: 100, time: 26 },
      { type: 'session-down', session: 's1', time: 30 },
      { type: 'session-up', session: 's1', time: 35 },
      { type: 'mapping', fec: 'fec1', session: 's1', label: 100, time: 36 },
    ],
  });
  input.mappings = [{ fec: 'fec1', session: 's1', label: 100 }];
  input.nextHops = [{ fec: 'fec1', via: 'R2' }];

  const fec1 = new LdpGrValidator(input).run().summary.fec1;
  assert.equal(fec1.available, false);
  assert.equal(fec1.blackholeReason, REASON.SESSION_FLAPPING);
});

test('非 GR 会话中断:标签立即撤销,不进入 stale', () => {
  const input = baseInput({
    sessions: [
      { id: 's1', local: 'R1', peer: 'R2', grCapable: false },
    ],
    events: [{ type: 'session-down', session: 's1', time: 10 }],
  });
  input.mappings = [{ fec: 'fec1', session: 's1', label: 100 }];
  input.nextHops = [{ fec: 'fec1', via: 'R2' }];

  const fec1 = new LdpGrValidator(input).run().summary.fec1;
  assert.equal(fec1.status, 'down');
  assert.equal(fec1.blackholeReason, REASON.NO_BINDING);
});
