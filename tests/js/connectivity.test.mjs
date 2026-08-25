import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildStateHealthNotice,
  ConnectionFailureTracker,
} from '../../static/js/connectivity.js';

test('状态刷新波动先由控制面健康检查消化，真实连续故障才提示断连', () => {
  const tracker = new ConnectionFailureTracker(2);

  assert.deepEqual(tracker.recordFailure({ controlPlaneReachable: true }), {
    disconnected: false,
    stateStale: false,
  });
  assert.deepEqual(tracker.recordFailure({ controlPlaneReachable: true }), {
    disconnected: false,
    stateStale: true,
  });
  assert.deepEqual(tracker.recordFailure(), {
    disconnected: false,
    stateStale: true,
  });
  assert.deepEqual(tracker.recordFailure(), {
    disconnected: true,
    stateStale: true,
  });
  tracker.recordSuccess();
  assert.deepEqual(tracker.recordFailure(), {
    disconnected: false,
    stateStale: false,
  });
  assert.deepEqual(tracker.recordFailure({ authRejected: true }), {
    disconnected: true,
    stateStale: true,
  });
});

test('冷启动尚无状态快照时仍展示状态刷新延迟', () => {
  assert.equal(
    buildStateHealthNotice(null, { stateRefreshDelayed: true }),
    '状态刷新延迟，控制台仍在线，正在自动重试。',
  );
  assert.equal(buildStateHealthNotice(null), '');
});
