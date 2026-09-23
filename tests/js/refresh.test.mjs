import test from 'node:test';
import assert from 'node:assert/strict';
import {
  POLL_INTERVAL_MS,
  STREAM_SILENCE_MS,
  decodeStateEvent,
  nextPollDelay,
  stateStreamUrl,
  streamIsLive,
  streamIsSilent,
} from '../../static/js/refresh.js';

test('事件流地址带上页面可见性，服务端据此决定推送节奏', () => {
  assert.equal(stateStreamUrl(true), '/api/events?visible=1');
  assert.equal(stateStreamUrl(false), '/api/events?visible=0');
});

test('解析事件帧并丢弃非法或回退的版本', () => {
  const frame = JSON.stringify({ version: 7, state: { services: [] } });

  assert.deepEqual(decodeStateEvent(frame, '7', 6), {
    version: 7,
    state: { services: [] },
  });
  assert.equal(decodeStateEvent(frame, '7', 7), null);
  assert.equal(decodeStateEvent('not json', '8', 0), null);
  assert.equal(decodeStateEvent(JSON.stringify({ version: 9 }), '9', 0), null);
  assert.equal(decodeStateEvent('', '1', 0), null);
});

test('缺 id 时退回帧内版本号，缺版本时丢弃', () => {
  const frame = JSON.stringify({ version: 12, state: { apps: [] } });

  assert.deepEqual(decodeStateEvent(frame, '', 0), {
    version: 12,
    state: { apps: [] },
  });
  assert.equal(decodeStateEvent(
    JSON.stringify({ state: { apps: [] } }), '', 0), null);
});

test('推送可用时不安排轮询，静默或断开才退回固定间隔', () => {
  assert.equal(nextPollDelay({ streamLive: true, silent: false }), null);
  assert.equal(nextPollDelay({ streamLive: true, silent: true }), POLL_INTERVAL_MS);
  assert.equal(nextPollDelay({ streamLive: false }), POLL_INTERVAL_MS);
  assert.equal(nextPollDelay(), POLL_INTERVAL_MS);
});

test('静默判据以最近一次事件为基准，未连接时不算静默', () => {
  assert.equal(streamIsSilent({ now: 1000, lastEventAt: 0, connectedAt: 0 }), false);
  assert.equal(streamIsSilent({
    now: 1000, lastEventAt: 0, connectedAt: 950,
  }), false);
  assert.equal(streamIsSilent({
    now: STREAM_SILENCE_MS + 1001, lastEventAt: 1000, connectedAt: 1000,
  }), true);
});

test('只有完成握手且未静默的长连接才接管刷新', () => {
  assert.equal(streamIsLive({
    available: true, readyState: 0, opened: false, silent: false,
  }), false);
  assert.equal(streamIsLive({
    available: true, readyState: 1, opened: true, silent: false,
  }), true);
  assert.equal(streamIsLive({
    available: true, readyState: 1, opened: true, silent: true,
  }), false);
  assert.equal(streamIsLive({
    available: true, readyState: 2, opened: true, silent: false,
  }), false);
});
