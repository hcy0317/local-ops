'use strict';

/* 状态刷新节奏：正常情况下由服务端事件推送驱动，只有推送不可用时才退回轮询。
   轮询间隔是保底手段，不再是对外承诺的刷新频率。 */

export const POLL_INTERVAL_MS = 2000;
/* 推送静默超过该时长即视为不可用（代理缓冲、连接半死），退回轮询。 */
export const STREAM_SILENCE_MS = 20000;

export function stateStreamUrl(visible) {
  return '/api/events?visible=' + (visible ? '1' : '0');
}

/* 服务端推送帧 → {version, state}；缺字段或版本回退一律丢弃。 */
export function decodeStateEvent(rawData, lastEventId, appliedVersion = 0) {
  if (typeof rawData !== 'string' || !rawData) return null;
  let payload;
  try {
    payload = JSON.parse(rawData);
  } catch (error) {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;
  const state = payload.state;
  if (!state || typeof state !== 'object') return null;
  const version = Number(lastEventId !== undefined && lastEventId !== null
    && lastEventId !== '' ? lastEventId : payload.version);
  if (!Number.isFinite(version)) return null;
  if (version <= Number(appliedVersion || 0)) return null;
  return { version, state };
}

/* 推送可用（且没有静默）时不安排轮询；返回 null 表示交给事件驱动。 */
export function nextPollDelay({ streamLive = false, silent = false } = {}) {
  if (streamLive && !silent) return null;
  return POLL_INTERVAL_MS;
}

export function streamIsSilent({ now, lastEventAt, connectedAt }) {
  const anchor = Number(lastEventAt) || Number(connectedAt) || 0;
  if (!anchor) return false;
  return now - anchor > STREAM_SILENCE_MS;
}

/* CONNECTING 不是可用状态：只有服务端真的完成过握手才由推送接管，
   否则必须保留轮询兜底。 */
export function streamIsLive({
  available = false,
  readyState,
  opened = false,
  silent = false,
} = {}) {
  return !!available && readyState !== 2 && opened === true && !silent;
}
