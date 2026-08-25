'use strict';

export class ConnectionFailureTracker {
  constructor(threshold = 2) {
    this.threshold = Math.max(1, Number(threshold) || 1);
    this.connectionFailures = 0;
    this.stateFailures = 0;
  }

  recordSuccess() {
    this.connectionFailures = 0;
    this.stateFailures = 0;
  }

  recordFailure({ controlPlaneReachable = false, authRejected = false } = {}) {
    this.stateFailures += 1;
    if (authRejected) {
      this.connectionFailures = this.threshold;
    } else if (controlPlaneReachable) {
      this.connectionFailures = 0;
    } else {
      this.connectionFailures += 1;
    }
    return Object.freeze({
      disconnected: this.connectionFailures >= this.threshold,
      stateStale: this.stateFailures >= this.threshold,
    });
  }
}

export function buildStateHealthNotice(data, {
  stateRefreshDelayed = false,
  componentNames = {},
} = {}) {
  const messages = [];
  if (stateRefreshDelayed) {
    messages.push('状态刷新延迟，控制台仍在线，正在自动重试');
  }
  if (!data) return messages.length ? messages.join('；') + '。' : '';

  const health = data.configHealth || {};
  if (data.degraded) {
    const components = [...new Set((data.degradedReasons || [])
      .map(item => componentNames[item && item.component] || '部分组件'))];
    messages.push('降级运行：' + (components.length ? components.join('、') : '部分组件') +
      '数据可能不完整');
  }
  if (health.writable === false) {
    messages.push('配置处于只读保护，修改不会保存');
  } else if (health.recoveredFromBackup) {
    messages.push('配置已从备份恢复，请核对内容');
  }
  return messages.length ? messages.join('；') + '。' : '';
}
