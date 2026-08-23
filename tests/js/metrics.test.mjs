import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeHostCpuPercent } from '../../static/js/metrics.js';

test('服务 CPU 核心合计按逻辑核心数归一为整机占比', () => {
  assert.equal(normalizeHostCpuPercent(251.2, 32), 7.85);
  assert.equal(normalizeHostCpuPercent(3200, 32), 100);
  assert.equal(normalizeHostCpuPercent(6400, 32), 100);
});

test('CPU 归一化拒绝负数和无效输入并兼容旧后端', () => {
  assert.equal(normalizeHostCpuPercent(-1, 32), 0);
  assert.equal(normalizeHostCpuPercent('unknown', 32), 0);
  assert.equal(normalizeHostCpuPercent(251.2, null), 100);
});
