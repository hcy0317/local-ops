'use strict';

export function normalizeHostCpuPercent(corePercent, logicalCpuCount) {
  const total = Number(corePercent);
  if (!Number.isFinite(total) || total <= 0) return 0;
  const cores = Number(logicalCpuCount);
  const capacity = Number.isFinite(cores) && cores > 0 ? cores : 1;
  return Math.min(100, total / capacity);
}
