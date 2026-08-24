'use strict';

const LIFECYCLE_STATUSES = new Set([
  'stopped', 'starting', 'running', 'stopping', 'orphaned', 'unknown',
]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function normalizedStatus(app) {
  const value = app && app.lifecycleStatus;
  if (LIFECYCLE_STATUSES.has(value)) return value;
  return app && app.running ? 'running' : 'stopped';
}

function generationId(app) {
  const identity = app && app.runtimeIdentity;
  const value = identity && identity.generationId;
  return typeof value === 'string' && value ? value : null;
}

/* Capture once when user intent begins. Callers keep this immutable snapshot
   through confirmation so a later poll cannot substitute a newer generation. */
export function lifecycleSnapshot(app, platform = 'unknown') {
  const windows = platform === 'windows';
  const macos = platform === 'macos';
  const hasExplicitStatus = !!app && LIFECYCLE_STATUSES.has(app.lifecycleStatus);
  const hasExplicitControl = !!app && typeof app.controlAvailable === 'boolean';
  const externalScheduled = !!app
    && app.runtimeSource === 'windowsTaskScheduler';
  const externalDocker = !!app
    && (app.runtimeSource === 'dockerCompose'
      || app.runtimeSource === 'dockerContainer');
  const externalProgram = !!app
    && app.runtimeSource === 'windowsElevationBroker';
  const status = (!windows && !macos) || (windows && (!hasExplicitStatus || !hasExplicitControl))
    ? 'unknown' : normalizedStatus(app);
  const generation = generationId(app);
  const expectedProcesses = externalProgram && Array.isArray(app.observedProcesses)
    ? app.observedProcesses
      .filter(item => item && Number.isInteger(item.pid) && item.pid > 0
        && Number.isFinite(item.createTime) && item.createTime > 0)
      .map(item => Object.freeze({ pid: item.pid, createTime: item.createTime }))
      .sort((left, right) => left.pid - right.pid)
    : [];
  const controlAvailable = windows
    ? !!app && app.controlAvailable === true
    : macos && app && typeof app.controlAvailable === 'boolean'
      ? app.controlAvailable
      : macos && (status === 'stopped' || status === 'running');
  const generationReady = externalScheduled || externalDocker
    || (externalProgram && expectedProcesses.length > 0) || macos || status === 'stopped'
    || (status === 'running' && UUID_RE.test(generation || ''));
  const canStart = controlAvailable && status === 'stopped';
  const canManage = controlAvailable && status === 'running' && generationReady;

  return Object.freeze({
    status,
    expectedGeneration: status === 'stopped' ? null : generation,
    expectedProcesses: Object.freeze(expectedProcesses),
    canStart,
    canManage,
    canDelete: externalScheduled || externalDocker || (!!app && app.deleteAvailable === true)
      || canStart || canManage,
    busy: status === 'starting' || status === 'stopping',
    uncertain: status === 'orphaned' || status === 'unknown',
  });
}

export function lifecyclePayload(snapshot, extra = {}) {
  const payload = { ...extra, expectedGeneration: snapshot.expectedGeneration };
  if (snapshot.expectedProcesses && snapshot.expectedProcesses.length) {
    payload.expectedProcesses = snapshot.expectedProcesses;
  }
  return payload;
}

export function sameLifecycleGeneration(snapshot, app, platform = 'unknown') {
  if (!snapshot || snapshot.status !== 'running') return false;
  const current = lifecycleSnapshot(app, platform);
  return current.canManage
    && current.expectedGeneration === snapshot.expectedGeneration
    && JSON.stringify(current.expectedProcesses) === JSON.stringify(snapshot.expectedProcesses);
}

export function isGenerationMismatch(result) {
  return !!result && result.code === 'GENERATION_MISMATCH';
}

export function isStopTimeout(result) {
  return !!result && result.code === 'STOP_TIMEOUT';
}

/* One user intent owns one mutation attempt and one post-mutation refresh.
   `mutate` is expected to use the UI's `act()` boundary, which turns network
   ambiguity into a null result without retrying the mutation. */
export async function runLifecycleMutation(mutate, refresh) {
  const result = await mutate();
  const stateIsFresh = await refresh(result) === true;
  return Object.freeze({ result, stateIsFresh });
}

export function canForceStopAfterTimeout({
  result,
  intent,
  currentApp,
  platform = 'unknown',
  stateIsFresh = false,
  forceCapable = false,
}) {
  return isStopTimeout(result)
    && stateIsFresh
    && forceCapable
    && sameLifecycleGeneration(intent, currentApp, platform);
}

/* The explicit boolean makes the second confirmation part of the executable
   contract. Callers still revalidate the current generation at confirmation. */
export async function runConfirmedForceStop({
  confirmed,
  timeoutResult,
  intent,
  currentApp,
  platform = 'unknown',
  stateIsFresh = false,
  forceCapable = false,
  mutate,
  refresh,
}) {
  if (confirmed !== true || !canForceStopAfterTimeout({
    result: timeoutResult,
    intent,
    currentApp,
    platform,
    stateIsFresh,
    forceCapable,
  })) {
    return Object.freeze({ forced: false, result: null, stateIsFresh: false });
  }
  const forceIntent = lifecycleSnapshot(currentApp, platform);
  const outcome = await runLifecycleMutation(
    () => mutate(lifecyclePayload(forceIntent, { force: true })),
    refresh,
  );
  return Object.freeze({ forced: true, ...outcome });
}
