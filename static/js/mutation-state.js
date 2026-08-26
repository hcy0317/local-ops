'use strict';

const LIFECYCLE_CONFIG_FIELDS = [
  'command',
  'commandSpec',
  'cwd',
  'port',
  'kind',
  'scheduledTaskPath',
  'dockerResource',
  'elevated',
];

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort()
      .map(key => [key, canonicalValue(value[key])]));
  }
  return value == null ? null : value;
}

function lifecycleConfigChanged(current, next) {
  return LIFECYCLE_CONFIG_FIELDS.some(field => JSON.stringify(
    canonicalValue(current[field])
  ) !== JSON.stringify(canonicalValue(next[field])));
}

function inferredRuntimeSource(app) {
  if (app.scheduledTaskPath) return 'windowsTaskScheduler';
  if (app.dockerResource) {
    return app.dockerResource.kind === 'compose'
      || app.dockerResource.type === 'compose'
      ? 'dockerCompose' : 'dockerContainer';
  }
  if (app.elevated === true && app.kind === 'task') {
    return 'windowsElevationBrokerTask';
  }
  if (app.elevated === true && app.kind === 'program') {
    return 'windowsElevationBroker';
  }
  return 'managed';
}

function pendingApp(app) {
  const kind = app.kind || 'service';
  return {
    ...app,
    kind,
    runtimeSource: inferredRuntimeSource({ ...app, kind }),
    lifecycleStatus: 'unknown',
    controlAvailable: false,
    deleteAvailable: true,
    running: false,
    runtimeIdentity: null,
    pid: null,
    uptimeSec: null,
    scheduledTask: null,
    scheduledTaskControlAvailable: false,
    docker: null,
    observedProcesses: [],
    programStopAvailable: false,
    observedRestricted: false,
    runtimeIssue: null,
    keepAliveAvailable: false,
    keepAliveRequiresElevation: true,
    keepAlivePersistentAuthorization: false,
    keepAliveAuthorized: false,
    health: { status: 'unknown', blocking: false, issues: [] },
    ports: [],
    openHosts: {},
    listening: false,
    portOccupied: false,
    portOccupiedPid: null,
    portOwner: null,
    portConflict: false,
    portConflictApps: [],
    keepAliveStatus: {
      state: app.keepAlive ? 'waiting' : 'disabled',
      attempts: 0,
      nextRetryAt: null,
      nextObserveAt: null,
      error: null,
    },
    optimisticPending: true,
  };
}

export function reconcileMutationState(data, mutation) {
  if (!data || !mutation || !Array.isArray(data.apps)) return data;
  if (mutation.type === 'app-delete') {
    return {
      ...data,
      apps: data.apps.filter(app => app.id !== mutation.appId),
    };
  }
  if (mutation.type === 'app-patch') {
    return {
      ...data,
      apps: data.apps.map(app => app.id === mutation.appId
        ? { ...app, ...(mutation.patch || {}), optimisticPending: true }
        : app),
    };
  }
  if (mutation.type === 'app-upsert' && mutation.app) {
    const index = data.apps.findIndex(app => app.id === mutation.app.id);
    const apps = [...data.apps];
    if (index >= 0) {
      const configured = { ...apps[index], ...mutation.app };
      apps[index] = lifecycleConfigChanged(apps[index], configured)
        ? pendingApp(configured)
        : {
          ...configured,
          runtimeSource: inferredRuntimeSource(configured),
          optimisticPending: true,
        };
    } else {
      apps.push(pendingApp(mutation.app));
    }
    return { ...data, apps };
  }
  if (mutation.type === 'broker-unlocked') {
    const elevationBroker = {
      ...(data.elevationBroker || {}),
      unlocked: true,
      sessionAuthorized: true,
    };
    return {
      ...data,
      elevationBroker,
      apps: data.apps.map(app => {
        const keepAliveAuthorized = !app.keepAliveRequiresElevation
          || app.keepAlivePersistentAuthorization === true
          || elevationBroker.sessionAuthorized === true;
        const elevated = app.elevated === true
          || app.runtimeSource === 'windowsElevationBroker'
          || app.runtimeSource === 'windowsElevationBrokerTask';
        if (!elevated) return {
          ...app,
          keepAliveAuthorized,
          optimisticPending: true,
        };
        return {
          ...app,
          elevationBroker: {
            ...(app.elevationBroker || {}),
            ...elevationBroker,
          },
          keepAliveAuthorized,
          optimisticPending: true,
        };
      }),
    };
  }
  return data;
}

export function commitMutationFeedback({ data, mutation, commit, refresh }) {
  const next = reconcileMutationState(data, mutation);
  commit(next);
  const pending = refresh();
  if (pending && typeof pending.catch === 'function') pending.catch(() => {});
  return next;
}

export function keepAliveFeedbackPatch(app, result, sessionAuthorized = false) {
  const keepAlive = result && result.keepAlive === true;
  const desiredRunning = result && result.desiredRunning === true;
  const requiresElevation = app.keepAliveRequiresElevation === true;
  const persistentAuthorization = keepAlive && requiresElevation;
  return {
    keepAlive,
    desiredRunning,
    keepAlivePersistentAuthorization: persistentAuthorization,
    keepAliveAuthorized: !requiresElevation
      || persistentAuthorization
      || sessionAuthorized === true,
    keepAliveStatus: {
      state: keepAlive ? (app.running ? 'watching' : 'starting') : 'disabled',
      attempts: 0,
      nextRetryAt: null,
      nextObserveAt: null,
      error: null,
    },
  };
}
