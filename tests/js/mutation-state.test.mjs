import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  commitMutationFeedback,
  keepAliveFeedbackPatch,
  reconcileMutationState,
} from '../../static/js/mutation-state.js';
import {
  elevatedControlGate,
  lifecycleSnapshot,
} from '../../static/js/lifecycle.js';

function baseState() {
  return {
    platform: 'windows',
    elevationBroker: {
      installed: true,
      verified: true,
      unlocked: false,
      sessionAuthorized: false,
    },
    apps: [
      {
        id: 'scheduled',
        name: 'Guard',
        command: 'scheduled',
        cwd: 'C:\\Tasks',
        kind: 'service',
        scheduledTaskPath: '\\TaskA',
        runtimeSource: 'windowsTaskScheduler',
        lifecycleStatus: 'running',
        controlAvailable: true,
        running: true,
        scheduledTask: { path: '\\TaskA', state: 'running', enabled: true },
        keepAlive: false,
        desiredRunning: false,
        keepAliveRequiresElevation: true,
        keepAliveAuthorized: false,
      },
      {
        id: 'docker',
        name: 'Docker',
        command: 'docker compose up',
        kind: 'service',
        dockerResource: { kind: 'compose', project: 'alpha' },
        docker: { running: true, projectName: 'alpha' },
        runtimeSource: 'dockerCompose',
        lifecycleStatus: 'running',
        controlAvailable: true,
        running: true,
        keepAliveRequiresElevation: true,
        keepAliveAuthorized: false,
      },
      {
        id: 'attached',
        name: 'Attached',
        command: 'python app.py',
        cwd: 'C:\\Attached',
        port: 8080,
        kind: 'service',
        attached: true,
        runtimeSource: 'managed',
        lifecycleStatus: 'running',
        controlAvailable: true,
        running: true,
        keepAliveRequiresElevation: true,
        keepAliveAuthorized: false,
      },
      {
        id: 'protected',
        name: 'Protected',
        kind: 'program',
        elevated: true,
        runtimeSource: 'windowsElevationBroker',
        lifecycleStatus: 'running',
        controlAvailable: false,
        running: true,
        observedRestricted: true,
        elevationBroker: {
          installed: true,
          verified: true,
          unlocked: false,
          sessionAuthorized: false,
        },
      },
      {
        id: 'stopped-admin',
        name: 'Stopped admin',
        kind: 'program',
        elevated: true,
        runtimeSource: 'windowsElevationBroker',
        lifecycleStatus: 'stopped',
        controlAvailable: false,
        running: false,
        elevationBroker: {
          installed: true,
          verified: true,
          unlocked: false,
          sessionAuthorized: false,
        },
      },
    ],
  };
}

test('successful mutation commits feedback before an unresolved refresh', () => {
  let committed = null;
  let refreshCalls = 0;
  const never = new Promise(() => {});

  const next = commitMutationFeedback({
    data: baseState(),
    mutation: {
      type: 'app-patch',
      appId: 'scheduled',
      patch: { keepAlive: true, desiredRunning: true },
    },
    commit: value => { committed = value; },
    refresh: () => { refreshCalls += 1; return never; },
  });

  assert.equal(next.apps[0].keepAlive, true);
  assert.equal(committed.apps[0].desiredRunning, true);
  assert.equal(refreshCalls, 1);
});

test('app upsert preserves live fields and creates a pending card immediately', () => {
  const updated = reconcileMutationState(baseState(), {
    type: 'app-upsert',
    app: { id: 'scheduled', name: 'Renamed', kind: 'service' },
  });
  assert.equal(updated.apps[0].name, 'Renamed');
  assert.equal(updated.apps[0].running, true);

  const created = reconcileMutationState(updated, {
    type: 'app-upsert',
    app: {
      id: 'new-card',
      name: 'New card',
      kind: 'service',
      command: 'python app.py',
      port: 8080,
    },
  });
  const card = created.apps.at(-1);
  assert.equal(card.id, 'new-card');
  assert.equal(card.lifecycleStatus, 'unknown');
  assert.equal(card.controlAvailable, false);
  assert.equal(card.optimisticPending, true);
});

test('lifecycle edits discard prior scheduled and Docker authority', () => {
  const scheduled = reconcileMutationState(baseState(), {
    type: 'app-upsert',
    app: {
      id: 'scheduled',
      name: 'Guard',
      command: 'scheduled',
      cwd: 'C:\\Tasks',
      kind: 'service',
      scheduledTaskPath: '\\TaskB',
      dockerResource: null,
      elevated: false,
      port: null,
    },
  }).apps.find(app => app.id === 'scheduled');
  const scheduledIntent = lifecycleSnapshot(scheduled, 'windows');
  assert.equal(scheduled.runtimeSource, 'windowsTaskScheduler');
  assert.equal(scheduled.lifecycleStatus, 'unknown');
  assert.equal(scheduled.controlAvailable, false);
  assert.equal(scheduled.running, false);
  assert.equal(scheduled.scheduledTask, null);
  assert.equal(scheduled.runtimeIdentity, null);
  assert.deepEqual(scheduled.observedProcesses, []);
  assert.equal(scheduledIntent.canManage, false);
  assert.equal(scheduledIntent.canStart, false);

  const docker = reconcileMutationState(baseState(), {
    type: 'app-upsert',
    app: {
      id: 'docker',
      name: 'Docker',
      command: 'docker compose up',
      kind: 'service',
      scheduledTaskPath: null,
      dockerResource: { kind: 'compose', project: 'beta' },
      elevated: false,
      port: null,
    },
  }).apps.find(app => app.id === 'docker');
  const dockerIntent = lifecycleSnapshot(docker, 'windows');
  assert.equal(docker.runtimeSource, 'dockerCompose');
  assert.equal(docker.lifecycleStatus, 'unknown');
  assert.equal(docker.controlAvailable, false);
  assert.equal(docker.docker, null);
  assert.equal(dockerIntent.canManage, false);
  assert.equal(dockerIntent.canStart, false);
});

test('lifecycle edits revoke pending keep-alive authority', () => {
  const managed = {
    id: 'managed',
    name: 'Managed',
    command: 'python app.py',
    commandSpec: null,
    cwd: 'C:\\Managed',
    port: 8080,
    kind: 'service',
    scheduledTaskPath: null,
    dockerResource: null,
    elevated: false,
    runtimeSource: 'managed',
    lifecycleStatus: 'running',
    controlAvailable: true,
    running: true,
    keepAliveAvailable: true,
    keepAliveRequiresElevation: false,
    keepAliveAuthorized: true,
    keepAlivePersistentAuthorization: false,
  };
  const data = { ...baseState(), apps: [managed] };

  const renamed = reconcileMutationState(data, {
    type: 'app-upsert', app: { id: 'managed', name: 'Renamed' },
  }).apps[0];
  assert.equal(renamed.running, true);
  assert.equal(renamed.controlAvailable, true);
  assert.equal(renamed.keepAliveAvailable, true);

  const mutations = [
    {
      id: 'managed', name: 'Managed', command: 'scheduled', commandSpec: null,
      cwd: 'C:\\Managed', port: null, kind: 'service',
      scheduledTaskPath: '\\TaskB', dockerResource: null, elevated: false,
    },
    {
      id: 'managed', name: 'Managed', command: 'admin.exe',
      commandSpec: { mode: 'direct', executable: 'C:\\Program Files\\Admin\\admin.exe', args: [] },
      cwd: 'C:\\Program Files\\Admin', port: null, kind: 'program',
      scheduledTaskPath: null, dockerResource: null, elevated: true,
    },
    {
      id: 'managed', name: 'Managed', command: 'python app.py', commandSpec: null,
      cwd: 'C:\\Managed', port: null, kind: 'task',
      scheduledTaskPath: null, dockerResource: null, elevated: false,
    },
  ];
  for (const app of mutations) {
    const pending = reconcileMutationState(data, {
      type: 'app-upsert', app,
    }).apps[0];
    assert.equal(pending.lifecycleStatus, 'unknown');
    assert.equal(pending.controlAvailable, false);
    assert.equal(pending.keepAliveAvailable, false);
    assert.equal(pending.keepAliveAuthorized, false);
    assert.equal(pending.keepAlivePersistentAuthorization, false);
  }
});

test('delete removes only the committed card', () => {
  const next = reconcileMutationState(baseState(), {
    type: 'app-delete', appId: 'scheduled',
  });
  assert.deepEqual(next.apps.map(app => app.id), [
    'docker', 'attached', 'protected', 'stopped-admin',
  ]);
});

test('keep-alive feedback mirrors persistent authorization semantics', () => {
  const result = { keepAlive: true, desiredRunning: true };
  const ordinary = keepAliveFeedbackPatch({
    running: true,
    keepAliveRequiresElevation: false,
    keepAliveAuthorized: true,
  }, result);
  const privileged = keepAliveFeedbackPatch({
    running: false,
    keepAliveRequiresElevation: true,
    keepAliveAuthorized: true,
  }, result);
  const disabledWithoutSession = keepAliveFeedbackPatch({
    running: true,
    keepAliveRequiresElevation: true,
    keepAliveAuthorized: true,
  }, { keepAlive: false, desiredRunning: false }, false);
  const disabledWithSession = keepAliveFeedbackPatch({
    running: true,
    keepAliveRequiresElevation: true,
    keepAliveAuthorized: true,
  }, { keepAlive: false, desiredRunning: false }, true);

  assert.equal(ordinary.keepAlivePersistentAuthorization, false);
  assert.equal(ordinary.keepAliveAuthorized, true);
  assert.equal(ordinary.keepAliveStatus.state, 'watching');
  assert.equal(privileged.keepAlivePersistentAuthorization, true);
  assert.equal(privileged.keepAliveAuthorized, true);
  assert.equal(privileged.keepAliveStatus.state, 'starting');
  assert.equal(disabledWithoutSession.keepAliveAuthorized, false);
  assert.equal(disabledWithSession.keepAliveAuthorized, true);
});

test('unlock updates session feedback without granting protected process control', () => {
  const next = reconcileMutationState(baseState(), { type: 'broker-unlocked' });

  assert.equal(next.elevationBroker.unlocked, true);
  assert.equal(next.elevationBroker.sessionAuthorized, true);
  const protectedApp = next.apps.find(app => app.id === 'protected');
  const stoppedApp = next.apps.find(app => app.id === 'stopped-admin');
  for (const id of ['scheduled', 'docker', 'attached']) {
    assert.equal(next.apps.find(app => app.id === id).keepAliveAuthorized, true);
  }
  assert.equal(protectedApp.controlAvailable, false);
  assert.equal(protectedApp.elevationBroker.sessionAuthorized, true);
  assert.equal(stoppedApp.controlAvailable, false);
  assert.equal(stoppedApp.keepAliveAuthorized, true);
  const stoppedIntent = lifecycleSnapshot(stoppedApp, 'windows');
  assert.equal(stoppedIntent.canStart, false);
  assert.equal(elevatedControlGate(stoppedApp, stoppedIntent), 'unavailable');
});

test('successful card mutations commit locally instead of awaiting a cold poll', () => {
  const source = path => readFileSync(
    new URL('../../' + path, import.meta.url), 'utf8'
  );
  const app = source('static/app.js');
  const overlays = source('static/js/overlays.js');
  const launchpad = source('static/js/launchpad.js');

  assert.match(app, /window\.__commitMutation = mutation => commitMutationFeedback/);
  assert.match(overlays, /window\.__commitMutation\(\{ type: 'broker-unlocked' \}\)/);
  assert.match(overlays, /window\.__commitMutation\(\{ type: 'app-upsert', app \}\)/);
  assert.match(launchpad, /type: 'app-patch',[\s\S]*keepAliveFeedbackPatch/);
  assert.match(launchpad, /type: 'app-delete', appId: app\.id/);
  assert.match(launchpad, /app\.optimisticPending && lifecycle\.status === 'unknown'/);
});
