/* lifecycle.js pure-function contracts (node --test, no DOM dependency).
   These tests lock the Phase 4 generation snapshot and fail-closed UI rules. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  lifecyclePayload,
  lifecycleSnapshot,
  sameLifecycleGeneration,
  isGenerationMismatch,
  isStopTimeout,
  runLifecycleMutation,
  canForceStopAfterTimeout,
  runConfirmedForceStop,
} from '../../static/js/lifecycle.js';

const GENERATION_A = '3d6448f0-87a0-4ace-baad-3b80abca9e3e';
const GENERATION_B = '9b45ada3-7e22-48c5-aaf3-1da8df695241';

function runningApp(generation = GENERATION_A) {
  return {
    lifecycleStatus: 'running',
    controlAvailable: true,
    running: true,
    runtimeIdentity: { generationId: generation },
  };
}

test('stopped Windows app captures an explicit null generation', () => {
  const snapshot = lifecycleSnapshot({
    lifecycleStatus: 'stopped',
    controlAvailable: true,
    running: false,
    runtimeIdentity: null,
  }, 'windows');

  assert.equal(snapshot.expectedGeneration, null);
  assert.equal(snapshot.canStart, true);
  assert.equal(snapshot.canManage, false);
  assert.equal(snapshot.canDelete, true);
  assert.deepEqual(lifecyclePayload(snapshot), { expectedGeneration: null });
});

test('running Windows app captures the exact verified generation', () => {
  const snapshot = lifecycleSnapshot(runningApp(), 'windows');

  assert.equal(snapshot.expectedGeneration, GENERATION_A);
  assert.equal(snapshot.canStart, false);
  assert.equal(snapshot.canManage, true);
  assert.equal(snapshot.canDelete, true);
  assert.deepEqual(
    lifecyclePayload(snapshot, { force: false }),
    { expectedGeneration: GENERATION_A, force: false },
  );
});

test('running Windows scheduled task is controllable without a managed generation', () => {
  const snapshot = lifecycleSnapshot({
    lifecycleStatus: 'running',
    controlAvailable: true,
    running: true,
    runtimeIdentity: null,
    runtimeSource: 'windowsTaskScheduler',
  }, 'windows');

  assert.equal(snapshot.expectedGeneration, null);
  assert.equal(snapshot.canManage, true);
  assert.equal(snapshot.canDelete, true);
});

test('running Docker resource is controllable without a managed generation', () => {
  for (const runtimeSource of ['dockerCompose', 'dockerContainer']) {
    const snapshot = lifecycleSnapshot({
      lifecycleStatus: 'running',
      controlAvailable: true,
      running: true,
      runtimeIdentity: null,
      runtimeSource,
    }, 'windows');

    assert.equal(snapshot.expectedGeneration, null, runtimeSource);
    assert.equal(snapshot.canManage, true, runtimeSource);
    assert.equal(snapshot.canDelete, true, runtimeSource);
  }
});

test('owned elevated program freezes exact observed processes for stop control', () => {
  const app = {
    lifecycleStatus: 'running',
    controlAvailable: true,
    running: true,
    runtimeIdentity: null,
    runtimeSource: 'windowsElevationBroker',
    observedProcesses: [
      { pid: 1201, createTime: 1001.5 },
      { pid: 1200, createTime: 1000.5 },
    ],
  };
  const snapshot = lifecycleSnapshot(app, 'windows');

  assert.equal(snapshot.expectedGeneration, null);
  assert.equal(snapshot.canManage, true);
  assert.deepEqual(snapshot.expectedProcesses, [
    { pid: 1200, createTime: 1000.5 },
    { pid: 1201, createTime: 1001.5 },
  ]);
  assert.deepEqual(lifecyclePayload(snapshot, { force: false }), {
    expectedGeneration: null,
    expectedProcesses: [
      { pid: 1200, createTime: 1000.5 },
      { pid: 1201, createTime: 1001.5 },
    ],
    force: false,
  });
});

test('elevated program stop intent fails closed when an observed PID is reused', () => {
  const app = {
    lifecycleStatus: 'running',
    controlAvailable: true,
    running: true,
    runtimeIdentity: null,
    runtimeSource: 'windowsElevationBroker',
    observedProcesses: [{ pid: 1200, createTime: 1000.5 }],
  };
  const snapshot = lifecycleSnapshot(app, 'windows');

  assert.equal(sameLifecycleGeneration(snapshot, app, 'windows'), true);
  app.observedProcesses = [{ pid: 1200, createTime: 2000.5 }];
  assert.equal(sameLifecycleGeneration(snapshot, app, 'windows'), false);
});

test('captured intent never substitutes a newer generation', () => {
  const app = runningApp();
  const snapshot = lifecycleSnapshot(app, 'windows');
  app.runtimeIdentity.generationId = GENERATION_B;

  assert.equal(lifecyclePayload(snapshot).expectedGeneration, GENERATION_A);
});

test('orphaned, unknown, busy, and malformed Windows identities fail closed', () => {
  for (const lifecycleStatus of ['orphaned', 'unknown', 'starting', 'stopping']) {
    const snapshot = lifecycleSnapshot({
      lifecycleStatus,
      controlAvailable: true,
      running: lifecycleStatus === 'stopping',
      runtimeIdentity: { generationId: GENERATION_A },
    }, 'windows');
    assert.equal(snapshot.canStart, false, lifecycleStatus);
    assert.equal(snapshot.canManage, false, lifecycleStatus);
    assert.equal(snapshot.canDelete, false, lifecycleStatus);
  }

  const malformed = lifecycleSnapshot(runningApp('not-a-generation'), 'windows');
  assert.equal(malformed.canManage, false);
  assert.equal(malformed.canDelete, false);
});

test('verified terminal Windows card can be removed without gaining process control', () => {
  const snapshot = lifecycleSnapshot({
    lifecycleStatus: 'unknown',
    controlAvailable: false,
    deleteAvailable: true,
    running: false,
    runtimeIdentity: { generationId: GENERATION_A },
  }, 'windows');

  assert.equal(snapshot.canManage, false);
  assert.equal(snapshot.canDelete, true);
  assert.equal(snapshot.expectedGeneration, GENERATION_A);
});

test('Windows state missing lifecycle authority fields fails closed', () => {
  for (const app of [
    { running: false },
    { running: true, runtimeIdentity: { generationId: GENERATION_A } },
    { lifecycleStatus: 'stopped', running: false },
    { lifecycleStatus: 'running', running: true, runtimeIdentity: { generationId: GENERATION_A } },
  ]) {
    const snapshot = lifecycleSnapshot(app, 'windows');
    assert.equal(snapshot.status, 'unknown');
    assert.equal(snapshot.canStart, false);
    assert.equal(snapshot.canManage, false);
    assert.equal(snapshot.canDelete, false);
  }
});

test('legacy macOS running state remains controllable with additive null generation', () => {
  const snapshot = lifecycleSnapshot({ running: true }, 'macos');

  assert.equal(snapshot.status, 'running');
  assert.equal(snapshot.expectedGeneration, null);
  assert.equal(snapshot.canManage, true);
});

test('unknown platform never inherits the macOS compatibility fallback', () => {
  const snapshot = lifecycleSnapshot({ running: true }, 'unknown');

  assert.equal(snapshot.status, 'unknown');
  assert.equal(snapshot.canStart, false);
  assert.equal(snapshot.canManage, false);
  assert.equal(snapshot.canDelete, false);
});

test('same generation requires a currently verified controllable runtime', () => {
  const snapshot = lifecycleSnapshot(runningApp(), 'windows');

  assert.equal(sameLifecycleGeneration(snapshot, runningApp(), 'windows'), true);
  assert.equal(sameLifecycleGeneration(snapshot, runningApp(GENERATION_B), 'windows'), false);
  assert.equal(sameLifecycleGeneration(snapshot, {
    ...runningApp(), lifecycleStatus: 'orphaned', controlAvailable: false,
  }, 'windows'), false);
});

test('stable lifecycle errors are classified without implying a retry', () => {
  assert.equal(isGenerationMismatch({ code: 'GENERATION_MISMATCH' }), true);
  assert.equal(isGenerationMismatch({ code: 'STOP_TIMEOUT' }), false);
  assert.equal(isGenerationMismatch(null), false);
  assert.equal(isStopTimeout({ code: 'STOP_TIMEOUT' }), true);
  assert.equal(isStopTimeout({ code: 'GENERATION_MISMATCH' }), false);
  assert.equal(isStopTimeout(null), false);
});

const FAILURE_RESULTS = [
  ['generation mismatch', { ok: false, code: 'GENERATION_MISMATCH' }],
  ['network ambiguity', null],
  ['HTTP 5xx', { ok: false, error: 'HTTP 500' }],
];

const SINGLE_CALLERS = [
  ['card start', () => lifecycleSnapshot({
    lifecycleStatus: 'stopped', controlAvailable: true, running: false,
  }, 'windows'), {}],
  ['card stop', () => lifecycleSnapshot(runningApp(), 'windows'), { force: false }],
  ['card restart', () => lifecycleSnapshot(runningApp(), 'windows'), {}],
  ['card delete', () => lifecycleSnapshot(runningApp(), 'windows'), {}],
  ['palette toggle', () => lifecycleSnapshot(runningApp(), 'windows'), { force: false }],
  ['palette restart', () => lifecycleSnapshot(runningApp(), 'windows'), {}],
  ['edit stop', () => lifecycleSnapshot(runningApp(), 'windows'), { force: false }],
  ['edit save', () => lifecycleSnapshot(runningApp(), 'windows'), { name: 'renamed' }],
  ['managed port stop', () => lifecycleSnapshot(runningApp(), 'windows'), { force: false }],
];

for (const [caller, captureIntent, extra] of SINGLE_CALLERS) {
  test(`${caller} freezes generation and never retries ambiguous failures`, async () => {
    for (const [failure, response] of FAILURE_RESULTS) {
      const intent = captureIntent();
      const expectedGeneration = intent.expectedGeneration;
      let mutationCalls = 0;
      let refreshCalls = 0;
      const payloads = [];

      const outcome = await runLifecycleMutation(
        async () => {
          mutationCalls += 1;
          payloads.push(lifecyclePayload(intent, extra));
          return response;
        },
        async result => {
          assert.equal(result, response, `${caller}: ${failure}`);
          refreshCalls += 1;
          return true;
        },
      );

      assert.equal(mutationCalls, 1, `${caller}: ${failure}`);
      assert.equal(refreshCalls, 1, `${caller}: ${failure}`);
      assert.equal(payloads[0].expectedGeneration, expectedGeneration, `${caller}: ${failure}`);
      assert.equal(outcome.result, response, `${caller}: ${failure}`);
      assert.equal(outcome.stateIsFresh, true, `${caller}: ${failure}`);
    }
  });
}

test('batch stop freezes every item and refreshes once without mutation retry', async () => {
  for (const [failure, response] of FAILURE_RESULTS) {
    const intents = [
      lifecycleSnapshot(runningApp(GENERATION_A), 'windows'),
      lifecycleSnapshot(runningApp(GENERATION_B), 'windows'),
    ];
    const mutationCalls = new Map();
    let refreshCalls = 0;
    const payloads = [];

    await runLifecycleMutation(
      async () => {
        for (const [index, intent] of intents.entries()) {
          mutationCalls.set(index, (mutationCalls.get(index) || 0) + 1);
          payloads.push(lifecyclePayload(intent, { force: false }));
        }
        return response;
      },
      async () => { refreshCalls += 1; return true; },
    );

    assert.deepEqual([...mutationCalls.values()], [1, 1], failure);
    assert.equal(refreshCalls, 1, failure);
    assert.deepEqual(
      payloads.map(payload => payload.expectedGeneration),
      [GENERATION_A, GENERATION_B],
      failure,
    );
  }
});

test('STOP_TIMEOUT force eligibility requires fresh same-generation capability', () => {
  const intent = lifecycleSnapshot(runningApp(GENERATION_A), 'windows');
  const timeout = { ok: false, code: 'STOP_TIMEOUT' };

  assert.equal(canForceStopAfterTimeout({
    result: timeout,
    intent,
    currentApp: runningApp(GENERATION_A),
    platform: 'windows',
    stateIsFresh: true,
    forceCapable: true,
  }), true);
  for (const override of [
    { stateIsFresh: false },
    { forceCapable: false },
    { currentApp: runningApp(GENERATION_B) },
    { result: { ok: false, code: 'GENERATION_MISMATCH' } },
  ]) {
    assert.equal(canForceStopAfterTimeout({
      result: timeout,
      intent,
      currentApp: runningApp(GENERATION_A),
      platform: 'windows',
      stateIsFresh: true,
      forceCapable: true,
      ...override,
    }), false);
  }
});

test('force executes once only after explicit confirmation and refreshes once', async () => {
  const intent = lifecycleSnapshot(runningApp(GENERATION_A), 'windows');
  let forceCalls = 0;
  let refreshCalls = 0;
  let forcePayload = null;

  const outcome = await runConfirmedForceStop({
    confirmed: true,
    timeoutResult: { ok: false, code: 'STOP_TIMEOUT' },
    intent,
    currentApp: runningApp(GENERATION_A),
    platform: 'windows',
    forceCapable: true,
    stateIsFresh: true,
    mutate: async payload => {
      forceCalls += 1;
      forcePayload = payload;
      return { ok: true };
    },
    refresh: async () => { refreshCalls += 1; return true; },
  });

  assert.equal(outcome.forced, true);
  assert.equal(forceCalls, 1);
  assert.equal(refreshCalls, 1);
  assert.deepEqual(forcePayload, { expectedGeneration: GENERATION_A, force: true });
});

test('unconfirmed, stale, different-generation, and failed-refresh timeout paths never force', async () => {
  const intent = lifecycleSnapshot(runningApp(GENERATION_A), 'windows');
  const base = {
    confirmed: true,
    timeoutResult: { ok: false, code: 'STOP_TIMEOUT' },
    intent,
    currentApp: runningApp(GENERATION_A),
    platform: 'windows',
    forceCapable: true,
    stateIsFresh: true,
  };

  for (const override of [
    { confirmed: false },
    { stateIsFresh: false },
    { forceCapable: false },
    { currentApp: runningApp(GENERATION_B) },
  ]) {
    let forceCalls = 0;
    let refreshCalls = 0;
    const outcome = await runConfirmedForceStop({
      ...base,
      ...override,
      mutate: async () => { forceCalls += 1; return { ok: true }; },
      refresh: async () => { refreshCalls += 1; return true; },
    });
    assert.equal(outcome.forced, false);
    assert.equal(forceCalls, 0);
    assert.equal(refreshCalls, 0);
  }
});

test('all lifecycle caller classes route through the shared executable contract', () => {
  const source = path => readFileSync(new URL('../../' + path, import.meta.url), 'utf8');
  const app = source('static/app.js');
  const launchpad = source('static/js/launchpad.js');
  const overlays = source('static/js/overlays.js');
  const widgets = source('static/js/widgets.js');

  assert.match(app, /run: \(\) => toggleApp\(a\.id, null, intent\)/, 'palette toggle');
  assert.match(app, /restartAppFromPalette\(a\.id, intent, name\)/, 'palette restart');
  assert.equal((app.match(/await runLifecycleMutation\(/g) || []).length, 1);

  assert.match(launchpad, /capturedIntent \|\| lifecycleSnapshot/, 'card intent');
  assert.match(launchpad, /del\('\/api\/apps\/' \+ app\.id, lifecyclePayload\(intent\)\)/,
    'card delete');
  assert.match(launchpad, /'\/api\/apps\/' \+ owner\.appId \+ '\/stop'/,
    'managed port stop');
  assert.equal((launchpad.match(/await runLifecycleMutation\(/g) || []).length, 4);

  assert.match(overlays, /body\.expectedGeneration = editingAppOriginal\.lifecycle\.expectedGeneration/,
    'edit save');
  assert.equal((overlays.match(/await runLifecycleMutation\(/g) || []).length, 2);
  assert.match(overlays, /confirmed: true[\s\S]*runConfirmedForceStop|runConfirmedForceStop\([\s\S]*confirmed: true/,
    'second explicit force confirmation');

  assert.match(widgets, /item\.intent[\s\S]*lifecyclePayload\(item\.intent, \{ force: false \}\)/,
    'batch stop');
  assert.equal((widgets.match(/await runLifecycleMutation\(/g) || []).length, 1);
});
