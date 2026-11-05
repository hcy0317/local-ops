import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../../static/app.js', import.meta.url), 'utf8');
const section = source.slice(source.indexOf('let brokerPromptedConsolePid'),
  source.indexOf('/* ---------------- 视图切换'));
function harness() {
  const nodes = new Map();
  const timers = new Map();
  const data = { platform: 'windows', consolePid: 42,
    capabilities: { manage_elevation_broker: true },
    apps: [{ elevated: true }],
    elevationBroker: { installed: true, verified: true, sessionAuthorized: false } };
  let layer = false, opened = 0, timerId = 0;
  const context = vm.createContext({
    state: { data }, document: { hidden: false },
    $: id => {
      if (!nodes.has(id)) nodes.set(id, { classList: { toggle() {} },
        appendChild() {}, addEventListener(type, fn) { this[type] = fn; } });
      return nodes.get(id);
    },
    icon() {}, setText(node, text) { node.textContent = text; }, toast() {},
    currentPlatform: () => data.platform,
    hasCapability: key => data.capabilities[key] === true,
    activeLayer: () => layer,
    openBrokerPassword() { opened++; layer = true; },
    setTimeout(fn) { const id = ++timerId; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(section, context);
  return { data, nodes, timers, context,
    prompt: () => vm.runInContext('promptForElevationSession(state.data)', context),
    render: () => vm.runInContext('renderBrokerSession()', context),
    setLayer(value) { layer = value; },
    get opened() { return opened; },
    tick() { const pending = [...timers.values()]; timers.clear(); pending.forEach(fn => fn()); },
  };
}

test('another dialog defers authorization without losing the one-time prompt', () => {
  const h = harness();
  h.setLayer(true);
  h.prompt(); h.prompt();
  assert.equal(h.opened, 0);
  assert.equal(h.timers.size, 1);
  h.setLayer(false); h.tick();
  assert.equal(h.opened, 1);
  h.setLayer(false); h.prompt();
  assert.equal(h.opened, 1);
  h.nodes.get('#brokerSessionBtn').click();
  assert.equal(h.opened, 2);
});

test('canceling a manually opened password dialog does not trigger an automatic repeat', () => {
  const h = harness();
  h.setLayer(true); h.prompt();
  h.nodes.get('#brokerSessionBtn').click();
  h.setLayer(false); h.tick();
  assert.equal(h.opened, 1);
});

test('a pending prompt rechecks current authorization and controller identity', () => {
  const h = harness();
  h.setLayer(true); h.prompt();
  h.data.elevationBroker.sessionAuthorized = true;
  h.setLayer(false); h.tick();
  assert.equal(h.opened, 0);
  h.data.elevationBroker.sessionAuthorized = false;
  h.prompt();
  assert.equal(h.opened, 1);
  h.setLayer(false); h.data.consolePid++; h.prompt();
  assert.equal(h.opened, 2);
});

test('background pages defer the prompt until visible', () => {
  const h = harness();
  h.context.document.hidden = true; h.prompt();
  assert.equal(h.opened, 0);
  h.context.document.hidden = false; h.tick();
  assert.equal(h.opened, 1);
});

test('header exposes installation, unlock and browser authorization states', () => {
  const h = harness();
  const button = h.nodes.get('#brokerSessionBtn');
  const label = h.nodes.get('#brokerSessionLabel');
  h.render();
  assert.equal(button.hidden, false);
  assert.equal(button.disabled, false);
  assert.equal(label.textContent, '解锁管理员');
  h.data.elevationBroker.unlocked = true; h.render();
  assert.equal(button.disabled, false);
  h.data.elevationBroker.sessionAuthorized = true; h.render();
  assert.equal(label.textContent, '管理员已授权');
  assert.equal(button.disabled, true);
  h.data.elevationBroker = {}; h.render();
  assert.equal(label.textContent, '安装管理员代理');
  h.data.platform = 'macos'; h.render();
  assert.equal(button.hidden, true);
  h.data.platform = 'windows'; h.data.capabilities = {}; h.render();
  assert.equal(button.hidden, true);
});
