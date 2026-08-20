'use strict';
/* ============================================================
   widgets.js — 右侧信息栏与导航轨
   实时动态/实时告警（会话内状态差异事件流，首帧静默建立基线）、
   端口/资源 TOP 5、小贴士、快捷操作、导航轨连接状态与版本。
   全部数据来自 /api/state 轮询快照，不新增后端接口。
   ============================================================ */
import { $, el, setText, setChildren, icon, state, fmtClock, taskExitStatus,
  openLayer, closeLayer, act, post, toast, escapeHtml, applyTheme,
  taskNotificationsEnabled, toggleTaskNotifications, currentPlatform,
  platformPresentation, shortcutLabel, hasCapability } from './core.js';
import { openAppModal, openLogs, openConsoleLog, openConfirm,
  offerForceStopAfterTimeout, refreshLifecycleState } from './overlays.js';
import { configuredPort } from './ports.js';
import { lifecyclePayload, lifecycleSnapshot, isGenerationMismatch,
  isStopTimeout, runLifecycleMutation } from './lifecycle.js';

const FEED_CAP = 50;
let feedSeq = 0;
let feedEvents = [];
let prevSnap = null;              // 上一份用于差异对比的快照

/* 断线、页面转入后台或总控台重启后由 app.js 调用：
   丢弃旧基线，下一份快照只重建基线，避免把断档期积压的变化
   一次性当作“刚刚发生”的事件灌进实时动态/告警。 */
export function resetFeedBaseline() {
  prevSnap = null;
}

const feedListL = $('#feedListL'), feedListS = $('#feedListS');
const topPortsL = $('#topPortsL'), topPortsS = $('#topPortsS');
const topResS = $('#topResS'), resTabs = $('#resTabs');
const tipsText = $('#tipsText'), tipsAction = $('#tipsAction');
const railConnDot = $('#railConnDot'), railConnText = $('#railConnText');
const railVer = $('#railVer');
let resMetric = 'cpu';

/* ---------------- 静态装饰图标与快捷操作 ---------------- */
export function initWidgets() {
  document.querySelectorAll('[data-ov-icon]').forEach(node => {
    setChildren(node, icon(node.dataset.ovIcon, 17));
  });
  document.querySelectorAll('[data-qa-icon]').forEach(node => {
    setChildren(node, icon(node.dataset.qaIcon, 13));
  });
  setChildren($('#tipsIcon'), icon('brain', 14));

  /* 顶栏与侧栏的快捷操作统一走 data-qa 代理 */
  document.addEventListener('click', e => {
    const btn = e.target.closest('[data-qa]');
    if (!btn) return;
    const action = btn.dataset.qa;
    if (action === 'add-svc') openAppModal(null, 'service');
    else if (action === 'add-task') openAppModal(null, 'task');
    else if (action === 'refresh' && window.__poll) window.__poll();
    else if (action === 'logs') openLogsCenter();
    else if (action === 'settings') openSettingsCenter();
    else if (action === 'batch-stop') {
      if (!hasCapability('stop_managed')) return;
      batchStopApps();
    }
  });
  /* 导航轨动作按钮（非视图切换） */
  document.querySelectorAll('.rail-btn[data-action]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.action === 'logs') openLogsCenter();
      else if (btn.dataset.action === 'settings') openSettingsCenter();
    });
  });
  setChildren($('#railIconLogs'), icon('file-text', 19));
  setChildren($('#railIconSettings'), icon('settings', 19));
  $('#logsMaskClose').addEventListener('click', closeLogsCenter);
  $('#logsMask').addEventListener('mousedown', e => {
    if (e.target === $('#logsMask')) closeLogsCenter();
  });
  $('#settingsMaskClose').addEventListener('click', closeSettingsCenter);
  $('#settingsMask').addEventListener('mousedown', e => {
    if (e.target === $('#settingsMask')) closeSettingsCenter();
  });
  for (const id of ['setCwd', 'setDataDir', 'setLogsDir']) {
    $("#" + id).addEventListener('click', () => copySettingsPath(id));
  }
  $('#setNotify').addEventListener('click', () => {
    toggleTaskNotifications();
    syncSettings();
  });
  $('#setAppearance').addEventListener('click', e => {
    const tab = e.target.closest('.mini-tab');
    if (!tab) return;
    const mode = tab.dataset.appearance;
    if (mode === 'auto') localStorage.removeItem('console-theme');
    else localStorage.setItem('console-theme', mode);
    applyTheme();
    syncSettings();
  });

  $('#feedClearL').addEventListener('click', clearFeed);
  $('#feedClearS').addEventListener('click', clearFeed);
  resTabs.addEventListener('click', e => {
    const tab = e.target.closest('.mini-tab');
    if (!tab) return;
    resMetric = tab.dataset.metric === 'mem' ? 'mem' : 'cpu';
    for (const t of resTabs.querySelectorAll('.mini-tab')) {
      t.classList.toggle('active', t === tab);
    }
    if (state.data) renderTopRes(state.data);
  });

  /* 导航轨连接状态只跟随连接语义；降级/配置提示也会复用横幅。 */
  const banner = $('#banner');
  const syncConn = () => {
    const down = banner.dataset.connection === 'down';
    railConnDot.classList.toggle('running', !down);
    railConnDot.classList.toggle('danger', down);
    setText(railConnText, down ? '连接中断' : '已连接');
  };
  new MutationObserver(syncConn)
    .observe(banner, { attributes: true, attributeFilter: ['data-connection'] });
  syncConn();

  tipsAction.addEventListener('click', () => {
    const tab = $('#tab-services');
    if (tab) tab.click();
  });
  initImportWizard();
}

/* ---------------- 实时动态 / 实时告警 ----------------
   对比相邻两份轮询快照产生事件；首份快照只建立基线，
   断线/后台恢复后同样静默重建，避免把存量当新闻。 */
function snapshotMaps(data) {
  const apps = new Map();
  for (const a of data.apps || []) {
    apps.set(a.id, {
      name: a.name || '未命名',
      kind: a.kind || 'service',
      running: !!a.running,
      port: configuredPort(a),
      occupied: !!a.portOccupied,
      exitAt: a.lastExit && a.lastExit.at ? a.lastExit.at : 0,
      exit: a.lastExit || null,
    });
  }
  const services = new Map();
  for (const s of data.services || []) {
    const key = s.instanceKey || s.key;
    if (!key) continue;
    services.set(key, {
      name: s.appName || s.project || s.name || '本地服务',
      port: s.port,
      mine: s.group === 'mine' && !s.hidden,
      linked: !!s.appId,   // 已关联启动台卡片的服务由应用事件覆盖，不重复上报
    });
  }
  return { apps, services, degraded: !!data.degraded };
}

function pushEvent(level, title, sub) {
  feedEvents.unshift({ seq: ++feedSeq, at: new Date(), level, title, sub });
  if (feedEvents.length > FEED_CAP) feedEvents.length = FEED_CAP;
}

function diffSnapshot(prev, next) {
  for (const [id, app] of next.apps) {
    const before = prev.apps.get(id);
    if (!before) continue;    // 新建卡片不算动态
    if (!before.running && app.running) {
      pushEvent('info', app.name + (app.kind === 'task' ? ' 开始运行' : ' 服务已启动'),
        app.port ? ':' + app.port : '');
    } else if (before.running && !app.running) {
      pushEvent('info', app.name + (app.kind === 'task' ? ' 运行结束' : ' 已停止'),
        app.port ? ':' + app.port : '');
    }
    if (!before.occupied && app.occupied) {
      pushEvent('warn', '端口冲突', app.name + (app.port ? ' :' + app.port + ' 被占用' : ''));
    }
    if (app.exitAt && app.exitAt !== before.exitAt && app.exit) {
      const status = taskExitStatus(app.exit);
      if (app.kind === 'task') {
        if (status === 'succeeded') pushEvent('ok', app.name + ' 任务执行成功', '');
        else if (status === 'failed') {
          pushEvent('error', app.name + ' 任务执行失败',
            app.exit.code != null ? '退出码 ' + app.exit.code : '');
        } else if (status === 'canceled') pushEvent('warn', app.name + ' 任务已取消', '');
        else pushEvent('warn', app.name + ' 任务已中止', '');
      } else if (app.exit.code) {
        pushEvent('error', app.name + ' 异常退出', '退出码 ' + app.exit.code);
      }
    }
  }
  for (const [key, svc] of next.services) {
    if (!prev.services.has(key) && svc.mine && !svc.linked) {
      pushEvent('info', svc.name + ' 服务已启动', svc.port ? ':' + svc.port : '');
    }
  }
  for (const [key, svc] of prev.services) {
    if (!next.services.has(key) && svc.mine && !svc.linked) {
      pushEvent('info', svc.name + ' 服务已停止', svc.port ? ':' + svc.port : '');
    }
  }
  if (!prev.degraded && next.degraded) {
    pushEvent('error', '总控台进入降级模式', '部分数据可能不完整');
  }
}

function feedItem(ev) {
  const item = el('div', 'feed-item');
  const dot = el('span', 'feed-dot lvl-' + ev.level);
  dot.setAttribute('aria-hidden', 'true');
  const main = el('div', 'feed-main');
  const title = el('div', 'feed-title');
  title.textContent = ev.title;
  main.appendChild(title);
  if (ev.sub) {
    const sub = el('div', 'feed-sub');
    sub.textContent = ev.sub;
    main.appendChild(sub);
  }
  const time = el('span', 'feed-time mono');
  time.textContent = fmtClock(ev.at).slice(0, 5);
  item.append(dot, main, time);
  return item;
}

function renderFeedInto(list, events, emptyText) {
  list.replaceChildren();
  if (!events.length) {
    const empty = el('div', 'feed-empty');
    empty.textContent = emptyText;
    list.appendChild(empty);
    return;
  }
  for (const ev of events.slice(0, 12)) list.appendChild(feedItem(ev));
}

function renderFeeds() {
  renderFeedInto(feedListL, feedEvents, '暂无动态；启动、停止与端口事件会显示在这里');
  renderFeedInto(feedListS,
    feedEvents.filter(ev => ev.level === 'warn' || ev.level === 'error'),
    '运行良好，暂无告警');
}

function clearFeed() {
  feedEvents = [];
  renderFeeds();
}

/* ---------------- TOP 5 ---------------- */
function mineServices(data) {
  return (data.services || []).filter(s => s.group === 'mine' && !s.hidden);
}

function renderTopPortsInto(container, data) {
  const apps = data.apps || [];
  const rows = mineServices(data)
    .filter(s => Number.isInteger(s.port))
    .sort((a, b) => a.port - b.port)
    .slice(0, 5);
  container.replaceChildren();
  if (!rows.length) {
    const empty = el('div', 't5-empty');
    empty.textContent = '暂无监听端口';
    container.appendChild(empty);
    return;
  }
  rows.forEach((svc, i) => {
    const row = el('div', 't5-row');
    const rank = el('span', 't5-rank');
    rank.textContent = String(i + 1);
    const port = el('span', 't5-port');
    port.textContent = ':' + svc.port;
    const name = el('span', 't5-name');
    name.textContent = svc.appName || svc.project || svc.name || '本地服务';
    name.title = name.textContent;
    row.append(rank, port, name);
    const conflict = apps.some(a => a.portOccupied && configuredPort(a) === svc.port);
    if (conflict) {
      const tag = el('span', 't5-tag');
      tag.textContent = '冲突';
      row.appendChild(tag);
    }
    container.appendChild(row);
  });
}

function renderTopRes(data) {
  const rows = mineServices(data)
    .slice()
    .sort((a, b) => (b[resMetric] || 0) - (a[resMetric] || 0))
    .slice(0, 5);
  topResS.replaceChildren();
  if (!rows.length) {
    const empty = el('div', 't5-empty');
    empty.textContent = '暂无服务进程';
    topResS.appendChild(empty);
    return;
  }
  rows.forEach((svc, i) => {
    const row = el('div', 't5-row');
    const rank = el('span', 't5-rank');
    rank.textContent = String(i + 1);
    const name = el('span', 't5-name');
    name.textContent = svc.appName || svc.project || svc.name || '本地服务';
    name.title = name.textContent;
    const val = el('span', 't5-val');
    const pct = typeof svc[resMetric] === 'number' ? svc[resMetric] : 0;
    val.textContent = pct.toFixed(1) + '%';
    const bar = el('span', 't5-bar');
    const fill = el('i');
    fill.style.width = Math.max(2, Math.min(100, pct)) + '%';
    bar.appendChild(fill);
    row.append(rank, name, bar, val);
    topResS.appendChild(row);
  });
}

/* ---------------- 小贴士 ---------------- */
function renderTips(data) {
  const conflicts = (data.apps || []).filter(a => a.portOccupied).length;
  let text;
  let actionable = false;
  if (conflicts > 0) {
    text = '检测到 ' + conflicts + ' 个端口冲突，建议尽快处理以避免服务异常。';
    actionable = true;
  } else if (data.degraded) {
    text = '当前处于降级模式，部分组件数据可能不完整；可尝试重启总控台恢复。';
  } else if (!hasCapability('launch_managed', data) || !hasCapability('stop_managed', data)) {
    text = platformPresentation(data).lifecycleNotice;
  } else {
    text = '所有服务运行正常。小技巧：按 ' + shortcutLabel('K', data) +
      ' 打开命令面板，可以快速启动、停止任意应用。';
  }
  setText(tipsText, text);
  tipsAction.hidden = !actionable;
}

/* ---------------- 主入口（每轮轮询调用） ---------------- */
export function renderWidgets(data) {
  if (!data) return;
  const next = snapshotMaps(data);
  if (prevSnap) diffSnapshot(prevSnap, next);
  prevSnap = next;
  renderFeeds();
  renderTopPortsInto(topPortsL, data);
  renderTopPortsInto(topPortsS, data);
  renderTopRes(data);
  renderTips(data);
  setText($('#cmdkShortcut'), shortcutLabel('K', data));
  setText($('#logsShortcut'), shortcutLabel('J', data));
  setText($('#pasteShortcut'), shortcutLabel('V', data));
  const batchStop = $('#batchStopAction');
  const canStop = hasCapability('stop_managed', data);
  batchStop.hidden = !canStop;
  batchStop.disabled = !canStop;
  setText(railVer, data.version ? 'v' + data.version : 'v—');
}

/* ============================================================
   日志中心（聚合弹层）：所有应用与总控台日志的目录页
   ============================================================ */
const logsMask = $('#logsMask'), logsList = $('#logsList');

function logsRow(app) {
  const row = el('button', 'logs-item');
  row.type = 'button';
  const box = el('span', 'logs-ic');
  if (app.icon) {
    const img = new Image();
    img.src = app.icon;
    img.alt = '';
    box.appendChild(img);
  } else if (app.glyph && window.LUCIDE && window.LUCIDE[app.glyph]) {
    box.appendChild(icon(app.glyph, 14));
  } else {
    box.textContent = app.name ? [...app.name][0].toUpperCase() : '?';
  }
  const main = el('span', 'logs-main');
  const name = el('span', 'logs-name');
  name.textContent = app.name || '未命名';
  const sub = el('span', 'logs-sub');
  const isTask = (app.kind || 'service') === 'task';
  const port = configuredPort(app);
  sub.textContent = (app.running ? '运行中' : '已停止') +
    (isTask ? ' · 任务' : port ? ' · :' + port : '');
  main.append(name, sub);
  row.append(box, main, icon('chevron-right', 14));
  row.addEventListener('click', () => {
    closeLogsCenter();
    openLogs(app);
  });
  return row;
}

function renderLogsList() {
  logsList.replaceChildren();
  const apps = (state.data && state.data.apps) || [];
  const sorted = apps.slice().sort((a, b) => (!!b.running) - (!!a.running));
  for (const app of sorted) logsList.appendChild(logsRow(app));
  /* 总控台自身日志固定在最后 */
  const row = el('button', 'logs-item');
  row.type = 'button';
  const box = el('span', 'logs-ic');
  box.appendChild(icon('terminal', 14));
  const main = el('span', 'logs-main');
  const name = el('span', 'logs-name');
  name.textContent = '总控台日志';
  const sub = el('span', 'logs-sub');
  sub.textContent = '系统 · ' + (platformPresentation().consoleLogPath || 'console.log');
  main.append(name, sub);
  row.append(box, main, icon('chevron-right', 14));
  row.addEventListener('click', () => {
    closeLogsCenter();
    openConsoleLog();
  });
  logsList.appendChild(row);
  if (!apps.length) {
    const empty = el('div', 'logs-empty');
    empty.textContent = '启动台还没有应用；上方是总控台自身日志';
    logsList.prepend(empty);
  }
}

export function openLogsCenter() {
  renderLogsList();
  openLayer(logsMask, $('#logsMaskClose'));
}
export function closeLogsCenter() { closeLayer(logsMask); }

/* ============================================================
   设置中心（聚合弹层）：通知开关 / 外观 / 版本与目录信息
   ============================================================ */
const settingsMask = $('#settingsMask');

function syncSettings() {
  const on = taskNotificationsEnabled();
  const sw = $('#setNotify');
  sw.classList.toggle('on', on);
  sw.setAttribute('aria-checked', String(on));
  const stored = localStorage.getItem('console-theme');
  const mode = stored === 'dark' ? 'dark' : stored === 'light' ? 'light' : 'auto';
  for (const tab of $('#setAppearance').querySelectorAll('.mini-tab')) {
    tab.classList.toggle('active', tab.dataset.appearance === mode);
  }
  const d = state.data || {};
  const presentation = platformPresentation(d);
  const platform = currentPlatform(d);
  setText($('#setPlatform'), platform === 'windows' ? 'Windows'
    : platform === 'macos' || platform === 'darwin' ? 'macOS' : '—');
  setText($('#setVersion'), d.version ? 'v' + d.version : '—');
  setText($('#setPort'), d.consolePort ? ':' + d.consolePort : '—');
  setText($('#setCwd'), d.consoleCwd || '—');
  setText($('#setDataDir'), presentation.dataDir || '—');
  setText($('#setLogsDir'), presentation.logsDir || '—');
  setText($('#setLaunchInstruction'), presentation.launchInstruction);
  setText($('#setLifecycleNotice'), presentation.lifecycleNotice);
  $('#setImportRow').hidden = platform !== 'windows';
  const pathLabels = { setCwd: '工作目录', setDataDir: '数据目录', setLogsDir: '日志目录' };
  for (const id of ['setCwd', 'setDataDir', 'setLogsDir']) {
    const button = $("#" + id);
    button.disabled = button.textContent === '—';
    button.title = button.disabled ? '' : '复制路径';
    button.setAttribute('aria-label', button.disabled ? pathLabels[id] + '不可用'
      : '复制' + pathLabels[id] + '：' + button.textContent);
  }
}

async function copySettingsPath(id) {
  const value = $("#" + id).textContent.trim();
  if (!value || value === '—') return;
  try {
    await navigator.clipboard.writeText(value);
    toast('路径已复制');
  } catch (_) {
    toast('无法复制路径，请手动选择文本');
  }
}

export function openSettingsCenter() {
  syncSettings();
  openLayer(settingsMask, $('#settingsMaskClose'));
}
export function closeSettingsCenter(restoreFocus = true) {
  closeLayer(settingsMask, restoreFocus !== false);
}

/* ============================================================
   Windows 配置导入：显式源文件 -> 预览 -> 选择 -> 提交/回滚
   ============================================================ */
const importMask = $('#importMask');
const importSourcePath = $('#importSourcePath');
const importMappingList = $('#importMappingList');
const importResult = $('#importResult');
const importSummary = $('#importSummary');
const importAppList = $('#importAppList');
const importStatus = $('#importStatus');
const importPreviewButton = $('#importPreview');
const importCommitButton = $('#importCommit');
const importRollbackButton = $('#importRollback');
const IMPORT_SELECTABLE_STATUSES = new Set(['ready', 'needs_review']);
let importPreviewState = null;
let importReceiptId = null;
let importBusy = false;

function setImportStatus(message) {
  setText(importStatus, message || '');
}

function invalidateImportPreview() {
  importPreviewState = null;
  importResult.hidden = true;
  importCommitButton.hidden = true;
  importSourcePath.removeAttribute('aria-invalid');
  for (const input of importMappingList.querySelectorAll('input')) {
    input.removeAttribute('aria-invalid');
  }
  setImportStatus('');
}

function createImportMappingRow(values = {}) {
  const row = el('div', 'import-mapping-row');
  const source = el('input', 'mono import-source-root');
  source.type = 'text';
  source.placeholder = 'macOS source root';
  source.setAttribute('aria-label', 'macOS 源目录');
  source.setAttribute('aria-describedby', 'importMappingHint importStatus');
  source.value = typeof values.sourceRoot === 'string' ? values.sourceRoot : '';
  const target = el('input', 'mono import-target-root');
  target.type = 'text';
  target.placeholder = 'Windows target root';
  target.setAttribute('aria-label', 'Windows 目标目录');
  target.setAttribute('aria-describedby', 'importMappingHint importStatus');
  target.value = typeof values.targetRoot === 'string' ? values.targetRoot : '';
  const remove = el('button', 'btn import-mapping-remove');
  remove.type = 'button';
  remove.textContent = '移除';
  remove.setAttribute('aria-label', '移除这条路径映射');
  const changed = () => invalidateImportPreview();
  source.addEventListener('input', changed);
  target.addEventListener('input', changed);
  remove.addEventListener('click', () => {
    if (importMappingList.children.length === 1) {
      source.value = '';
      target.value = '';
    } else {
      row.remove();
    }
    invalidateImportPreview();
  });
  row.append(source, target, remove);
  return row;
}

function readImportRequest() {
  const sourcePath = importSourcePath.value.trim();
  if (!sourcePath) {
    setImportStatus('请先填写源配置文件路径。');
    importSourcePath.setAttribute('aria-invalid', 'true');
    importSourcePath.focus();
    return null;
  }
  const pathMappings = [];
  for (const row of importMappingList.querySelectorAll('.import-mapping-row')) {
    const sourceRoot = row.querySelector('.import-source-root').value.trim();
    const targetRoot = row.querySelector('.import-target-root').value.trim();
    if (!sourceRoot && !targetRoot) continue;
    if (!sourceRoot || !targetRoot) {
      row.querySelector('.import-source-root').setAttribute(
        'aria-invalid', String(!sourceRoot));
      row.querySelector('.import-target-root').setAttribute(
        'aria-invalid', String(!targetRoot));
      setImportStatus('每条路径映射都必须同时填写源目录和目标目录。');
      return null;
    }
    pathMappings.push({ sourceRoot, targetRoot });
  }
  return { sourcePath, pathMappings };
}

function importAppStatus(app) {
  if (app && typeof app.status === 'string') return app.status;
  if (app && typeof app.importStatus === 'string') return app.importStatus;
  const compatibility = app && app.platformCompatibility;
  return compatibility && typeof compatibility.status === 'string'
    ? compatibility.status : 'blocked';
}

function importStatusLabel(status) {
  return ({
    ready: '可导入',
    needs_review: '需要复核',
    blocked: '已阻止',
    conflict: '与现有应用冲突',
  })[status] || '不可导入';
}

function importAppReasons(app) {
  const reasons = Array.isArray(app && app.reasons) ? app.reasons
    : Array.isArray(app && app.platformCompatibility && app.platformCompatibility.reasons)
      ? app.platformCompatibility.reasons : [];
  return reasons.map(reason => typeof reason === 'string' ? reason
    : reason && typeof reason.message === 'string' ? reason.message : '')
    .filter(Boolean).join('；');
}

function syncImportCommitState() {
  const checked = importAppList.querySelectorAll(
    'input[type="checkbox"][data-import-selectable="true"]:checked').length;
  importCommitButton.disabled = importBusy || checked === 0;
}

function renderImportPreview(result) {
  const summary = result && result.summary && typeof result.summary === 'object'
    ? result.summary : {};
  setText(importSummary,
    '可导入 ' + (Number(summary.ready) || 0) +
    ' · 需要复核 ' + (Number(summary.needs_review) || 0) +
    ' · 已阻止 ' + (Number(summary.blocked) || 0) +
    ' · 冲突 ' + (Number(summary.conflict) || 0));
  importAppList.replaceChildren();
  const apps = Array.isArray(result && result.apps) ? result.apps : [];
  for (const app of apps) {
    const status = importAppStatus(app);
    const selectable = IMPORT_SELECTABLE_STATUSES.has(status);
    const row = el('label', 'import-app-item' + (selectable ? '' : ' is-disabled'));
    const checkbox = el('input');
    checkbox.type = 'checkbox';
    checkbox.value = app && app.id != null ? String(app.id) : '';
    checkbox.dataset.importSelectable = String(selectable);
    checkbox.disabled = !selectable || !checkbox.value;
    checkbox.checked = selectable && !!checkbox.value;
    checkbox.addEventListener('change', syncImportCommitState);
    const copy = el('span', 'import-app-main');
    const title = el('strong', 'import-app-name');
    title.textContent = app && app.name ? app.name : '未命名应用';
    const meta = el('span', 'import-app-detail');
    meta.textContent = (app && (app.cwd || app.command)) || '没有可显示的路径或命令';
    const reason = importAppReasons(app);
    const detail = el('span', 'import-app-detail');
    detail.textContent = reason || importStatusLabel(status);
    copy.append(title, meta, detail);
    const badge = el('span', 'import-app-status');
    badge.dataset.status = status;
    badge.classList.add(status.replace('_', '-'));
    badge.textContent = importStatusLabel(status);
    row.append(checkbox, copy, badge);
    importAppList.appendChild(row);
  }
  if (!apps.length) {
    const empty = el('p', 'import-empty');
    empty.textContent = '源配置中没有可预览的应用。';
    importAppList.appendChild(empty);
  }
  importResult.hidden = false;
  importCommitButton.hidden = false;
  syncImportCommitState();
}

function setImportBusy(value) {
  importBusy = value;
  importMask.setAttribute('aria-busy', String(value));
  importPreviewButton.disabled = value;
  importRollbackButton.disabled = value;
  syncImportCommitState();
}

async function previewImport() {
  if (importBusy || currentPlatform() !== 'windows') return;
  const request = readImportRequest();
  if (!request) return;
  invalidateImportPreview();
  setImportBusy(true);
  setImportStatus('正在生成预览…');
  const result = await act(post('/api/config/import/preview', request));
  setImportBusy(false);
  if (!result || result.ok === false) {
    setImportStatus(result && result.error ? result.error : '无法生成导入预览。');
    return;
  }
  if (!result.previewId) {
    setImportStatus('预览响应缺少 previewId，未允许提交。');
    return;
  }
  importPreviewState = { ...request, previewId: result.previewId };
  renderImportPreview(result);
  setImportStatus('预览已生成。请核对应用状态和路径后再提交。');
}

async function commitImport() {
  if (importBusy || currentPlatform() !== 'windows' || !importPreviewState) return;
  const selectedAppIds = [...importAppList.querySelectorAll(
    'input[type="checkbox"][data-import-selectable="true"]:checked')]
    .map(input => input.value).filter(Boolean);
  if (!selectedAppIds.length) {
    setImportStatus('请选择至少一个可导入的应用。');
    return;
  }
  const request = {
    sourcePath: importPreviewState.sourcePath,
    pathMappings: importPreviewState.pathMappings,
    previewId: importPreviewState.previewId,
    selectedAppIds,
  };
  setImportBusy(true);
  setImportStatus('正在提交所选应用…');
  const result = await act(post('/api/config/import/commit', request));
  setImportBusy(false);
  if (!result || result.ok === false) {
    setImportStatus(result && result.error ? result.error : '导入提交失败。');
    return;
  }
  importReceiptId = typeof result.importId === 'string' ? result.importId : null;
  importCommitButton.hidden = true;
  importRollbackButton.hidden = !importReceiptId;
  setImportStatus('导入已提交' + (importReceiptId ? '，可在此回滚本次导入。' : '。'));
  if (window.__poll) window.__poll();
}

async function rollbackImport() {
  if (importBusy || currentPlatform() !== 'windows' || !importReceiptId) return;
  setImportBusy(true);
  setImportStatus('正在回滚本次导入…');
  const result = await act(post('/api/config/import/rollback', { importId: importReceiptId }));
  setImportBusy(false);
  if (!result || result.ok === false) {
    setImportStatus(result && result.error ? result.error : '回滚失败。');
    return;
  }
  importReceiptId = null;
  importRollbackButton.hidden = true;
  invalidateImportPreview();
  setImportStatus('本次导入已回滚。');
  if (window.__poll) window.__poll();
}

function initImportWizard() {
  if (!importMappingList.children.length) {
    importMappingList.appendChild(createImportMappingRow());
  }
  $('#setImportOpen').addEventListener('click', openImportWizard);
  $('#importClose').addEventListener('click', closeImportWizard);
  importMask.addEventListener('mousedown', event => {
    if (event.target === importMask) closeImportWizard();
  });
  importSourcePath.addEventListener('input', invalidateImportPreview);
  $('#importAddMapping').addEventListener('click', () => {
    importMappingList.appendChild(createImportMappingRow());
    invalidateImportPreview();
  });
  importPreviewButton.addEventListener('click', previewImport);
  importCommitButton.addEventListener('click', commitImport);
  importRollbackButton.addEventListener('click', rollbackImport);
}

export function openImportWizard() {
  if (currentPlatform() !== 'windows') return;
  const returnFocus = $('#rail-settings');
  closeSettingsCenter(false);
  importRollbackButton.hidden = !importReceiptId;
  openLayer(importMask, importSourcePath, returnFocus);
}

export function closeImportWizard() { closeLayer(importMask); }

/* ============================================================
   批量停止服务：确认后逐个走安全停止，绝不按端口结束进程
   ============================================================ */
function batchStopApps() {
  if (!hasCapability('stop_managed')) {
    toast(platformPresentation().lifecycleNotice);
    return;
  }
  const running = ((state.data && state.data.apps) || [])
    .map(app => ({ app, intent: lifecycleSnapshot(app, currentPlatform()) }))
    .filter(item => item.app.runtimeSource !== 'windowsTaskScheduler'
      && item.intent.canManage);
  if (!running.length) {
    toast('当前没有运行中的应用');
    return;
  }
  const names = running.map(item => item.app.name || '未命名').join('、');
  openConfirm({
    title: '批量停止服务',
    bodyHtml: '确定要停止全部 <b>' + running.length + '</b> 个运行中的应用吗？' +
      '<div class="confirm-detail">' + escapeHtml(names) +
      '。将逐个安全停止，不会按端口结束其他进程。</div>',
    okText: '全部停止',
    tone: 'danger',
    onOk: async () => {
      if (!hasCapability('stop_managed')) {
        toast(platformPresentation().lifecycleNotice);
        return;
      }
      let stopped = 0;
      let changed = 0;
      const timedOut = [];
      const { stateIsFresh } = await runLifecycleMutation(async () => {
        for (const item of running) {
          const result = await act(post(
            '/api/apps/' + item.app.id + '/stop',
            lifecyclePayload(item.intent, { force: false }),
          ));
          if (result && result.ok !== false) stopped += 1;
          else if (isGenerationMismatch(result)) changed += 1;
          else if (isStopTimeout(result)) timedOut.push({ ...item, result });
        }
        return null;
      }, refreshLifecycleState);
      const details = [
        changed ? changed + ' 个状态已变化、未重试' : '',
        timedOut.length ? timedOut.length + ' 个停止超时' : '',
      ].filter(Boolean).join('；');
      toast('已停止 ' + stopped + ' 个应用' + (details ? '；' + details : ''));
      if (timedOut.length === 1) {
        const item = timedOut[0];
        offerForceStopAfterTimeout(
          item.result, item.intent, item.app.id, item.app.name,
          stateIsFresh,
        );
      } else if (timedOut.length > 1) {
        toast('多个应用停止超时；请在对应卡片逐一确认强制停止');
      }
    },
  });
}
