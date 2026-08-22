'use strict';
/* ============================================================
   overlays.js — 浮层：确认框 / 应用编辑模态 / 日志抽屉
   ============================================================ */
import { $, el, setText, setChildren, icon, escapeHtml,
  post, put, del, act, toast, state, openLayer, closeLayer,
  GLYPHS, findApp, bumpMutationEpoch, hasCapability,
  platformPresentation, currentPlatform } from './core.js';
import { lifecyclePayload, lifecycleSnapshot, sameLifecycleGeneration,
  isGenerationMismatch, isStopTimeout, runLifecycleMutation,
  runConfirmedForceStop } from './lifecycle.js';

/* ---------------- DOM 引用 ---------------- */
const appModalMask = $('#appModalMask'), appModal = $('#appModal'), appModalTitle = $('#appModalTitle');
const fName = $('#fName'), fCmd = $('#fCmd'), fCwd = $('#fCwd'), fPort = $('#fPort');
const kindRow = $('#kindRow'), portField = $('#portField'), fCmdLabel = $('#fCmdLabel');
const scheduledTaskField = $('#scheduledTaskField');
const fScheduledTaskPath = $('#fScheduledTaskPath');
const btnRefreshScheduledTasks = $('#btnRefreshScheduledTasks');
const dockerResourceField = $('#dockerResourceField');
const fDockerResource = $('#fDockerResource');
const btnRefreshDockerResources = $('#btnRefreshDockerResources');
const cwdField = $('#cwdField');
const programArgsField = $('#programArgsField'), fProgramArgs = $('#fProgramArgs');
const elevatedField = $('#elevatedField'), fElevated = $('#fElevated');
const btnPickScript = $('#btnPickScript'), btnPickCwd = $('#btnPickCwd');
const btnDetectProject = $('#btnDetectProject');
const detectPanel = $('#detectPanel'), detectSummary = $('#detectSummary');
const detectFiles = $('#detectFiles'), detectList = $('#detectList');
const iconFile = $('#iconFile'), btnPickIcon = $('#btnPickIcon'), btnRemoveIcon = $('#btnRemoveIcon');
const glyphGrid = $('#glyphGrid');
const iconPreview = $('#iconPreview');
const iconPreviewImg = $('#iconPreviewImg'), iconPreviewGlyph = $('#iconPreviewGlyph');
const iconPreviewTxt = $('#iconPreviewTxt');
const appearanceDetails = $('#appearanceDetails'), appearanceChevron = $('#appearanceChevron');
const appCancel = $('#appCancel'), appSave = $('#appSave');
const appStopEdit = $('#appStopEdit'), editRunningNotice = $('#editRunningNotice');
const commandCompatibility = $('#commandCompatibility');

const confirmMask = $('#confirmMask'), confirmTitle = $('#confirmTitle'), confirmBody = $('#confirmBody');
const forceRow = $('#forceRow'), forceCheck = $('#forceCheck');
const confirmCancel = $('#confirmCancel'), confirmOk = $('#confirmOk');

const drawerMask = $('#drawerMask'), logDrawer = $('#logDrawer');
const drawerTitle = $('#drawerTitle'), drawerClose = $('#drawerClose');
const logBody = $('#logBody'), logPre = $('#logPre');
const logSourceStatus = $('#logSourceStatus'), logSourceText = $('#logSourceText');
const logTaskHistoryEnable = $('#logTaskHistoryEnable');

const brokerPasswordMask = $('#brokerPasswordMask');
const brokerPasswordTitle = $('#brokerPasswordTitle');
const brokerPasswordNote = $('#brokerPasswordNote');
const brokerPassword = $('#brokerPassword');
const brokerPasswordConfirmField = $('#brokerPasswordConfirmField');
const brokerPasswordConfirm = $('#brokerPasswordConfirm');
const brokerPasswordCancel = $('#brokerPasswordCancel');
const brokerPasswordSubmit = $('#brokerPasswordSubmit');

const iconVer = new Map();   // appId → 图标版本号，上传/删除后刷新浏览器缓存
setChildren(appearanceChevron, icon('chevron-down', 16));
export function bumpIconVer(id) { iconVer.set(id, (iconVer.get(id) || 0) + 1); }
export function getIconVer(id) { return iconVer.get(id) || 0; }

/* ============================================================
   确认模态
   ============================================================ */
let confirmCb = null;
export function openConfirm({ title, bodyHtml, okText = '确认', showForce = false,
                       tone = 'danger', onOk }) {
  confirmTitle.textContent = title;
  confirmBody.innerHTML = bodyHtml;
  forceRow.hidden = !showForce;
  forceCheck.checked = false;
  confirmOk.textContent = okText;
  confirmOk.classList.toggle('btn-stop', tone === 'danger');
  confirmOk.classList.toggle('btn-accent', tone === 'primary');
  confirmCb = onOk;
  openLayer(confirmMask, confirmCancel);
}
export function closeConfirm() {
  closeLayer(confirmMask);
  confirmCb = null;
}
confirmOk.addEventListener('click', () => {
  const cb = confirmCb;
  const force = forceCheck.checked;
  closeConfirm();
  if (cb) cb(force);
});
confirmCancel.addEventListener('click', closeConfirm);
confirmMask.addEventListener('mousedown', e => { if (e.target === confirmMask) closeConfirm(); });

/* ============================================================
   管理员启动代理：首次安装或当前会话解锁
   ============================================================ */
let brokerPasswordMode = 'unlock';
const BROKER_INTERACTIVE_TIMEOUT_MS = 180000;

export function openBrokerPassword() {
  const broker = (state.data && state.data.elevationBroker) || {};
  brokerPasswordMode = !broker.installed || !broker.verified ? 'install' : 'unlock';
  const installing = brokerPasswordMode === 'install';
  setText(brokerPasswordTitle, installing ? '安装管理员启动代理' : '解锁管理员启动');
  setText(brokerPasswordNote, installing
    ? '首次安装会显示一次 Windows UAC；系统会自动使用已部署的 Windows 伴随包，未找到时才需手动选择。密码仅保存为不可逆 verifier。'
    : '密码只解锁当前 Local Ops 进程；退出后需要重新输入。');
  brokerPasswordConfirmField.hidden = !installing;
  brokerPassword.value = '';
  brokerPasswordConfirm.value = '';
  setText(brokerPasswordSubmit, installing ? '安装并解锁' : '解锁');
  openLayer(brokerPasswordMask, brokerPassword);
}

export function closeBrokerPassword() {
  brokerPassword.value = '';
  brokerPasswordConfirm.value = '';
  closeLayer(brokerPasswordMask);
}

async function submitBrokerPassword() {
  const password = brokerPassword.value;
  if (password.length < 8) return fieldError(brokerPassword, '密码至少需要 8 个字符');
  if (brokerPasswordMode === 'install' && password !== brokerPasswordConfirm.value) {
    return fieldError(brokerPasswordConfirm, '两次输入的密码不一致');
  }
  brokerPasswordSubmit.disabled = true;
  try {
    const endpoint = brokerPasswordMode === 'install'
      ? '/api/windows/elevation-broker/install'
      : '/api/windows/elevation-broker/unlock';
    let result;
    try {
      result = await post(
        endpoint, { password },
        brokerPasswordMode === 'install' ? BROKER_INTERACTIVE_TIMEOUT_MS : undefined,
      );
    } catch (error) {
      await act(Promise.reject(error));
      return;
    }
    if (brokerPasswordMode === 'install'
        && result && result.code === 'BROKER_PACKAGE_REQUIRED') {
      const selected = await act(post(
        '/api/pick', { what: 'exe' }, BROKER_INTERACTIVE_TIMEOUT_MS,
      ));
      if (!selected || selected.ok === false || selected.canceled) return;
      result = await act(post(
        endpoint,
        { password, packageExecutable: selected.path },
        BROKER_INTERACTIVE_TIMEOUT_MS,
      ));
    } else {
      result = await act(result);
    }
    if (!result || result.ok === false) return;
    if (brokerPasswordMode === 'install') {
      const unlocked = await act(post(
        '/api/windows/elevation-broker/unlock', { password },
      ));
      if (!unlocked || unlocked.ok === false) return;
    }
    closeBrokerPassword();
    await window.__poll();
    toast('当前 Local Ops 会话已解锁管理员启动');
  } finally {
    brokerPasswordSubmit.disabled = false;
  }
}

brokerPasswordCancel.addEventListener('click', closeBrokerPassword);
brokerPasswordSubmit.addEventListener('click', submitBrokerPassword);
brokerPasswordMask.addEventListener('mousedown', e => {
  if (e.target === brokerPasswordMask) closeBrokerPassword();
});

/* ---------------- 结束进程确认 ---------------- */
export function confirmKill(svc) {
  if (!hasCapability('kill_external')) {
    toast(platformPresentation().lifecycleNotice);
    return;
  }
  openConfirm({
    title: '结束进程',
    bodyHtml: '确定要结束进程 <b>' + escapeHtml(svc.name || '') + '</b> 吗？' +
      '<div class="confirm-detail mono">PID ' + escapeHtml(String(svc.pid)) +
      (svc.port ? ' · 端口 :' + escapeHtml(String(svc.port)) : '') + '</div>',
    okText: '结束',
    showForce: true,
    onOk: async force => {
      if (!hasCapability('kill_external')) {
        toast(platformPresentation().lifecycleNotice);
        return;
      }
      await act(post('/api/kill', { pid: svc.pid, force }));
    },
  });
}

export async function refreshLifecycleState(result) {
  const stateIsFresh = window.__poll ? await window.__poll() === true : false;
  if (isGenerationMismatch(result)) {
    toast('应用状态已变化，本次操作未执行；已刷新最新状态');
  }
  return stateIsFresh;
}

/* Graceful timeout never escalates on its own. A fresh same-generation state
   is required before presenting a separate force confirmation. */
export function offerForceStopAfterTimeout(
  result, intent, appId, appName, stateIsFresh, onStopped,
) {
  if (!isStopTimeout(result)) return false;
  const latest = findApp(appId);
  if (!stateIsFresh || !hasCapability('force_stop_managed')
      || !sameLifecycleGeneration(intent, latest, currentPlatform())) {
    toast('停止超时；当前状态已变化或无法安全强制停止，请查看诊断');
    return true;
  }
  const forceIntent = lifecycleSnapshot(latest, currentPlatform());
  openConfirm({
    title: '强制停止应用',
    bodyHtml: '<b>' + escapeHtml(appName || '应用') + '</b> 未能在限定时间内停止。' +
      '<div class="confirm-detail">强制停止只会终止已重新验证、仍属于同一代的受管 Job。</div>',
    okText: '强制停止',
    onOk: async () => {
      const current = findApp(appId);
      const forceOutcome = await runConfirmedForceStop({
        confirmed: true,
        timeoutResult: result,
        intent: forceIntent,
        currentApp: current,
        platform: currentPlatform(),
        stateIsFresh,
        forceCapable: hasCapability('force_stop_managed'),
        mutate: payload => act(post('/api/apps/' + appId + '/stop', payload)),
        refresh: refreshLifecycleState,
      });
      if (!forceOutcome.forced) {
        toast('应用状态已变化，未执行强制停止');
        await refreshLifecycleState(null);
        return;
      }
      /* runConfirmedForceStop creates lifecyclePayload(forceIntent, { force: true })
         only after the confirmation-time generation check succeeds. */
      const forceResult = forceOutcome.result;
      if (forceResult && forceResult.ok !== false) {
        toast('已强制停止 ' + (appName || '应用'));
        if (onStopped) onStopped(findApp(appId));
      }
    },
  });
  return true;
}

/* ============================================================
   添加 / 编辑应用模态（图标库 + 上传）
   ============================================================ */
let editingAppId = null;
let editingAppOriginal = null;
let appSaving = false;
let pendingIcon = null;      // { blob, type, url }
let selectedGlyph = null;    // 选中的 Lucide 图标名
let removeStoredIcon = false; // 仅在保存成功后删除，取消编辑不触碰后端
let pendingAttach = null;     // 从服务监控添加时待认领的来源进程信息
let detectingProject = false; // 认领流程必须等项目命令识别完成后再允许保存
let selectedCommandSpec = null;
let selectedCompatibility = null;
let scheduledTaskRows = [];
let dockerResourceRows = [];

function selectedScheduledTaskPath() {
  const value = fScheduledTaskPath.value.trim();
  return value || null;
}

function scheduledTaskMode() {
  return currentPlatform() === 'windows' && !!selectedScheduledTaskPath();
}

function dockerResourceKey(resource) {
  if (!resource || typeof resource !== 'object') return '';
  return resource.kind === 'container'
    ? 'container:' + (resource.containerId || '')
    : resource.kind === 'compose' ? 'compose:' + (resource.projectName || '') : '';
}

function selectedDockerResource() {
  const key = fDockerResource.value;
  const row = dockerResourceRows.find(item => item.key === key);
  return row ? row.resource : null;
}

function dockerResourceMode() {
  return !!selectedDockerResource();
}

function externalResourceMode() {
  return scheduledTaskMode() || dockerResourceMode();
}

function scheduledTaskCommand(path) {
  return 'schtasks.exe /Run /TN "' + path + '"';
}

function renderScheduledTaskOptions(selectedPath) {
  const selected = selectedPath || '';
  fScheduledTaskPath.replaceChildren();
  const local = document.createElement('option');
  local.value = '';
  local.textContent = '不关联计划任务（使用本地命令）';
  fScheduledTaskPath.appendChild(local);
  for (const task of scheduledTaskRows) {
    const option = document.createElement('option');
    option.value = task.path || '';
    const state = task.state === 'running' ? '运行中'
      : task.state === 'ready' ? '就绪'
        : task.state === 'disabled' ? '已禁用'
          : task.state === 'queued' ? '已排队' : '未知';
    option.textContent = (task.path || task.name || '未命名任务') + ' · ' + state;
    fScheduledTaskPath.appendChild(option);
  }
  if (selected && !scheduledTaskRows.some(task => task.path === selected)) {
    const missing = document.createElement('option');
    missing.value = selected;
    missing.textContent = selected + ' · 当前未找到';
    fScheduledTaskPath.appendChild(missing);
  }
  fScheduledTaskPath.value = selected;
}

function syncScheduledTaskMode({ inferKind = false } = {}) {
  const path = selectedScheduledTaskPath();
  const scheduled = scheduledTaskMode();
  const docker = selectedDockerResource();
  const external = scheduled || !!docker;
  const program = modalKind === 'program';
  const wasExternal = fCmd.readOnly;
  cwdField.hidden = external;
  detectPanel.hidden = external || detectPanel.hidden;
  btnPickScript.hidden = external;
  btnDetectProject.hidden = external || program;
  fCmd.readOnly = external || program;
  if (scheduled) {
    fCwd.value = '';
    fPort.value = '';
    fCmd.value = scheduledTaskCommand(path);
    setStructuredCommand(null, { status: 'ready', reasons: [] });
    const row = scheduledTaskRows.find(task => task.path === path);
    if (!fName.value.trim() && row) fName.value = row.name || row.path || '';
    if (inferKind && row && row.state === 'running') setModalKind('service');
  } else if (docker) {
    fCwd.value = docker.kind === 'compose' ? docker.workingDir || '' : '';
    fPort.value = '';
    fCmd.value = dockerResourceCommand(docker);
    setStructuredCommand(null, { status: 'ready', reasons: [] });
    const row = dockerResourceRows.find(item => item.key === dockerResourceKey(docker));
    if (!fName.value.trim() && row) {
      fName.value = row.label.split(' · ')[1] || row.label;
    }
    if (inferKind) setModalKind('service');
  } else if (wasExternal && !program) {
    fCmd.value = '';
    setStructuredCommand(null, null);
  }
  setText(fCmdLabel, scheduled ? '计划任务入口' : docker ? 'Docker 启动入口'
    : modalKind === 'task' ? '执行命令' : '启动命令');
  portField.hidden = external || modalKind !== 'service';
  fPort.disabled = external || modalKind !== 'service';
  refreshEditSaveMode();
}

async function loadScheduledTasks(selectedPath = selectedScheduledTaskPath()) {
  if (!hasCapability('monitor_scheduled_tasks') || currentPlatform() !== 'windows') return;
  btnRefreshScheduledTasks.disabled = true;
  try {
    const response = await fetch('/api/windows/scheduled-tasks', {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    const result = await response.json();
    if (!response.ok || !result || result.ok === false) {
      throw new Error((result && result.error) || '计划任务列表读取失败');
    }
    scheduledTaskRows = Array.isArray(result.tasks) ? result.tasks : [];
    renderScheduledTaskOptions(selectedPath);
    syncScheduledTaskMode();
  } catch (error) {
    renderScheduledTaskOptions(selectedPath);
    toast('Windows 计划任务读取失败：' + error.message);
  } finally {
    btnRefreshScheduledTasks.disabled = false;
  }
}

function dockerResourceCommand(resource) {
  if (!resource) return '';
  if (resource.kind === 'container') {
    return 'docker container start ' + resource.containerId;
  }
  const files = (resource.configFiles || [])
    .map(path => ' --file "' + path + '"').join('');
  return 'docker compose --project-name "' + resource.projectName + '"' +
    ' --project-directory "' + resource.workingDir + '"' + files + ' up --detach';
}

function renderDockerResourceOptions(selectedResource) {
  const selected = dockerResourceKey(selectedResource);
  fDockerResource.replaceChildren();
  const local = document.createElement('option');
  local.value = '';
  local.textContent = '不关联 Docker 资源（使用本地命令）';
  fDockerResource.appendChild(local);
  if (selectedResource && !dockerResourceRows.some(row => row.key === selected)) {
    dockerResourceRows.push({
      key: selected, resource: selectedResource,
      label: selected + ' · 当前未发现',
    });
  }
  for (const row of dockerResourceRows) {
    const option = document.createElement('option');
    option.value = row.key;
    option.textContent = row.label;
    fDockerResource.appendChild(option);
  }
  fDockerResource.value = selected;
}

async function loadDockerResources(selectedResource = selectedDockerResource()) {
  if (!hasCapability('monitor_docker')) return;
  btnRefreshDockerResources.disabled = true;
  try {
    const response = await fetch('/api/docker/resources', {
      method: 'GET', headers: { Accept: 'application/json' },
    });
    const result = await response.json();
    if (!response.ok || !result || result.ok === false) {
      throw new Error((result && result.error) || 'Docker 资源读取失败');
    }
    const projects = (result.projects || []).map(project => ({
      key: dockerResourceKey({ kind: 'compose', ...project }),
      resource: {
        kind: 'compose', projectName: project.projectName,
        workingDir: project.workingDir, configFiles: project.configFiles || [],
      },
      label: 'Compose · ' + project.projectName +
        (project.running ? ' · 运行中' : ' · 已停止'),
    })).filter(row => row.resource.workingDir && row.resource.configFiles.length);
    const containers = (result.containers || []).map(container => ({
      key: 'container:' + container.id,
      resource: { kind: 'container', containerId: container.id },
      label: '容器 · ' + (container.name || container.id.slice(0, 12)) +
        ' · ' + (container.running ? '运行中' : container.state || '已停止'),
    }));
    dockerResourceRows = [...projects, ...containers];
    renderDockerResourceOptions(selectedResource);
    syncScheduledTaskMode();
  } catch (error) {
    renderDockerResourceOptions(selectedResource);
    toast('Docker 资源读取失败：' + error.message);
  } finally {
    btnRefreshDockerResources.disabled = false;
  }
}

function compatibilityStatus(value) {
  if (value && ['ready', 'needs_review', 'blocked'].includes(value.status)) {
    return value.status;
  }
  return null;
}

function renderCommandCompatibility() {
  const status = compatibilityStatus(selectedCompatibility)
    || (selectedCommandSpec && selectedCommandSpec.needsReview ? 'needs_review' : null);
  commandCompatibility.classList.toggle('needs-review', status === 'needs_review');
  commandCompatibility.classList.toggle('blocked', status === 'blocked');
  if (!status) {
    commandCompatibility.hidden = true;
    commandCompatibility.textContent = '';
    return;
  }
  const label = status === 'ready' ? '可用于当前平台'
    : status === 'needs_review' ? '保存后仍需人工复核，当前平台不会执行'
      : '当前命令或路径不可用';
  const reasons = selectedCompatibility && Array.isArray(selectedCompatibility.reasons)
    ? selectedCompatibility.reasons.map(reason => reason && reason.message).filter(Boolean)
    : [];
  commandCompatibility.textContent = label + (reasons.length ? '：' + reasons.join('；') : '');
  commandCompatibility.hidden = false;
}

function setStructuredCommand(commandSpec, compatibility) {
  selectedCommandSpec = commandSpec && typeof commandSpec === 'object' ? commandSpec : null;
  selectedCompatibility = compatibility && typeof compatibility === 'object'
    ? compatibility : null;
  renderCommandCompatibility();
}

function invalidateCommandCompatibility() {
  selectedCompatibility = null;
  renderCommandCompatibility();
}

export function buildGlyphGrid() {
  GLYPHS.forEach(g => {
    const b = el('button', 'glyph-btn');
    b.type = 'button';
    b.title = g;
    b.setAttribute('aria-label', '选择图标 ' + g);
    b.setAttribute('aria-pressed', 'false');
    b.dataset.glyph = g;
    b.appendChild(icon(g, 17));
    b.addEventListener('click', () => {
      const selecting = selectedGlyph !== g;
      selectedGlyph = selecting ? g : null;
      if (selecting) {
        clearPendingIcon();
        const app = editingAppId ? findApp(editingAppId) : null;
        if (app && app.icon) removeStoredIcon = true;
      }
      syncGlyphGrid();
      renderIconPreview();
    });
    glyphGrid.appendChild(b);
  });
}
function syncGlyphGrid() {
  for (const b of glyphGrid.children) {
    const selected = b.dataset.glyph === selectedGlyph;
    b.classList.toggle('sel', selected);
    b.setAttribute('aria-pressed', String(selected));
  }
}

function clearPendingIcon() {
  if (pendingIcon) URL.revokeObjectURL(pendingIcon.url);
  pendingIcon = null;
}
function setPendingIcon(file) {
  clearPendingIcon();
  selectedGlyph = null;
  removeStoredIcon = false;
  pendingIcon = { blob: file, type: file.type || 'image/png', url: URL.createObjectURL(file) };
  syncGlyphGrid();
  renderIconPreview();
}
/* 预览优先级：待上传图片 > 已上传图片 > glyph > 名称首字 */
function renderIconPreview() {
  const app = editingAppId ? findApp(editingAppId) : null;
  const showImg = pendingIcon || (!removeStoredIcon && app && app.icon);
  const glyph = selectedGlyph;
  if (showImg) {
    const v = getIconVer(app && app.id);
    iconPreviewImg.src = pendingIcon ? pendingIcon.url : app.icon + (v ? '?v=' + v : '');
    iconPreviewImg.hidden = false;
    iconPreviewGlyph.hidden = true;
    iconPreviewTxt.hidden = true;
  } else if (glyph && window.LUCIDE && window.LUCIDE[glyph]) {
    iconPreviewImg.hidden = true;
    iconPreviewGlyph.hidden = false;
    iconPreviewTxt.hidden = true;
    setChildren(iconPreviewGlyph, icon(glyph, 20));
  } else {
    iconPreviewImg.hidden = true;
    iconPreviewGlyph.hidden = true;
    iconPreviewTxt.hidden = false;
    const nm = fName.value.trim();
    iconPreviewTxt.textContent = nm ? [...nm][0].toUpperCase() : '?';
  }
  btnRemoveIcon.hidden = !(pendingIcon || selectedGlyph ||
    (!removeStoredIcon && app && (app.icon || app.glyph)));
}

let modalKind = 'service';
let detectRequestSeq = 0;
let detectedPortValue = null;

function readPortValue() {
  const raw = fPort.value.trim();
  if (!raw) return null;
  if (!/^\d+$/.test(raw)) return NaN;
  const value = Number(raw);
  return Number.isInteger(value) && value >= 1 && value <= 65535 ? value : NaN;
}

function resetDetection(clearAutoPort = false) {
  detectRequestSeq += 1;
  detectingProject = false;
  if (clearAutoPort && detectedPortValue != null &&
      fPort.value.trim() === String(detectedPortValue)) fPort.value = '';
  detectedPortValue = null;
  btnDetectProject.disabled = false;
  btnPickCwd.disabled = false;
  detectPanel.hidden = true;
  detectList.replaceChildren();
  detectSummary.textContent = '';
  detectFiles.textContent = '';
}

function modalLifecycleChanged() {
  if (!editingAppOriginal) return false;
  const currentPort = modalKind === 'task' || externalResourceMode() ? null
    : readPortValue();
  return fCmd.value.trim() !== (editingAppOriginal.command || '') ||
    (fCwd.value.trim() || null) !== (editingAppOriginal.cwd || null) ||
    currentPort !== (editingAppOriginal.port == null ? null : editingAppOriginal.port) ||
    modalKind !== (editingAppOriginal.kind || 'service') ||
    (modalKind === 'program' && fElevated.checked !== editingAppOriginal.elevated) ||
    (modalKind === 'program' && JSON.stringify(selectedCommandSpec) !==
      JSON.stringify(editingAppOriginal.commandSpec)) ||
    selectedScheduledTaskPath() !== (editingAppOriginal.scheduledTaskPath || null) ||
    dockerResourceKey(selectedDockerResource()) !==
      dockerResourceKey(editingAppOriginal.dockerResource);
}

function refreshEditSaveMode() {
  const lifecycle = editingAppOriginal && editingAppOriginal.lifecycle;
  const externalMonitor = !!(editingAppOriginal && (
    editingAppOriginal.scheduledTaskPath || editingAppOriginal.dockerResource
  ));
  const observedRunning = !!(lifecycle && lifecycle.status === 'running');
  const running = observedRunning && !externalMonitor;
  const lifecycleUnavailable = !externalMonitor
    && !!(lifecycle && !lifecycle.canStart && !lifecycle.canManage);
  const needsStop = running && modalLifecycleChanged();
  const isTask = modalKind === 'task';
  const stopVerb = isTask ? '中止任务' : '停止服务';
  const canStop = hasCapability('stop_managed');
  const commandBlocked = compatibilityStatus(selectedCompatibility) === 'blocked';
  editRunningNotice.hidden = !running && !lifecycleUnavailable && !observedRunning;
  if (externalMonitor && observedRunning) {
    setText(editRunningNotice, '该 Guard 正由 Windows 任务计划程序运行；这里只修改监控卡片，不会停止外部任务。');
  } else if (lifecycleUnavailable) {
    setText(editRunningNotice, '运行身份暂时无法验证；生命周期配置和进程控制已安全禁用。');
  } else if (running) {
    setText(editRunningNotice, !canStop ? platformPresentation().lifecycleNotice
      : needsStop ? '修改内容已保留。请先' + stopVerb + '，再继续保存。'
        : (isTask ? '任务' : '服务') + '正在运行。可在这里先' + stopVerb +
          '，编辑面板不会关闭，当前填写内容也不会丢失。');
  }
  setText(appStopEdit, stopVerb);
  appStopEdit.hidden = externalMonitor || !running || !canStop || !lifecycle.canManage;
  appStopEdit.disabled = appSaving || !canStop || !lifecycle || !lifecycle.canManage;
  appSave.hidden = false;
  const willAttach = !editingAppId && pendingAttach && modalKind === 'service'
    && !externalResourceMode()
    && readPortValue() === pendingAttach.port;
  setText(appSave, willAttach ? '保存并认领' : '保存');
  appSave.disabled = appSaving || needsStop || commandBlocked
    || (lifecycleUnavailable && modalLifecycleChanged())
    || (willAttach && detectingProject);
  appSave.title = commandBlocked ? '当前命令或路径不可用，请先修正'
    : lifecycleUnavailable && modalLifecycleChanged()
      ? '运行身份无法验证，不能修改生命周期配置'
      : needsStop ? (canStop ? '请先在当前面板' + stopVerb
      : platformPresentation().lifecycleNotice)
      : (willAttach && detectingProject ? '正在识别可靠的项目启动命令' : '');
}

function setModalKind(kind) {
  modalKind = ['service', 'task', 'program'].includes(kind) ? kind : 'service';
  if (modalKind === 'program') {
    fScheduledTaskPath.value = '';
    fDockerResource.value = '';
  }
  kindRow.querySelectorAll('.kind-btn').forEach(b => {
    const active = b.dataset.kind === modalKind;
    b.classList.toggle('active', active);
    b.setAttribute('aria-pressed', String(active));
  });
  const program = modalKind === 'program';
  scheduledTaskField.hidden = program || currentPlatform() !== 'windows'
    || !hasCapability('monitor_scheduled_tasks');
  dockerResourceField.hidden = program || !hasCapability('monitor_docker');
  programArgsField.hidden = !program;
  elevatedField.hidden = !program || currentPlatform() !== 'windows';
  portField.hidden = modalKind !== 'service' || externalResourceMode();
  fPort.disabled = modalKind !== 'service' || externalResourceMode();
  fCmd.readOnly = externalResourceMode() || program;
  btnDetectProject.hidden = program || externalResourceMode();
  btnPickScript.hidden = externalResourceMode();
  setText(btnPickScript, program ? '选择 EXE' : '选择脚本…');
  setText(fCmdLabel, scheduledTaskMode() ? '计划任务入口'
    : dockerResourceMode() ? 'Docker 启动入口'
    : modalKind === 'program' ? 'EXE 路径'
      : modalKind === 'task' ? '执行命令' : '启动命令');
  fName.placeholder = modalKind === 'task' ? '如：每日备份'
    : modalKind === 'program' ? '如：设备管理器' : '如：本地博客';
  fCmd.placeholder = modalKind === 'program' ? '请选择一个 EXE'
    : modalKind === 'task'
    ? '选择脚本后自动生成执行命令，也可以手动填写'
    : '选择项目后自动识别启动命令，也可以手动填写';
  appModalTitle.textContent = (editingAppId ? '编辑' : '添加') +
    (modalKind === 'task' ? '批处理任务'
      : modalKind === 'program' ? '程序' : '服务');
  refreshEditSaveMode();
}
kindRow.querySelectorAll('.kind-btn').forEach(b =>
  b.addEventListener('click', () => setModalKind(b.dataset.kind)));

export function openAppModal(app, presetKind, focusAction = '') {
  editingAppId = app ? app.id : null;
  pendingAttach = hasCapability('attach_external') && !editingAppId && app
    && Number.isInteger(app.attachPid)
    && app.attachPid > 0 && Number.isInteger(Number(app.port))
    ? {
        pid: app.attachPid,
        port: Number(app.port),
        instanceKey: app.attachInstanceKey || null,
        command: (app.command || '').trim(),
      }
    : null;
  editingAppOriginal = app ? {
    command: app.command || '', cwd: app.cwd || null,
    port: app.port == null ? null : app.port,
    kind: app.kind || 'service', running: !!app.running,
    commandSpec: app.commandSpec || null,
    scheduledTaskPath: app.scheduledTaskPath || null,
    dockerResource: app.dockerResource || null,
    elevated: app.elevated === true,
    lifecycle: lifecycleSnapshot(app, currentPlatform()),
  } : null;
  resetDetection();
  clearPendingIcon();
  removeStoredIcon = false;
  selectedGlyph = (app && app.glyph) || null;
  setStructuredCommand(app && app.commandSpec, app && app.platformCompatibility);
  fName.value = (app && app.name) || '';
  fCmd.value = (app && app.command) || '';
  fCwd.value = (app && app.cwd) || '';
  fPort.value = app && app.port != null ? app.port : '';
  const programArgs = app && app.commandSpec && app.commandSpec.mode === 'direct'
    && Array.isArray(app.commandSpec.args) ? app.commandSpec.args : [];
  fProgramArgs.value = programArgs.join('\n');
  fElevated.checked = app ? app.elevated === true : currentPlatform() === 'windows';
  scheduledTaskField.hidden = currentPlatform() !== 'windows'
    || !hasCapability('monitor_scheduled_tasks');
  dockerResourceField.hidden = !hasCapability('monitor_docker');
  renderScheduledTaskOptions((app && app.scheduledTaskPath) || '');
  renderDockerResourceOptions((app && app.dockerResource) || null);
  [fName, fCmd, fCwd, fPort].forEach(clearFieldError);
  setModalKind(presetKind || (app && app.kind) || 'service');
  syncScheduledTaskMode();
  appearanceDetails.open = !!(app && (app.icon || app.glyph));
  syncGlyphGrid();
  renderIconPreview();
  const focusTarget = focusAction === 'pick-script' ? btnPickScript
      : focusAction === 'pick-cwd' ? btnPickCwd
      : focusAction === 'edit-command' ? fCmd
        : app ? fName : (modalKind === 'task' || modalKind === 'program'
          ? btnPickScript : btnPickCwd);
  openLayer(appModalMask, focusTarget);
  if (!scheduledTaskField.hidden) loadScheduledTasks((app && app.scheduledTaskPath) || '');
  if (!dockerResourceField.hidden) loadDockerResources((app && app.dockerResource) || null);
  /* 监听进程的 argv 往往只是框架子进程（如 next-server），不一定适合作为
     下次启动命令。打开认领表单时同时读取项目配置，让用户选择可靠命令。 */
  if (pendingAttach && fCwd.value.trim()) detectProject();
}
export function closeAppModal() {
  closeLayer(appModalMask);
  resetDetection();
  editingAppId = null;
  editingAppOriginal = null;
  clearPendingIcon();
  selectedGlyph = null;
  removeStoredIcon = false;
  pendingAttach = null;
  fCmd.readOnly = false;
  cwdField.hidden = false;
  btnPickScript.hidden = false;
  btnDetectProject.hidden = false;
  setStructuredCommand(null, null);
}

function applyDetectedCandidate(candidate, option) {
  const previousAutoPort = detectedPortValue == null ? '' : String(detectedPortValue);
  const currentPort = fPort.value.trim();
  fCmd.value = candidate.command || '';
  setStructuredCommand(candidate.commandSpec, candidate.platformCompatibility);
  clearFieldError(fCmd);
  setModalKind(candidate.kind || 'service');
  if (candidate.port != null) {
    if (!currentPort || currentPort === previousAutoPort) {
      fPort.value = String(candidate.port);
      detectedPortValue = candidate.port;
    } else {
      detectedPortValue = null;
    }
  } else {
    if (previousAutoPort && currentPort === previousAutoPort) fPort.value = '';
    detectedPortValue = null;
  }
  detectList.querySelectorAll('.detect-option').forEach(node => {
    const active = node === option;
    node.classList.toggle('selected', active);
    node.setAttribute('aria-pressed', String(active));
  });
  const portText = candidate.port != null && fPort.value === String(candidate.port)
    ? '，端口 ' + candidate.port : '';
  refreshEditSaveMode();
  toast('已填入“' + candidate.label + '”' + portText);
}

function renderDetection(result) {
  const candidates = Array.isArray(result.candidates) ? result.candidates : [];
  detectPanel.hidden = false;
  detectList.replaceChildren();
  const files = Array.isArray(result.files) ? result.files : [];
  detectFiles.textContent = files.length ? '读取了 ' + files.join('、') : '';
  if (!candidates.length) {
    detectSummary.textContent = '没有识别到可直接启动的配置';
    const empty = el('p', 'detect-empty');
    empty.textContent = '仍可选择脚本，系统会按文件类型生成执行命令；也可以手动填写。';
    detectList.appendChild(empty);
    return;
  }
  detectSummary.textContent = '找到 ' + candidates.length + ' 个候选，选择一个填入';
  candidates.forEach((candidate, index) => {
    const option = el('button', 'detect-option');
    option.type = 'button';
    option.setAttribute('aria-pressed', 'false');
    const head = el('span', 'detect-option-head');
    const title = el('span', 'detect-option-title');
    title.textContent = candidate.label || '启动项目';
    head.appendChild(title);
    if (index === 0) {
      const recommended = el('span', 'detect-recommended');
      recommended.textContent = '推荐';
      head.appendChild(recommended);
    }
    if (candidate.kind === 'task') {
      const kind = el('span', 'detect-kind');
      kind.textContent = '任务';
      head.appendChild(kind);
    }
    if (candidate.port != null) {
      const port = el('span', 'detect-port mono');
      port.textContent = ':' + candidate.port;
      head.appendChild(port);
    }
    const command = el('span', 'detect-command mono');
    const mode = candidate.commandSpec && candidate.commandSpec.mode;
    command.textContent = (mode ? '[' + mode + '] ' : '') + (candidate.command || '');
    const source = el('span', 'detect-source');
    source.textContent = candidate.source || '';
    option.append(head, command, source);
    option.addEventListener('click', () => applyDetectedCandidate(candidate, option));
    detectList.appendChild(option);
  });
}

async function detectProject() {
  const cwd = fCwd.value.trim();
  if (!cwd) return fieldError(fCwd, '请先选择项目文件夹');
  const requestSeq = ++detectRequestSeq;
  detectPanel.hidden = false;
  detectSummary.textContent = '正在读取项目配置…';
  detectFiles.textContent = '';
  detectList.replaceChildren();
  btnDetectProject.disabled = true;
  btnPickCwd.disabled = true;
  detectingProject = true;
  refreshEditSaveMode();
  try {
    const result = await act(post('/api/project/detect', { cwd }));
    if (requestSeq !== detectRequestSeq) return;
    if (!result || result.ok === false) {
      detectSummary.textContent = '识别失败，请检查文件夹后重试';
      return;
    }
    if (!fName.value.trim() && result.name) {
      fName.value = result.name;
      renderIconPreview();
    }
    renderDetection(result);
    if (pendingAttach && !editingAppId &&
        fCmd.value.trim() === pendingAttach.command) {
      const candidates = Array.isArray(result.candidates) ? result.candidates : [];
      const index = candidates.findIndex(candidate =>
        candidate.kind !== 'task' && Number(candidate.port) === pendingAttach.port);
      if (index >= 0) {
        const option = detectList.querySelectorAll('.detect-option')[index];
        applyDetectedCandidate(candidates[index], option);
      }
    }
  } finally {
    if (requestSeq === detectRequestSeq) {
      detectingProject = false;
      btnDetectProject.disabled = false;
      btnPickCwd.disabled = false;
      refreshEditSaveMode();
    }
  }
}

function fieldError(input, msg) {
  toast(msg);
  input.classList.add('invalid');
  input.setAttribute('aria-invalid', 'true');
  input.focus();
}
function clearFieldError(input) {
  input.classList.remove('invalid');
  input.removeAttribute('aria-invalid');
}

async function stopEditingApp() {
  if (!editingAppId || !editingAppOriginal || !editingAppOriginal.lifecycle) return;
  const intent = editingAppOriginal.lifecycle;
  if (!intent.canManage) {
    toast('运行身份无法验证，已禁止停止；请查看诊断');
    return;
  }
  if (!hasCapability('stop_managed')) {
    toast(platformPresentation().lifecycleNotice);
    return;
  }
  appSaving = true;
  refreshEditSaveMode();
  const isTask = modalKind === 'task';
  toast((isTask ? '正在中止任务' : '正在停止服务') + '，编辑内容会保留…');
  try {
    const { result, stateIsFresh } = await runLifecycleMutation(
      () => act(post(
        '/api/apps/' + editingAppId + '/stop',
        lifecyclePayload(intent, { force: false }),
      )),
      refreshLifecycleState,
    );
    const latest = findApp(editingAppId);
    if (latest) {
      editingAppOriginal.running = !!latest.running;
      editingAppOriginal.lifecycle = lifecycleSnapshot(latest, currentPlatform());
    }
    if ((result && result.ok !== false) || (latest && !latest.running
        && editingAppOriginal.lifecycle.status === 'stopped')) {
      toast((isTask ? '任务已中止' : '服务已停止') + '，可以继续编辑并保存');
    } else {
      offerForceStopAfterTimeout(
        result,
        intent,
        editingAppId,
        latest && latest.name,
        stateIsFresh,
        stopped => {
          if (!stopped) return;
          editingAppOriginal.running = !!stopped.running;
          editingAppOriginal.lifecycle = lifecycleSnapshot(stopped, currentPlatform());
          refreshEditSaveMode();
        },
      );
    }
  } finally {
    appSaving = false;
    refreshEditSaveMode();
  }
}

function rememberSavedApp(app, id, body) {
  editingAppId = id;
  editingAppOriginal = {
    command: body.command,
    cwd: body.cwd,
    port: body.port,
    kind: body.kind,
    commandSpec: body.commandSpec || null,
    scheduledTaskPath: body.scheduledTaskPath || null,
    dockerResource: body.dockerResource || null,
    elevated: body.elevated === true,
    running: !!app.running,
    lifecycle: lifecycleSnapshot(app, currentPlatform()),
  };
  setStructuredCommand(app.commandSpec || body.commandSpec, app.platformCompatibility);
  setModalKind(body.kind);
}

async function saveApp() {
  const name = fName.value.trim();
  const command = fCmd.value.trim();
  if (!name) return fieldError(fName, '请填写名称');
  if (!command) return fieldError(
    fCmd, modalKind === 'task' ? '请填写执行命令' : '请填写启动命令');
  if (modalKind === 'program') {
    if (!selectedCommandSpec || selectedCommandSpec.mode !== 'direct'
        || !String(selectedCommandSpec.executable || '').toLowerCase().endsWith('.exe')) {
      return fieldError(fCmd, '请选择一个 EXE 程序');
    }
    selectedCommandSpec = {
      ...selectedCommandSpec,
      args: fProgramArgs.value.split(/\r?\n/).filter(value => value !== ''),
    };
  }
  const port = modalKind !== 'service' || externalResourceMode() ? null : readPortValue();
  if (Number.isNaN(port)) return fieldError(fPort, '端口必须是 1–65535 之间的整数');
  const body = {
    name,
    command,
    cwd: fCwd.value.trim() || null,
    port,
    glyph: selectedGlyph || null,
    kind: modalKind,
    scheduledTaskPath: selectedScheduledTaskPath(),
    dockerResource: selectedDockerResource(),
    elevated: modalKind === 'program' && fElevated.checked,
  };
  if (selectedCommandSpec) body.commandSpec = selectedCommandSpec;
  if (externalResourceMode()) delete body.commandSpec;
  if (editingAppOriginal && editingAppOriginal.lifecycle) {
    body.expectedGeneration = editingAppOriginal.lifecycle.expectedGeneration;
  }
  const wasCreating = !editingAppId;
  const attachRequest = wasCreating && hasCapability('attach_external') && pendingAttach
    && modalKind === 'service'
    && !externalResourceMode()
    && port === pendingAttach.port ? { ...pendingAttach } : null;
  if (attachRequest) body.attachPid = attachRequest.pid;
  appSaving = true;
  refreshEditSaveMode();
  try {
    const app = editingAppId
      ? (await runLifecycleMutation(
        () => act(put('/api/apps/' + editingAppId, body)),
        async app => await refreshLifecycleState(app),
      )).result
      : await act(post('/api/apps', body));
    if (!app || app.ok === false) {
      if (!wasCreating) {
        const latest = findApp(editingAppId);
        if (latest) {
          editingAppOriginal.running = !!latest.running;
          editingAppOriginal.lifecycle = lifecycleSnapshot(latest, currentPlatform());
        }
      }
      if (app && app.requiresStop && editingAppOriginal) {
        editingAppOriginal.running = true;
      }
      refreshEditSaveMode();
      return;
    }
    const id = app.id || editingAppId;
    const attachSucceeded = !!(attachRequest && app.attached);
    if (attachSucceeded && app.cwd) {
      body.cwd = app.cwd;
      fCwd.value = app.cwd;
    }
    rememberSavedApp(
      attachSucceeded ? { ...app, running: true } : app,
      id,
      body,
    );
    if (pendingIcon && id) {
      try {
        const r = await fetch('/api/apps/' + id + '/icon', {
          method: 'POST',
          headers: { 'Content-Type': pendingIcon.type },
          body: pendingIcon.blob,
        });
        const j = await r.json();
        if (!r.ok || (j && j.ok === false)) {
          toast((j && j.error) || '图标上传失败，配置已保存，可直接重试');
          await window.__poll();
          return;
        }
        bumpIconVer(id);
        bumpMutationEpoch();   // 原生 fetch 不经过 req，手动作废在途旧快照
      } catch (e) {
        toast('图标上传失败：' + e.message + '。配置已保存，可直接重试');
        await window.__poll();
        return;
      }
    } else if (removeStoredIcon && id) {
      const result = await act(del('/api/apps/' + id + '/icon'));
      if (!result || result.ok === false) {
        toast('配置已保存，但图标清除失败，可直接重试');
        await window.__poll();
        return;
      }
      removeStoredIcon = false;
      bumpIconVer(id);
    }
    closeAppModal();
    await window.__poll();
    if (attachSucceeded) toast('已加入启动台并认领正在运行的进程');
    if (body.elevated) {
      const broker = (state.data && state.data.elevationBroker) || {};
      if (!broker.unlocked) openBrokerPassword();
    }
  } finally {
    appSaving = false;
    refreshEditSaveMode();
  }
}

export function initAppModal({ onAddService, onAddTask, onAddProgram }) {
  onAddService.addEventListener('click', () => openAppModal(null, 'service'));
  onAddTask.addEventListener('click', () => openAppModal(null, 'task'));
  onAddProgram.addEventListener('click', () => openAppModal(null, 'program'));
  appCancel.addEventListener('click', closeAppModal);
  appSave.addEventListener('click', saveApp);
  appStopEdit.addEventListener('click', stopEditingApp);
  fScheduledTaskPath.addEventListener('change', () => {
    if (selectedScheduledTaskPath()) fDockerResource.value = '';
    syncScheduledTaskMode({ inferKind: !editingAppId });
    renderIconPreview();
  });
  btnRefreshScheduledTasks.addEventListener('click', () => {
    loadScheduledTasks(selectedScheduledTaskPath());
  });
  fDockerResource.addEventListener('change', () => {
    if (selectedDockerResource()) fScheduledTaskPath.value = '';
    syncScheduledTaskMode({ inferKind: !editingAppId });
    renderIconPreview();
  });
  btnRefreshDockerResources.addEventListener('click', () => {
    loadDockerResources(selectedDockerResource());
  });
  appModalMask.addEventListener('mousedown', e => { if (e.target === appModalMask) closeAppModal(); });

  /* 选择批处理脚本：自动填命令 / 工作目录 / 名称 */
  btnPickScript.addEventListener('click', async () => {
    btnPickScript.disabled = true;
    try {
      const r = await act(post('/api/pick', {
        what: modalKind === 'program' ? 'exe' : 'script',
      }));
      if (!r || r.canceled || !r.path) return;  // 取消或失败均静默
      if (!r.command || !r.commandSpec) {
        toast('选择结果缺少结构化命令，请刷新总控台后重试');
        return;
      }
      if (modalKind === 'program' && !r.path.toLowerCase().endsWith('.exe')) {
        toast('程序只接受 EXE 文件');
        return;
      }
      fCmd.value = modalKind === 'program' ? r.path : r.command;
      setStructuredCommand(r.commandSpec, r.platformCompatibility);
      if (r.dir && !fCwd.value.trim()) fCwd.value = r.dir;
      if (!fName.value.trim()) {
        if (r.stem) fName.value = r.stem;
      }
      fCmd.classList.remove('invalid');
      refreshEditSaveMode();
      detectList.querySelectorAll('.detect-option').forEach(node => {
        node.classList.remove('selected');
        node.setAttribute('aria-pressed', 'false');
      });
      toast(modalKind === 'program' ? '已选择 EXE' : '已按脚本类型生成执行命令');
    } finally {
      btnPickScript.disabled = false;
    }
  });

  /* 浏览工作目录（当前平台原生选择框） */
  btnPickCwd.addEventListener('click', async () => {
    btnPickCwd.disabled = true;
    try {
      const r = await act(post('/api/pick', { what: 'dir' }));
      if (r && !r.canceled && r.path) {
        fCwd.value = r.path;
        invalidateCommandCompatibility();
        if (!fName.value.trim() && r.stem) fName.value = r.stem;
        fCwd.classList.remove('invalid');
        refreshEditSaveMode();
        if (modalKind !== 'program') await detectProject();
      }
    } finally {
      btnPickCwd.disabled = false;
    }
  });
  btnDetectProject.addEventListener('click', detectProject);
  fCwd.addEventListener('input', () => {
    invalidateCommandCompatibility();
    resetDetection(true);
  });
  [fName, fCwd, fPort].forEach(input =>
    input.addEventListener('input', () => {
      clearFieldError(input);
      refreshEditSaveMode();
    }));
  fCmd.addEventListener('input', () => {
    clearFieldError(fCmd);
    setStructuredCommand(null, null);
    refreshEditSaveMode();
  });
  fProgramArgs.addEventListener('input', () => {
    if (selectedCommandSpec && selectedCommandSpec.mode === 'direct') {
      selectedCommandSpec = {
        ...selectedCommandSpec,
        args: fProgramArgs.value.split(/\r?\n/).filter(value => value !== ''),
      };
    }
    refreshEditSaveMode();
  });
  fElevated.addEventListener('change', refreshEditSaveMode);

  /* 图标：上传 / 粘贴 / 清除 */
  btnPickIcon.addEventListener('click', () => iconFile.click());
  iconFile.addEventListener('change', () => {
    const f = iconFile.files && iconFile.files[0];
    if (f) {
      if (!/^image\/(png|jpeg|webp)$/.test(f.type)) toast('仅支持 png / jpg / webp 图片');
      else if (f.size > 5 * 1024 * 1024) toast('图标不能超过 5MB');
      else setPendingIcon(f);
    }
    iconFile.value = '';
  });
  appModal.addEventListener('paste', e => {
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const it of items) {
      if (it.type && /^image\/(png|jpeg|webp)$/.test(it.type)) {
        const f = it.getAsFile();
        if (f) {
          if (f.size > 5 * 1024 * 1024) toast('图标不能超过 5MB');
          else {
            setPendingIcon(f);
            toast('已从剪贴板读取图片');
          }
          e.preventDefault();
          break;
        }
      }
    }
  });
  btnRemoveIcon.addEventListener('click', () => {
    clearPendingIcon();
    selectedGlyph = null;
    syncGlyphGrid();
    if (editingAppId) {
      const a = findApp(editingAppId);
      removeStoredIcon = !!(a && a.icon);
    }
    renderIconPreview();
  });
  fName.addEventListener('input', renderIconPreview);
  /* 非 textarea 字段回车直接保存 */
  [fName, fCwd, fPort].forEach(inp =>
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') saveApp(); }));
}

/* ============================================================
   日志抽屉
   ============================================================ */
let logTimer = null;
let logAppId = null;
let logRequestSeq = 0;
let logController = null;
let logIsConsole = false;

function logEndpoint(appId) {
  return logIsConsole ? '/api/console/log?tail=300'
    : '/api/apps/' + appId + '/logs?tail=300';
}

export function openLogs(app) {
  openLogDrawer(app.id, (app.name || '') + ' · 日志');
}
export function openConsoleLog() {
  openLogDrawer('console', '总控台 · 日志');
}
function openLogDrawer(appId, title) {
  closeLogs();
  logAppId = appId;
  logIsConsole = appId === 'console';
  const requestSeq = ++logRequestSeq;
  drawerTitle.textContent = title;
  logPre.textContent = '加载中…';
  logSourceStatus.hidden = true;
  logTaskHistoryEnable.hidden = true;
  logBody.setAttribute('aria-busy', 'true');
  openLayer(logDrawer, drawerClose);
  drawerMask.classList.add('open');
  drawerMask.setAttribute('aria-hidden', 'false');
  fetchLogs(appId, requestSeq);
}
async function fetchLogs(appId, requestSeq) {
  if (!logAppId || logAppId !== appId || requestSeq !== logRequestSeq) return;
  const controller = new AbortController();
  logController = controller;
  try {
    const r = await fetch(logEndpoint(appId), {
      cache: 'no-store',
      signal: controller.signal,
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    if (logAppId !== appId || requestSeq !== logRequestSeq) return;
    const firstLoad = logPre.textContent === '加载中…';
    const nearBottom = firstLoad ||
      logBody.scrollHeight - logBody.scrollTop - logBody.clientHeight < 48;
    const text = j.text || '暂无日志';
    renderTaskHistorySource(j.taskHistory);
    /* 增量追加新行：全量重写会打断用户选区并让滚动位置漂移。 */
    const previous = firstLoad ? '' : logPre.textContent;
    if (previous && text.startsWith(previous)) {
      logPre.append(document.createTextNode(text.slice(previous.length)));
    } else {
      logPre.textContent = text;
    }
    logBody.setAttribute('aria-busy', 'false');
    if (nearBottom) requestAnimationFrame(() => {
      if (logAppId === appId && requestSeq === logRequestSeq) {
        logBody.scrollTop = logBody.scrollHeight;
      }
    });
  } catch (e) {
    if (e.name !== 'AbortError' && logAppId === appId && requestSeq === logRequestSeq) {
      if (logPre.textContent === '加载中…') logPre.textContent = '日志加载失败，正在重试…';
      logBody.setAttribute('aria-busy', 'false');
    }
  } finally {
    if (logController === controller) logController = null;
    if (!document.hidden && logAppId === appId && requestSeq === logRequestSeq) {
      logTimer = setTimeout(() => fetchLogs(appId, requestSeq), 1500);
    }
  }
}

function renderTaskHistorySource(taskHistory) {
  const applicable = !!(taskHistory && taskHistory.applicable);
  logSourceStatus.hidden = !applicable;
  if (!applicable) {
    logTaskHistoryEnable.hidden = true;
    return;
  }
  const count = Number(taskHistory.eventCount) || 0;
  if (taskHistory.enabled === true) {
    logSourceText.textContent = 'Windows 任务历史已启用 · ' + count + ' 条事件';
  } else if (taskHistory.enabled === false) {
    logSourceText.textContent = 'Windows 任务历史未启用 · 当前显示已有记录';
  } else {
    logSourceText.textContent = 'Windows 任务历史状态不可用';
  }
  logTaskHistoryEnable.hidden = taskHistory.enabled !== false
    || !hasCapability('manage_scheduled_task_history');
}

logTaskHistoryEnable.addEventListener('click', async () => {
  if (!logAppId || logIsConsole || logTaskHistoryEnable.disabled) return;
  logTaskHistoryEnable.disabled = true;
  try {
    const result = await act(post(
      '/api/apps/' + logAppId + '/scheduled-history', { enabled: true }
    ));
    if (result && result.ok) {
      toast('已启用 Windows 任务历史');
      fetchLogs(logAppId, ++logRequestSeq);
    }
  } finally {
    logTaskHistoryEnable.disabled = false;
  }
});
export function closeLogs() {
  logRequestSeq += 1;
  if (logTimer) { clearTimeout(logTimer); logTimer = null; }
  if (logController) { logController.abort(); logController = null; }
  logAppId = null;
  logSourceStatus.hidden = true;
  logTaskHistoryEnable.hidden = true;
  logBody.setAttribute('aria-busy', 'false');
  closeLayer(logDrawer);
  drawerMask.classList.remove('open');
  drawerMask.setAttribute('aria-hidden', 'true');
}
export function initLogDrawer() {
  drawerClose.addEventListener('click', closeLogs);
  drawerMask.addEventListener('click', closeLogs);
  document.addEventListener('visibilitychange', () => {
    if (!logAppId) return;
    if (document.hidden) {
      logRequestSeq += 1;
      if (logTimer) { clearTimeout(logTimer); logTimer = null; }
      if (logController) { logController.abort(); logController = null; }
    } else {
      fetchLogs(logAppId, ++logRequestSeq);
    }
  });
}
