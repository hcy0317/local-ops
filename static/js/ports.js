'use strict';

/* 后端根据真实 bind address 返回 openHost；旧后端缺字段时保持原行为。 */
export function localServiceUrl(item, port) {
  const value = Number(port);
  if (!Number.isInteger(value) || value <= 0 || value > 65535) return '';
  let host = item && item.openHosts && item.openHosts[String(value)];
  if (!host && item) host = item.openHost;
  host = host === 'localhost' ? 'localhost' : '127.0.0.1';
  return 'http://' + host + ':' + value;
}

/* 自定义网址只交给浏览器打开，不参与监听发现、图标抓取或进程控制。 */
export function normalizeOpenUrl(value) {
  if (typeof value !== 'string') return '';
  const text = value.trim();
  if (!text || text.length > 4096 || /[\s\\]/.test(text) || !/^https?:\/\//i.test(text)) return '';
  try {
    const url = new URL(text);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname
        || url.username || url.password || url.port === '0') return '';
    return text;
  } catch (e) { return ''; }
}

export function appLinkUrl(app) {
  return normalizeOpenUrl(app && app.openUrl) || localServiceUrl(app, preferredOpenPort(app));
}

export function appIsOpenable(app) {
  return !!normalizeOpenUrl(app && app.openUrl) || portIsOpenable(app);
}

/* ============================================================
   ports.js — 端口归一化纯函数（无 DOM 依赖）

   配置端口用于启动前校验，ports 才是运行中进程实际监听的端口。
   两者不一致时，所有“打开/复制”动作必须使用实际端口，避免给出失效链接。
   独立成模块供启动台 / 服务监控 / 命令面板复用，也可被 node 直接单测。
   ============================================================ */

export function normalizePort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

export function configuredPort(app) {
  return normalizePort(app && app.port);
}

export function actualPorts(app) {
  const seen = new Set();
  for (const value of (app && Array.isArray(app.ports) ? app.ports : [])) {
    const port = normalizePort(value);
    if (port) seen.add(port);
  }
  return [...seen];
}

export function hasPortMismatch(app) {
  const configured = configuredPort(app);
  const actual = actualPorts(app);
  return !!(app && app.running && configured && app.listening === false
    && actual.length && !actual.includes(configured));
}

export function preferredOpenPort(app) {
  const configured = configuredPort(app);
  const actual = actualPorts(app);
  if (hasPortMismatch(app)) return actual[0] || null;
  if (configured && (!app || !app.running || app.listening !== false)) return configured;
  return actual[0] || configured;
}

export function displayedPorts(app) {
  const configured = configuredPort(app);
  const actual = actualPorts(app);
  if (app && app.running && actual.length) {
    const preferred = preferredOpenPort(app);
    return [preferred, ...actual.filter(port => port !== preferred)];
  }
  return configured ? [configured] : actual;
}

export function portIsOpenable(app) {
  return !!(app && app.running && preferredOpenPort(app)
    && (!configuredPort(app) || app.listening !== false || hasPortMismatch(app)));
}
