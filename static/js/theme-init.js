'use strict';

/* 同源阻塞脚本：必须在首张样式表前确定主题，避免模块加载后的浅色首帧。 */
(function applyInitialTheme() {
  let stored = null;
  try {
    stored = localStorage.getItem('console-theme');
  } catch (error) {
    stored = null;
  }
  const systemDark = window.matchMedia
    && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = stored === 'dark' || stored === 'light'
    ? stored : systemDark ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme;
}());
