'use strict';

const MOUSE_DRAG_THRESHOLD_PX = 6;
const TOUCH_MOVE_CANCEL_PX = 10;
export const TOUCH_SORT_HOLD_MS = 450;

export class PointerSortSession {
  constructor() {
    this.pointerId = null;
    this.active = false;
  }

  reserve(pointerId) {
    if (!Number.isInteger(pointerId) || this.pointerId !== null) return false;
    this.pointerId = pointerId;
    this.active = false;
    return true;
  }

  activate(pointerId) {
    if (!this.owns(pointerId)) return false;
    this.active = true;
    return true;
  }

  owns(pointerId) {
    return this.pointerId !== null && this.pointerId === pointerId;
  }

  release(pointerId) {
    if (!this.owns(pointerId)) return false;
    this.pointerId = null;
    this.active = false;
    return true;
  }
}

/* 触摸卡片先服从页面滚动；只有保持不动完成长按才进入排序。
   返回 wait/start/cancel，让事件层在 cancel 前不阻止浏览器默认滚动。 */
export function pointerSortIntent(pointerType, deltaX, deltaY, elapsedMs = 0) {
  const x = Math.abs(Number(deltaX) || 0);
  const y = Math.abs(Number(deltaY) || 0);
  if (pointerType === 'touch') {
    if (Math.hypot(x, y) >= TOUCH_MOVE_CANCEL_PX) return 'cancel';
    return Number(elapsedMs) >= TOUCH_SORT_HOLD_MS ? 'start' : 'wait';
  }
  return x + y >= MOUSE_DRAG_THRESHOLD_PX ? 'start' : 'wait';
}

/* 所有排序中的临时节点和恢复节点都停在添加卡之前，添加卡因此始终是尾锚点。 */
export function insertBeforePinnedAddCard(grid, node) {
  const addCard = [...grid.children]
    .find(child => child.classList && child.classList.contains('add-card')) || null;
  grid.insertBefore(node, addCard);
}
