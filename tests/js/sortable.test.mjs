import test from 'node:test';
import assert from 'node:assert/strict';
import {
  insertBeforePinnedAddCard,
  PointerSortSession,
  pointerSortIntent,
} from '../../static/js/sortable.js';

test('触摸卡片在长按成立前移动就只滚动页面', () => {
  assert.equal(pointerSortIntent('touch', 2, 9, 200), 'wait');
  assert.equal(pointerSortIntent('touch', 7, 7, 200), 'wait');
  assert.equal(pointerSortIntent('touch', 8, 8, 200), 'cancel');
  assert.equal(pointerSortIntent('touch', 3, 10, 200), 'cancel');
  assert.equal(pointerSortIntent('touch', 12, 24, 200), 'cancel');
});

test('一个 pointer session 只能由最先按下的指针激活和释放', () => {
  const session = new PointerSortSession();

  assert.equal(session.reserve(11), true);
  assert.equal(session.reserve(22), false);
  assert.equal(session.activate(22), false);
  assert.equal(session.activate(11), true);
  assert.equal(session.owns(22), false);
  assert.equal(session.release(22), false);
  assert.equal(session.owns(11), true);
  assert.equal(session.release(11), true);
  assert.equal(session.pointerId, null);
  assert.equal(session.active, false);
});

test('触摸排序需要长按 450ms，鼠标仍保留短距离拖拽', () => {
  assert.equal(pointerSortIntent('touch', 0, 0, 449), 'wait');
  assert.equal(pointerSortIntent('touch', 0, 0, 450), 'start');
  assert.equal(pointerSortIntent('touch', 10, 0, 450), 'cancel');
  assert.equal(pointerSortIntent('mouse', 3, 2), 'wait');
  assert.equal(pointerSortIntent('mouse', 3, 3), 'start');
});

test('排序占位和恢复卡片只能插入固定的添加卡之前', () => {
  const card = { id: 'card', classList: { contains: () => false } };
  const addCard = {
    id: 'add',
    classList: { contains: name => name === 'add-card' },
  };
  const placeholder = { id: 'placeholder', classList: { contains: () => false } };
  const children = [card, addCard];
  const grid = {
    children,
    insertBefore(node, anchor) {
      const current = children.indexOf(node);
      if (current >= 0) children.splice(current, 1);
      const index = anchor ? children.indexOf(anchor) : children.length;
      children.splice(index, 0, node);
    },
  };

  insertBeforePinnedAddCard(grid, placeholder);

  assert.deepEqual(children.map(node => node.id), ['card', 'placeholder', 'add']);
});
