"""状态变更广播：让控制台页面按事件刷新，而不是按固定频率轮询。

服务端只在快照真的变化时广播；没有页面订阅时不建快照，也不额外起负载。
页面重新可见时重新订阅，会立刻拿到一份重新计算的快照。
"""

from __future__ import annotations

import json
import threading
import time

# 有可见页面时保持前端原有的“接近实时”手感。
VISIBLE_INTERVAL_SEC = 2.5
# 页面全部在后台时降频；连续没有变化再逐步退避，避免空转开销。
HIDDEN_INTERVAL_SEC = 30.0
HIDDEN_MAX_INTERVAL_SEC = 300.0
# 单条长连接的最长存活时间，到点由浏览器自动重连并重新校验会话。
STREAM_MAX_SEC = 240.0
# 没有状态变化时的心跳间隔，避免代理提前断开长连接。
HEARTBEAT_SEC = 10.0


class Subscription:
    """一个订阅者句柄；只通过本对象改状态，避免直接操作广播器内部结构。"""

    __slots__ = ("_broadcaster", "visible", "seen", "closed")

    def __init__(self, broadcaster, visible):
        self._broadcaster = broadcaster
        self.visible = bool(visible)
        self.seen = 0
        self.closed = False

    def set_visible(self, visible):
        self._broadcaster.set_visible(self, visible)

    def close(self):
        self._broadcaster.unsubscribe(self)


class StateBroadcaster:
    """合并构建、按变更广播状态快照。

    ``build`` 返回完整状态字典；同一份快照会发给所有订阅者，订阅者按自己的
    会话权限再做投影。没有订阅者时线程只等通知，不产生任何快照开销。
    """

    def __init__(
            self, build=None, *,
            visible_interval=VISIBLE_INTERVAL_SEC,
            hidden_interval=HIDDEN_INTERVAL_SEC,
            hidden_max_interval=HIDDEN_MAX_INTERVAL_SEC,
            logger=None):
        self._cond = threading.Condition(threading.Lock())
        self._build = build
        self._fingerprint = None
        self._visible_interval = float(visible_interval)
        self._hidden_interval = float(hidden_interval)
        self._hidden_max_interval = float(hidden_max_interval)
        self._logger = logger
        self._subscribers = []
        self._state = None
        self._serialized = None
        self._version = 0
        self._dirty = 0
        self._handled = 0
        self._unchanged = 0
        self._force_publish = False
        self._stop = False
        self._thread = None

    # ---------------------------------------------------------- 生命周期
    def bind(self, build, fingerprint=None):
        """绑定快照构建函数；每个进程只服务一个控制台实例。

        ``fingerprint`` 提供共享快照之外的附加变更信号（例如按会话投影、
        不在快照里的保活状态），返回 ``None`` 表示没有额外信号。
        """
        with self._cond:
            self._build = build
            self._fingerprint = fingerprint
            self._state = None
            self._serialized = None
            self._version = 0
            self._handled = 0
            self._unchanged = 0
            self._force_publish = True
            for subscription in self._subscribers:
                subscription.seen = 0
            self._dirty += 1
            self._ensure_thread_locked()
            self._cond.notify_all()

    def close(self):
        """停止后台线程；只用于进程退出与测试夹具。"""
        with self._cond:
            self._stop = True
            self._cond.notify_all()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def subscribe(self, visible=True):
        subscription = Subscription(self, visible)
        with self._cond:
            self._subscribers.append(subscription)
            # 已有快照先零延迟交付，随后后台重算校准。首次订阅没有缓存时
            # 才等待重建，避免切回页面被慢查询卡住。
            self._dirty += 1
            self._ensure_thread_locked()
            self._cond.notify_all()
        return subscription

    def unsubscribe(self, subscription):
        with self._cond:
            subscription.closed = True
            if subscription in self._subscribers:
                self._subscribers.remove(subscription)
            self._cond.notify_all()

    def set_visible(self, subscription, visible):
        visible = bool(visible)
        with self._cond:
            if subscription.closed or subscription.visible == visible:
                return
            subscription.visible = visible
            if visible:
                # 回到前台立刻巡检一次，并恢复高频节奏。
                self._unchanged = 0
                self._dirty += 1
            self._cond.notify_all()

    def notify(self):
        """状态可能已变化（写操作、配置或进程变化）；尽快重算并广播。"""
        with self._cond:
            self._dirty += 1
            # 写操作后必须至少下发一帧，即使瞬态重建仍与上一帧相同。
            # 前端本地乐观状态需要一次权威快照来结束 pending。
            self._force_publish = True
            self._cond.notify_all()

    # ---------------------------------------------------------- 订阅者接口
    def wait(self, subscription, timeout=HEARTBEAT_SEC):
        """等待比 ``subscription.seen`` 更新的快照；超时返回 ``None``。"""
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._cond:
            while True:
                if subscription.closed or self._stop:
                    return None
                if self._state is not None and self._version > subscription.seen:
                    subscription.seen = self._version
                    return self._version, self._state
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def version(self):
        with self._cond:
            return self._version

    # ---------------------------------------------------------- 内部实现
    def _ensure_thread_locked(self):
        if self._stop or self._build is None:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run, name="state-broadcaster", daemon=True)
        self._thread.start()

    def _interval_locked(self):
        if any(item.visible for item in self._subscribers):
            return self._visible_interval
        backoff = self._hidden_interval * (2 ** min(self._unchanged, 8))
        return min(backoff, self._hidden_max_interval)

    def _run(self):
        while True:
            with self._cond:
                while not self._stop and not self._subscribers:
                    self._cond.wait()
                if self._stop:
                    return
                if self._dirty == self._handled:
                    self._cond.wait(self._interval_locked())
                    if self._stop:
                        return
                    if self._dirty != self._handled:
                        # 被写操作唤醒：立刻重算，不等待巡检周期。
                        continue
                marker = self._dirty
            state = self._build_state()
            serialized = self._state_key(state)
            with self._cond:
                self._handled = marker
                if serialized is None:
                    self._unchanged += 1
                    continue
                force_publish = self._force_publish
                if serialized == self._serialized and not force_publish:
                    self._unchanged += 1
                    continue
                self._serialized = serialized
                self._state = state
                self._force_publish = False
                self._unchanged = 0
                self._version += 1
                self._cond.notify_all()

    def _build_state(self):
        build = self._build
        if build is None:
            return None
        try:
            return build()
        except Exception:  # noqa: BLE001 - 后台线程不能因单次构建失败退出
            if self._logger is not None:
                self._logger.exception("状态广播构建快照失败")
            return None

    def _state_key(self, state):
        serialized = serialize_state(state)
        if serialized is None or self._fingerprint is None:
            return serialized
        try:
            extra = self._fingerprint()
        except Exception:  # noqa: BLE001 - 附加信号失败不应拖垮广播
            if self._logger is not None:
                self._logger.exception("状态广播附加指纹失败")
            return serialized
        if extra is None:
            return serialized
        return serialized + "\n" + str(extra)


def serialize_state(state):
    if state is None:
        return None
    try:
        return json.dumps(state, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return None
