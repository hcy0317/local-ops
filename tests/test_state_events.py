import threading
import time
import unittest

from localops.state_events import StateBroadcaster


class CountingBuilder:
    def __init__(self):
        self.calls = 0
        self.value = 0
        self.guard = threading.Lock()

    def __call__(self):
        with self.guard:
            self.calls += 1
            return {"value": self.value}

    def set(self, value):
        with self.guard:
            self.value = value


def wait_for_version(broadcaster, subscription, version, timeout=2.0):
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        item = broadcaster.wait(subscription, timeout=min(0.05, timeout))
        if item is None:
            continue
        latest = item
        if item[0] >= version:
            return item
    return latest


class StateBroadcasterTests(unittest.TestCase):
    def setUp(self):
        self.broadcaster = StateBroadcaster(
            visible_interval=0.05,
            hidden_interval=0.3,
            hidden_max_interval=0.6,
        )
        self.addCleanup(self.broadcaster.close)

    def test_no_subscribers_means_no_snapshot_builds(self):
        builder = CountingBuilder()
        self.broadcaster.bind(builder)

        time.sleep(0.25)

        self.assertEqual(builder.calls, 0)
        self.assertEqual(self.broadcaster.version(), 0)

    def test_subscribe_builds_immediately_and_notify_publishes_changes(self):
        builder = CountingBuilder()
        self.broadcaster.bind(builder)

        subscription = self.broadcaster.subscribe(visible=True)
        version, state = wait_for_version(self.broadcaster, subscription, 1)
        self.assertEqual(version, 1)
        self.assertEqual(state, {"value": 0})

        builder.set(1)
        self.broadcaster.notify()
        version, state = wait_for_version(self.broadcaster, subscription, 2)
        self.assertGreaterEqual(version, 2)
        self.assertEqual(state, {"value": 1})
        subscription.close()

    def test_periodic_identical_snapshot_does_not_advance_version(self):
        builder = CountingBuilder()
        self.broadcaster.bind(builder)
        subscription = self.broadcaster.subscribe(visible=True)
        wait_for_version(self.broadcaster, subscription, 1)

        time.sleep(0.3)

        self.assertEqual(self.broadcaster.version(), 1)
        self.assertGreaterEqual(builder.calls, 2)
        subscription.close()

    def test_explicit_notify_publishes_identical_snapshot_for_reconciliation(self):
        builder = CountingBuilder()
        self.broadcaster.bind(builder)
        subscription = self.broadcaster.subscribe(visible=True)
        wait_for_version(self.broadcaster, subscription, 1)

        self.broadcaster.notify()
        version, state = wait_for_version(self.broadcaster, subscription, 2)

        self.assertEqual(version, 2)
        self.assertEqual(state, {"value": 0})
        subscription.close()

    def test_new_subscriber_receives_cached_snapshot_before_slow_rebuild(self):
        calls = 0

        def builder():
            nonlocal calls
            calls += 1
            if calls > 1:
                time.sleep(0.35)
                return {"value": 1}
            return {"value": 0}

        broadcaster = StateBroadcaster(
            visible_interval=10.0,
            hidden_interval=10.0,
            hidden_max_interval=10.0,
        )
        self.addCleanup(broadcaster.close)
        broadcaster.bind(builder)
        first = broadcaster.subscribe(visible=True)
        wait_for_version(broadcaster, first, 1)

        broadcaster.notify()
        second = broadcaster.subscribe(visible=True)
        started = time.monotonic()
        item = broadcaster.wait(second, timeout=0.1)

        self.assertIsNotNone(item)
        self.assertEqual(item[1], {"value": 0})
        self.assertLess(time.monotonic() - started, 0.1)
        first.close()
        second.close()

    def test_fingerprint_alone_can_trigger_a_new_version(self):
        builder = CountingBuilder()
        signal = {"value": "watching"}
        self.broadcaster.bind(builder, lambda: signal["value"])
        subscription = self.broadcaster.subscribe(visible=True)
        wait_for_version(self.broadcaster, subscription, 1)

        signal["value"] = "backoff"
        self.broadcaster.notify()
        version, state = wait_for_version(self.broadcaster, subscription, 2)

        self.assertEqual(version, 2)
        self.assertEqual(state, {"value": 0})
        subscription.close()

    def test_visible_subscribers_are_refreshed_faster_than_background(self):
        builder = CountingBuilder()
        self.broadcaster.bind(builder)
        subscription = self.broadcaster.subscribe(visible=True)
        wait_for_version(self.broadcaster, subscription, 1)

        def count_versions(duration):
            start = time.monotonic()
            seen = self.broadcaster.version()
            while time.monotonic() - start < duration:
                builder.set(builder.calls + 1)
                time.sleep(0.01)
            return self.broadcaster.version() - seen

        visible = count_versions(0.6)
        subscription.set_visible(False)
        time.sleep(0.2)
        hidden = count_versions(0.6)

        self.assertGreaterEqual(visible, 5)
        self.assertLessEqual(hidden, 3)
        subscription.close()

    def test_closed_subscription_stops_receiving(self):
        builder = CountingBuilder()
        self.broadcaster.bind(builder)
        subscription = self.broadcaster.subscribe(visible=True)
        wait_for_version(self.broadcaster, subscription, 1)

        subscription.close()
        self.assertTrue(subscription.closed)
        self.assertIsNone(self.broadcaster.wait(subscription, timeout=0.05))

        subscription.set_visible(True)
        self.assertTrue(subscription.closed)

    def test_build_failure_does_not_kill_the_background_thread(self):
        state = {"value": 0}
        calls = []

        def builder():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return dict(state)

        self.broadcaster.bind(builder)
        subscription = self.broadcaster.subscribe(visible=True)

        state["value"] = 5
        # 首次构建失败后线程必须继续工作：后续巡检仍能发布有效快照。
        version, snapshot = wait_for_version(self.broadcaster, subscription, 1)
        self.assertEqual(version, 1)
        self.assertEqual(snapshot, {"value": 5})
        self.assertGreaterEqual(len(calls), 2)
        subscription.close()


if __name__ == "__main__":
    unittest.main()
