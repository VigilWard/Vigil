"""state.json 的去重、队列与持久化语义。"""
import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vigil.models import SEEN_RETENTION, Item, StateError
from vigil.state import STATE_VERSION, State, load_state


def make_item(uid="1", source_key="s", title="标题", fingerprint_source="x"):
    return Item(source_key=source_key, source_name="源", uid=uid, title=title,
                link="https://e.test/1", published=1000, summary=fingerprint_source)


class StateCase(unittest.TestCase):
    def setUp(self):
        handle = TemporaryDirectory()
        self.addCleanup(handle.cleanup)
        self.path = Path(handle.name) / "state.json"


class TestPersistence(StateCase):
    def test_roundtrip(self):
        state = State()
        now = int(time.time())
        state.health("k").initialized = True
        state.health("k").etag = '"abc"'
        state.seen["k:1"] = "fp"
        state.seen_at["k:1"] = now
        self.assertTrue(state.save(self.path))

        loaded = load_state(self.path)
        self.assertTrue(loaded.health("k").initialized)
        self.assertEqual(loaded.health("k").etag, '"abc"')
        self.assertEqual(loaded.seen["k:1"], "fp")
        self.assertEqual(loaded.seen_at["k:1"], now)

    def test_noop_save_does_not_touch_file(self):
        state = State()
        state.health("k").initialized = True
        state.save(self.path)
        before = self.path.read_text(encoding="utf-8")
        stamp = self.path.stat().st_mtime_ns

        self.assertFalse(state.save(self.path))
        self.assertEqual(before, self.path.read_text(encoding="utf-8"))
        self.assertEqual(stamp, self.path.stat().st_mtime_ns)

    def test_missing_file_starts_empty(self):
        self.assertEqual(load_state(self.path).seen, {})

    def test_atomic_write_leaves_no_temp(self):
        State().save(self.path)
        self.assertFalse((self.path.parent / "state.json.tmp").exists())

    def test_corrupt_json_raises_with_hint(self):
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(StateError):
            load_state(self.path)

    def test_old_version_rejected(self):
        self.path.write_text(json.dumps({"version": 99, "seen": {}}), encoding="utf-8")
        with self.assertRaises(StateError) as ctx:
            load_state(self.path)
        self.assertIn("--reset", str(ctx.exception))

    def test_pending_key_mismatch_rejected(self):
        self.path.write_text(json.dumps({
            "version": STATE_VERSION,
            "pending": {"other:key": {
                "item": make_item().to_dict(), "fingerprint": "x", "since": 1, "sent": []
            }},
        }), encoding="utf-8")
        with self.assertRaises(StateError):
            load_state(self.path)


class TestDedup(StateCase):
    def test_new_item_is_fresh(self):
        state = State()
        self.assertTrue(state.is_fresh(make_item()))

    def test_remembered_item_is_not_fresh(self):
        state = State()
        item = make_item()
        state.remember(item, 100)
        self.assertFalse(state.is_fresh(item))

    def test_changed_content_is_fresh_again(self):
        state = State()
        state.remember(make_item(title="旧标题"), 100)
        self.assertTrue(state.is_fresh(make_item(title="新标题")))

    def test_touch_is_coarse(self):
        state = State()
        item = make_item()
        state.remember(item, 1000)
        state.touch(item.key, 1000 + 60)
        self.assertEqual(state.seen_at[item.key], 1000)
        state.touch(item.key, 1000 + 86400)
        self.assertEqual(state.seen_at[item.key], 1000 + 86400)


class TestPending(StateCase):
    def test_queue_is_idempotent(self):
        state = State()
        item = make_item()
        self.assertTrue(state.queue(item, 100))
        self.assertFalse(state.queue(item, 200))
        self.assertEqual(len(state.pending), 1)

    def test_revision_replaces_pending(self):
        state = State()
        state.queue(make_item(title="旧"), 100)
        self.assertTrue(state.queue(make_item(title="新"), 200))
        self.assertEqual(len(state.pending), 1)

    def test_pending_for_target(self):
        state = State()
        item = make_item()
        state.queue(item, 100)
        self.assertEqual([i.key for i in state.pending_for("a")], [item.key])
        state.ack([item.key], "a", {"a", "b"}, 100)
        self.assertEqual(state.pending_for("a"), [])          # a 已确认
        self.assertEqual(len(state.pending_for("b")), 1)      # b 还没有
        self.assertEqual(state.seen, {})                      # 尚未全部完成

    def test_item_completed_only_after_all_targets(self):
        state = State()
        item = make_item()
        state.queue(item, 100)
        state.ack([item.key], "a", {"a", "b"}, 100)
        state.ack([item.key], "b", {"a", "b"}, 100)
        self.assertEqual(state.pending, {})
        self.assertEqual(state.seen[item.key], item.fingerprint)

    def test_ack_unknown_key_is_ignored(self):
        state = State()
        state.ack(["nope:1"], "a", {"a"}, 100)
        self.assertEqual(state.pending, {})

    def test_merged_keys_are_acked_together(self):
        state = State()
        winner = make_item(uid="w")
        loser = make_item(uid="l", source_key="other")
        state.queue(winner, 100)
        state.queue(loser, 100)
        state.ack([winner.key, loser.key], "a", {"a"}, 100)
        self.assertEqual(state.pending, {})
        self.assertIn(loser.key, state.seen)

    def test_expired_pending_is_dropped(self):
        state = State()
        item = make_item()
        state.queue(item, 0)
        dropped_seen, dropped_pending = state.prune(10_000_000)
        self.assertEqual(dropped_pending, 1)
        self.assertEqual(state.pending, {})

    def test_pending_is_capped(self):
        state = State()
        for index in range(310):
            state.queue(make_item(uid=str(index)), 1000 + index)
        state.prune(1000)
        self.assertLessEqual(len(state.pending), 300)
        # 留下的是最新的
        keys = {item.key for item in state.pending_for("a")}
        self.assertIn("s:309", keys)
        self.assertNotIn("s:0", keys)


class TestRetention(StateCase):
    def test_old_seen_entries_are_pruned(self):
        state = State()
        state.remember(make_item(uid="old"), 0)
        state.remember(make_item(uid="new"), 10_000_000)
        dropped_seen, _ = state.prune(10_000_000)
        self.assertEqual(dropped_seen, 1)
        self.assertNotIn("s:old", state.seen)
        self.assertIn("s:new", state.seen)

    def test_pending_items_are_not_pruned_as_seen(self):
        state = State()
        item = make_item()
        state.queue(item, SEEN_RETENTION)          # 队列里的条目还没过期
        state.seen[item.key] = item.fingerprint
        state.seen_at[item.key] = 0                # 但 seen 记录早该过期了
        state.prune(SEEN_RETENTION + 100)
        self.assertIn(item.key, state.seen)


if __name__ == "__main__":
    unittest.main()
