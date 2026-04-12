import tempfile
import unittest
from pathlib import Path

from core.event_chain import append_event, export_events, import_events


class TestEventChainImport(unittest.TestCase):
    def test_export_import_roundtrip(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            p1 = Path(d1)
            p2 = Path(d2)
            log1 = p1 / "event_chain.jsonl"
            state1 = p1 / "event_chain_state.json"
            # create 3 events
            for i in range(3):
                append_event(log_path=log1, state_path=state1, etype="T", payload={"i": i})

            bundle = export_events(log_dir=p1, from_seq=1, limit=10)
            self.assertTrue(bundle.get("ok"))
            events = bundle.get("events")
            self.assertEqual(len(events), 3)

            # Import into empty chain should fail because prev_hash mismatch (local last is "", first prev is "")
            # Here it should succeed because first prev is empty.
            res = import_events(log_dir=p2, events=events)
            self.assertTrue(res.get("ok"), res)
            self.assertEqual(res.get("imported"), 3)


if __name__ == "__main__":
    unittest.main()
