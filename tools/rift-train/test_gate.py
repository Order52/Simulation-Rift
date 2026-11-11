"""Tests for gate.py's forward test. Run: python3 test_gate.py (in tools/rift-train)."""
import json, os, subprocess, sys, tempfile, unittest

GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")


def row(source, high, n=1000, label="malicious"):
    return {"source": source, "label": label, "view": "address", "high_rate": high, "n": n}


def report(forward=None, phishdb=0.6, champion=None):
    test = [row("phishdb", phishdb), row("commoncrawl", 0.0005, label="benign")]
    if forward is not None:
        test.append(forward)
    out = {
        "test": test,
        "auc_trained_sources_address_view": 0.98,
        "scoring_microseconds_on_this_machine": {"p50": 2.0},
        "model": {"sha256": "x", "bytes": 1},
    }
    if champion is not None:
        out["champion"] = champion
    return out


def run(old, new):
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for name, data in (("old", old), ("new", new)):
            path = os.path.join(d, name + ".json")
            with open(path, "w") as f:
                json.dump(data, f)
            paths.append(path)
        done = subprocess.run([sys.executable, "-I", GATE, *paths], capture_output=True, text=True)
        return done.returncode, done.stdout


class ForwardTest(unittest.TestCase):
    def test_refuses_a_model_that_misses_more_new_links(self):
        champion = report(row("forward", 0.50))
        code, out = run(report(), report(row("forward", 0.45), champion=champion))
        self.assertEqual(code, 1, out)
        self.assertIn("forward test", out)

    def test_passes_within_the_margin(self):
        champion = report(row("forward", 0.50))
        code, out = run(report(), report(row("forward", 0.495), champion=champion))
        self.assertEqual(code, 0, out)
        self.assertIn("forward test: 49.50%", out)

    def test_passes_when_better(self):
        champion = report(row("forward", 0.50))
        code, out = run(report(), report(row("forward", 0.60), champion=champion))
        self.assertEqual(code, 0, out)

    def test_too_few_links_are_not_judged(self):
        champion = report(row("forward", 0.50, n=100))
        code, out = run(report(), report(row("forward", 0.10, n=100), champion=champion))
        self.assertEqual(code, 0, out)
        self.assertIn("not judged", out)

    def test_no_forward_set_changes_nothing(self):
        code, out = run(report(), report(champion=report()))
        self.assertEqual(code, 0, out)
        self.assertNotIn("forward test", out)

    def test_forward_size_is_not_a_shrunken_feed(self):
        old = report(row("forward", 0.5, n=4000))
        champion = report(row("forward", 0.5, n=1000))
        code, out = run(old, report(row("forward", 0.5, n=1000), champion=champion))
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
