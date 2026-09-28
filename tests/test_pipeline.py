import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nvregdecomp.csv_loader import load_csv, parse_text  # noqa: E402
from nvregdecomp.explain import analyses_from_ghidra, analyze_code, confidence, summarize  # noqa: E402
from nvregdecomp.ghidra_runner import GhidraRunner, find_analyze_headless  # noqa: E402
from nvregdecomp.prescan import prescan  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SAMPLE_CODE = textwrap.dedent("""\
    void FUN_1400a0000(longlong param_1)
    {
      int iVar1;
      uint local_28;

      local_28 = 0;
      iVar1 = FUN_140123456(param_1,L"AllowMaxPerf",4,&local_28);
      if (iVar1 == 0) {
        if (local_28 == 1) {
          DAT_140fff000 = local_28;
        }
        if ((local_28 & 0x4) != 0) {
          FUN_140222222();
        }
      }
      return;
    }""")


class CsvTest(unittest.TestCase):
    def test_bundled_csv(self):
        values = load_csv(os.path.join(ROOT, "nvidia.csv"))
        self.assertGreater(len(values), 1300)
        by = {v.name: v for v in values}
        self.assertEqual(by["AdapterType"].total, 3)
        self.assertEqual(by["VulkanImplicitLayers"].reads, 18)

    def test_plain_list(self):
        vals = parse_text("Foo\nBar\n")
        self.assertEqual([v.name for v in vals], ["Bar", "Foo"])


class PrescanTest(unittest.TestCase):
    def test_utf16_ascii_and_partial(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "nvlddmkm.sys")
            b = os.path.join(d, "other.dll")
            with open(a, "wb") as fh:
                fh.write(b"\x00" * 16 + "AllowMaxPerf".encode("utf-16-le") + b"\x00\x00" * 3
                         + b"junk\x00RMHdcpKeyglobZero=%d\x00" + b"\xff" * 8)
            with open(b, "wb") as fh:
                fh.write(b"\x00allowmaxperf\x00EnableThing\x00")
            res = prescan([a, b], ["AllowMaxPerf", "RMHdcpKeyglobZero", "EnableThing", "Missing"])
            self.assertEqual(res.hits["allowmaxperf"][0].encoding, "utf16")
            self.assertEqual(res.hits["allowmaxperf"][0].offset, 16)
            # stop_at_first_file: in b nicht erneut gesucht
            self.assertEqual(len(res.hits["allowmaxperf"]), 1)
            self.assertFalse(res.hits["rmhdcpkeyglobzero"][0].exact)
            self.assertIn("enablething", res.hits)
            self.assertNotIn("missing", res.hits)


class ExplainTest(unittest.TestCase):
    def test_analyze_code(self):
        info = analyze_code(SAMPLE_CODE, [6], "AllowMaxPerf")
        self.assertEqual(info["reader"], "FUN_140123456")
        self.assertEqual(info["out_var"], "local_28")
        self.assertIn("local_28 == 1", info["comparisons"])
        self.assertTrue(any("0x4" in m for m in info["masks"]))
        self.assertTrue(any(s.startswith("DAT_140fff000") for s in info["stores"]))
        self.assertIn("4", info["constants"])


def _fake_ghidra(dirname):
    """Simuliert analyzeHeadless: schreibt das JSON, das RegValueFinder liefern würde."""
    support = os.path.join(dirname, "support")
    os.makedirs(support)
    path = os.path.join(support, "analyzeHeadless")
    code = json.dumps(SAMPLE_CODE)
    with open(path, "w") as fh:
        fh.write(f"""#!{sys.executable}
import json, sys
a = sys.argv
i = a.index("-postScript")
names = open(a[i + 2], encoding="utf-8").read().split()
out = {{"program": "nvlddmkm.sys", "values": [], "notFound": [],
       "functions": {{"1400a0000": {{"name": "FUN_1400a0000", "entry": "1400a0000", "code": {code}}}}}}}
for n in names:
    out["values"].append({{"name": n, "strings": [], "refs": [
        {{"string": "140500000", "from": "1400a0010", "kind": "xref:DATA",
          "function": "FUN_1400a0000", "entry": "1400a0000", "lines": [6]}},
        {{"string": "140500000", "from": "140600000", "kind": "xref:DATA",
          "data": {{"bytesAfter": "01 00", "bytesBefore": "", "tableBase": "", "tableFunctions": []}}}}]}})
json.dump(out, open(a[i + 3], "w", encoding="utf-8"))
print("fake ghidra ok")
""")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return dirname


@unittest.skipIf(sys.platform == "win32", "Fake-Skript nutzt Shebang")
class RunnerTest(unittest.TestCase):
    def test_runner_with_fake_ghidra(self):
        with tempfile.TemporaryDirectory() as d:
            g = _fake_ghidra(os.path.join(d, "ghidra"))
            self.assertTrue(find_analyze_headless(g))
            binary = os.path.join(d, "nvlddmkm.sys")
            open(binary, "wb").write(b"x")
            logs = []
            r = GhidraRunner(g, os.path.join(d, "work"), log=logs.append)
            res = r.analyze(binary, ["AllowMaxPerf"])
            self.assertTrue(r.is_imported(binary))
            an = analyses_from_ghidra(res)["allowmaxperf"]
            self.assertEqual(len(an), 2)
            self.assertEqual(confidence(an), "hoch")
            s = summarize("AllowMaxPerf", an)
            self.assertIn("local_28 == 1", s)
            # zweiter Lauf nutzt -process
            r.analyze(binary, ["AllowMaxPerf"])
            self.assertTrue(any("-process" in l for l in logs))


if __name__ == "__main__":
    unittest.main()
