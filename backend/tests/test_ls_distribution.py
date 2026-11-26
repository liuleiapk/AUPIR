from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "backend"


def run_json(args: list[str]) -> dict:
    proc = subprocess.run([str(BIN), *args], text=True, capture_output=True, check=True)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")][-1]


class LSDistributionTests(unittest.TestCase):
    def test_unbiased_start_domain_separation_and_zero_band(self):
        row = run_json(["ls_distribution_audit", "1127", "8", "100000", "12345"])
        self.assertEqual(row["start_domain"], 1120)
        self.assertEqual(row["start_sampling"], "UINT64_REJECTION_UNBIASED")
        self.assertNotEqual(row["start_domain_tag"], row["bits_domain_tag"])
        self.assertGreater(row["all_zero_bands"], 0)
        self.assertLess(abs(row["ones_fraction"] - 0.5), 0.01)

    def test_exact_gf2_rank_runner(self):
        row = run_json(["ls_rank_trials", "32", "48", "100", "16", "67890", "2"])
        self.assertEqual(row["Q"], 32)
        self.assertEqual(row["C"], 48)
        self.assertEqual(row["matrix_distribution"], "SHA256_PRF_COLUMN_BAND_GF2_v2")

    def test_server_emits_c_by_block_and_client_recovers(self):
        with tempfile.TemporaryDirectory(prefix="ls-direction-test-") as raw:
            prefix = Path(raw) / "case"
            prep = [str(BIN), "prepare", "64", "128", "8", "1,2", str(prefix),
                    "1", "7", "991", "genschedule", "123", "2", "8", "456", "10"]
            subprocess.run(prep, check=True, text=True, capture_output=True)
            responses = []
            for server in range(2):
                response = Path(raw) / f"response{server}"
                responses.append(response)
                subprocess.run([str(BIN), "server", "indirected",
                                f"{prefix}.s{server}.keys", str(response), "128", "1", "7",
                                "legacy_reference"],
                               check=True, text=True, capture_output=True)
                self.assertEqual(response.stat().st_size, 10 * 128)
            recovered = run_json(["recover", f"{prefix}.meta", str(responses[0]),
                                  str(responses[1]), "128", "7"])
            self.assertEqual(recovered["response_bytes_read"], 2 * 10 * 128)
            for mode, threads, kernel in [
                    ("paper_faithful_scalar", "1", "scalar"),
                    ("paper_faithful_optimized", "4", "avx2")]:
                recovered = run_json(["recover", f"{prefix}.meta", str(responses[0]),
                                      str(responses[1]), "128", "7", "-", mode,
                                      threads, kernel])
                self.assertEqual(recovered["response_bytes_read"], 2 * 10 * 128)
                self.assertEqual(recovered["implementation_mode"], mode)

    def test_algorithm4_operation_count_and_differential(self):
        metrics = run_json(["ls_plan_metrics", "1024", "1536", "1127", "128", "499999"])
        self.assertTrue(metrics["paper_full_rank"])
        self.assertLess(metrics["total_row_xor_count"], metrics["legacy_total_row_xor_count"])
        rows = subprocess.run([
            str(BIN), "ls_client_compare", "32", "48", "40", "16", "8192", "8192",
            "499999", "4", "avx2", "random"], text=True, capture_output=True, check=True)
        parsed = [json.loads(line) for line in rows.stdout.splitlines() if line.startswith("{")]
        self.assertEqual(len(parsed), 3)
        self.assertTrue(all(row["content_equality"] for row in parsed))
        self.assertTrue(all(row["matches_legacy"] for row in parsed))


if __name__ == "__main__":
    unittest.main()
