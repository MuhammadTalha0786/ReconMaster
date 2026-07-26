"""
tests/test_reconmaster.py
===========================
Unit tests for ReconMaster's non-network logic: multi-selection
parsing, timeout validation, firewall technique metadata and
combination validation, target/port/filename validation, job
orchestration (with subprocess mocked out — no live network or Nmap
required), and report generation/output-path handling.

Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import firewall
import utils
from job import ScanJob, ScanTask, TaskStatus, order_tasks, run_job, skip_redundant_tasks
from report import build_job_report_data, build_report_data, generate_job_reports, generate_report
from scanner import ScanResult
from settings import Settings, resolve_timeout


class TestMultiSelectionParsing(unittest.TestCase):
    def test_basic_comma_separated(self):
        result = utils.parse_multi_selection("1,2,3", range(1, 9))
        self.assertEqual(result.selected, [1, 2, 3])
        self.assertEqual(result.invalid, [])
        self.assertEqual(result.duplicates, [])

    def test_space_separated(self):
        result = utils.parse_multi_selection("1 2 3", range(1, 9))
        self.assertEqual(result.selected, [1, 2, 3])

    def test_duplicates_and_invalid(self):
        result = utils.parse_multi_selection("1,2,2,99,4", range(1, 9))
        self.assertEqual(result.selected, [1, 2, 4])
        self.assertEqual(result.invalid, ["99"])
        self.assertEqual(result.duplicates, [2])

    def test_empty_input(self):
        result = utils.parse_multi_selection("", range(1, 9))
        self.assertEqual(result.selected, [])

    def test_non_numeric(self):
        result = utils.parse_multi_selection("abc,def", range(1, 9))
        self.assertEqual(result.selected, [])
        self.assertEqual(result.invalid, ["abc", "def"])


class TestTimeoutValidation(unittest.TestCase):
    def test_valid_timeout(self):
        self.assertEqual(utils.validate_timeout_value("1200"), 1200)

    def test_rejects_negative(self):
        self.assertIsNone(utils.validate_timeout_value("-1"))

    def test_rejects_non_numeric(self):
        self.assertIsNone(utils.validate_timeout_value("abc"))

    def test_rejects_empty(self):
        self.assertIsNone(utils.validate_timeout_value(""))

    def test_rejects_zero(self):
        self.assertIsNone(utils.validate_timeout_value("0"))

    def test_resolve_timeout_modes(self):
        default_settings = Settings(timeout_mode="default")
        self.assertEqual(resolve_timeout("host_discovery", default_settings), 60)
        self.assertIsNone(resolve_timeout("custom_command", default_settings))

        custom_settings = Settings(timeout_mode="custom", custom_timeout_seconds=500)
        self.assertEqual(resolve_timeout("host_discovery", custom_settings), 500)
        self.assertEqual(resolve_timeout("aggressive_scan", custom_settings), 500)

        unlimited_settings = Settings(timeout_mode="unlimited")
        self.assertIsNone(resolve_timeout("host_discovery", unlimited_settings))
        self.assertIsNone(resolve_timeout("aggressive_scan", unlimited_settings))


class TestTargetAndPortValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(utils.validate_target("192.168.1.10"))

    def test_valid_ipv6(self):
        self.assertTrue(utils.validate_target("2001:db8::1"))

    def test_valid_hostname(self):
        self.assertTrue(utils.validate_target("scanme.nmap.org"))

    def test_valid_cidr(self):
        self.assertTrue(utils.validate_target("192.168.1.0/24"))

    def test_rejects_empty(self):
        self.assertFalse(utils.validate_target(""))

    def test_rejects_malformed(self):
        self.assertFalse(utils.validate_target("999.999.999.999.abc!!"))

    def test_port_spec_valid(self):
        self.assertTrue(utils.validate_port_spec("22,80,443"))
        self.assertTrue(utils.validate_port_spec("1-1000"))
        self.assertTrue(utils.validate_port_spec("22,1-999,443"))

    def test_port_spec_invalid(self):
        self.assertFalse(utils.validate_port_spec(""))
        self.assertFalse(utils.validate_port_spec("99999"))
        self.assertFalse(utils.validate_port_spec("abc"))
        self.assertFalse(utils.validate_port_spec("22; rm -rf /"))

    def test_filename_sanitization_blocks_traversal(self):
        self.assertEqual(utils.sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(utils.sanitize_filename("normal_name"), "normal_name")


class TestFirewallMetadata(unittest.TestCase):
    def test_technique_count(self):
        self.assertEqual(len(firewall.FIREWALL_TECHNIQUES), 29)

    def test_describe_techniques_matches_metadata(self):
        techniques = firewall.describe_techniques()
        self.assertEqual(len(techniques), 29)
        self.assertEqual({t.key for t in techniques}, set(firewall.FIREWALL_TECHNIQUES.keys()))

    def test_build_args_known_technique(self):
        self.assertEqual(firewall.build_firewall_args("ack"), ["-sA"])
        self.assertEqual(firewall.build_firewall_args("fragment"), ["-f"])

    def test_build_args_unknown_technique_raises(self):
        with self.assertRaises(ValueError):
            firewall.build_firewall_args("not_a_real_technique")


class TestFirewallCombinationValidation(unittest.TestCase):
    def test_incompatible_scan_types_split(self):
        plan = firewall.validate_firewall_combination(["fin", "ack", "null", "xmas"])
        # 4 mutually exclusive scan types -> 4 separate groups
        self.assertEqual(len(plan.groups), 4)
        self.assertTrue(plan.notes)

    def test_compatible_modifier_combines_with_scan_type(self):
        plan = firewall.validate_firewall_combination(["ack", "fragment", "custom_ttl"])
        self.assertEqual(len(plan.groups), 1)
        self.assertIn("ack", plan.groups[0])
        self.assertIn("fragment", plan.groups[0])

    def test_skip_ping_conflicts_with_ping_methods(self):
        plan = firewall.validate_firewall_combination(["skip_ping", "syn_ping"])
        self.assertEqual(len(plan.groups), 2)
        self.assertTrue(any("No Ping" in n for n in plan.notes))

    def test_unknown_keys_ignored(self):
        plan = firewall.validate_firewall_combination(["ack", "not_real"])
        self.assertEqual(plan.groups, [["ack"]])


class TestJobOrchestration(unittest.TestCase):
    def test_task_ordering(self):
        ordered = order_tasks(["aggressive_scan", "host_discovery", "nse_scan"])
        self.assertEqual(ordered, ["host_discovery", "nse_scan", "aggressive_scan"])

    def test_redundant_task_skipping(self):
        tasks = [
            ScanTask("service_detection", "Service/Version Detection", ["-sV"]),
            ScanTask("aggressive_scan", "Aggressive Scan", ["-A"]),
        ]
        notes = []
        skip_redundant_tasks(tasks, notes)
        self.assertEqual(tasks[0].status, TaskStatus.SKIPPED)
        self.assertTrue(notes)

    def test_run_job_continues_after_task_failure(self):
        """A failing/timeout task must not abort the rest of the job."""
        tasks = [
            ScanTask("host_discovery", "Host Discovery", ["-sn"], timeout=60),
            ScanTask("port_scan", "Port Scan", ["-F"], timeout=180),
        ]
        job = ScanJob(target="10.0.0.1", tasks=tasks)

        call_count = {"n": 0}

        def flaky(target, args, timeout=None):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("simulated failure")
            return ScanResult(target=target, command=["nmap"] + args + [target],
                               raw_output="ok", success=True, duration_seconds=0.1)

        with patch("job.run_nmap_with_xml", side_effect=flaky):
            run_job(job)

        self.assertEqual(tasks[0].status, TaskStatus.FAILED)
        self.assertEqual(tasks[1].status, TaskStatus.COMPLETED)

    def test_run_job_records_completed_task(self):
        tasks = [ScanTask("host_discovery", "Host Discovery", ["-sn"], timeout=60)]
        job = ScanJob(target="10.0.0.1", tasks=tasks)
        fake_result = ScanResult(target="10.0.0.1", command=["nmap", "-sn", "10.0.0.1"],
                                  raw_output="Host is up.", success=True, duration_seconds=0.2)
        with patch("job.run_nmap_with_xml", return_value=fake_result):
            run_job(job)
        self.assertEqual(tasks[0].status, TaskStatus.COMPLETED)
        self.assertEqual(tasks[0].stdout, "Host is up.")


class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="reconmaster_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _sample_result(self, raw_output="PORT STATE\n80/tcp open"):
        return ScanResult(target="test.local", command=["nmap", "-sV", "test.local"],
                           raw_output=raw_output, success=True, duration_seconds=1.5)

    def test_all_single_scan_formats_generate_nonempty_files(self):
        data = build_report_data(self._sample_result())
        for fmt in ("txt", "json", "xml", "html", "pdf"):
            path = generate_report(data, fmt, f"test_{fmt}", self.tmp_dir)
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 0)

    def test_pdf_handles_special_characters_without_crashing(self):
        """Regression test for the PDF-crash-on-'<'/'&' bug found in review."""
        data = build_report_data(self._sample_result(
            "Banner: <html>&amp;test</html> value < 5 & value > 2"
        ))
        path = generate_report(data, "pdf", "special_chars", self.tmp_dir)
        self.assertTrue(path.exists())
        self.assertGreater(path.stat().st_size, 0)

    def test_html_escapes_special_characters(self):
        data = build_report_data(self._sample_result("<script>alert(1)</script>"))
        path = generate_report(data, "html", "xss_check", self.tmp_dir)
        content = path.read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertIn("&lt;script&gt;", content)

    def test_filename_traversal_is_blocked(self):
        data = build_report_data(self._sample_result())
        path = generate_report(data, "txt", "../../../evil", self.tmp_dir)
        self.assertTrue(str(path.resolve()).startswith(str(self.tmp_dir.resolve())))

    def test_output_directory_autocreated(self):
        nested = self.tmp_dir / "does" / "not" / "exist"
        data = build_report_data(self._sample_result())
        path = generate_report(data, "txt", "auto_dir", nested)
        self.assertTrue(path.exists())

    def test_aggregated_job_report_all_formats(self):
        tasks = [ScanTask("host_discovery", "Host Discovery", ["-sn"], timeout=60,
                           status=TaskStatus.COMPLETED, command="nmap -sn test.local",
                           stdout="Host is up.", duration_seconds=0.5)]
        job = ScanJob(target="test.local", tasks=tasks)
        job.started_at = "2026-07-26 10:00:00"
        job.ended_at = "2026-07-26 10:00:01"
        data = build_job_report_data(job, notes=["example note"])
        paths = generate_job_reports(data, ["txt", "json", "xml", "html", "pdf"],
                                      "job_report_test", self.tmp_dir)
        for path in paths:
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 0)


class TestBannerGrabAsJobTask(unittest.TestCase):
    """Regression tests: banner grabbing must be a proper ScanTask within
    a multi-task job (not a separate post-job step), with full status
    tracking and inclusion in the aggregated report."""

    def _fake_banner_results(self):
        from banner import BannerResult
        return [
            BannerResult(host="10.0.0.5", port=22, banner="SSH-2.0-OpenSSH_9.0", reachable=True),
            BannerResult(host="10.0.0.5", port=80, banner="Server: nginx", reachable=True),
            BannerResult(host="10.0.0.5", port=443, banner=None, reachable=False),
        ]

    def test_banner_grab_task_reaches_completed_status(self):
        task = ScanTask("banner_grab", "Banner Grabbing", [], timeout=60, task_type="banner_grab")
        job = ScanJob(target="10.0.0.5", tasks=[task])
        with patch("job.banner_mod.grab_banners", return_value=self._fake_banner_results()):
            run_job(job)
        self.assertEqual(task.status, TaskStatus.COMPLETED)

    def test_banner_grab_task_populates_structured_banners(self):
        task = ScanTask("banner_grab", "Banner Grabbing", [], timeout=60, task_type="banner_grab")
        job = ScanJob(target="10.0.0.5", tasks=[task])
        with patch("job.banner_mod.grab_banners", return_value=self._fake_banner_results()):
            run_job(job)
        self.assertEqual(len(task.banners), 3)
        self.assertEqual(task.banners[0]["port"], 22)
        self.assertTrue(task.banners[0]["reachable"])
        self.assertIn("SSH-2.0-OpenSSH", task.banners[0]["banner"])
        self.assertFalse(task.banners[2]["reachable"])

    def test_banner_grab_task_runs_alongside_nmap_tasks_in_order(self):
        """Confirms banner_grab occupies its correct slot (position 3, per
        TASK_ORDER) among a mixed set of nmap and banner tasks, and both
        task types actually execute."""
        tasks = [
            ScanTask("host_discovery", "Host Discovery", ["-sn"], timeout=60),
            ScanTask("port_scan", "Port Scan", ["-F"], timeout=180),
            ScanTask("banner_grab", "Banner Grabbing", [], timeout=60, task_type="banner_grab"),
        ]
        job = ScanJob(target="10.0.0.5", tasks=tasks)
        fake_nmap_result = ScanResult(target="10.0.0.5", command=["nmap"], raw_output="ok",
                                       success=True, duration_seconds=0.1)
        with patch("job.run_nmap_with_xml", return_value=fake_nmap_result), \
             patch("job.banner_mod.grab_banners", return_value=self._fake_banner_results()):
            run_job(job)
        self.assertTrue(all(t.status == TaskStatus.COMPLETED for t in tasks))
        self.assertEqual(len(tasks[2].banners), 3)  # banner task specifically got its results

    def test_banner_grab_task_timeout_reported_correctly(self):
        """A banner grab that exceeds its application timeout must be
        reported as TIMEOUT, not silently hang or crash the job."""
        import time as time_mod

        def slow_grab(target):
            time_mod.sleep(0.3)
            return self._fake_banner_results()

        task = ScanTask("banner_grab", "Banner Grabbing", [], timeout=0.05, task_type="banner_grab")
        job = ScanJob(target="10.0.0.5", tasks=[task])
        with patch("job.banner_mod.grab_banners", side_effect=slow_grab):
            run_job(job)
        self.assertEqual(task.status, TaskStatus.TIMEOUT)
        self.assertIn("Application timeout reached", task.stderr)

    def test_banner_grab_not_marked_failed_when_nmap_missing(self):
        """Banner grabbing doesn't depend on Nmap at all, so an
        NmapNotFoundError from an earlier Nmap-based task must not
        prevent the banner-grab task from still running."""
        from scanner import NmapNotFoundError

        tasks = [
            ScanTask("port_scan", "Port Scan", ["-F"], timeout=180),
            ScanTask("banner_grab", "Banner Grabbing", [], timeout=60, task_type="banner_grab"),
        ]
        job = ScanJob(target="10.0.0.5", tasks=tasks)
        with patch("job.run_nmap_with_xml", side_effect=NmapNotFoundError("nmap not found")), \
             patch("job.banner_mod.grab_banners", return_value=self._fake_banner_results()):
            run_job(job)
        self.assertEqual(tasks[0].status, TaskStatus.FAILED)
        self.assertEqual(tasks[1].status, TaskStatus.COMPLETED)
        self.assertEqual(len(tasks[1].banners), 3)


class TestBannerResultsInAggregatedReport(unittest.TestCase):
    """Regression tests: banner-grab results (not just raw stdout) must
    appear as a dedicated Banner Information section in every aggregated
    report format."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="reconmaster_banner_test_"))
        banner_task = ScanTask(
            "banner_grab", "Banner Grabbing", [], timeout=60, task_type="banner_grab",
            status=TaskStatus.COMPLETED, command="socket banner grab (common service ports)",
            stdout="22: reachable — SSH-2.0-OpenSSH_9.0\n80: reachable — Server: nginx",
            duration_seconds=1.1,
            banners=[
                {"port": 22, "reachable": True, "banner": "SSH-2.0-OpenSSH_9.0"},
                {"port": 80, "reachable": True, "banner": "Server: nginx"},
                {"port": 443, "reachable": False, "banner": ""},
            ],
        )
        job = ScanJob(target="10.0.0.5", tasks=[banner_task])
        job.started_at = "2026-07-26 10:00:00"
        job.ended_at = "2026-07-26 10:00:02"
        job.duration_seconds = 2.0
        self.data = build_job_report_data(job)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_txt_report_contains_banner_information_section(self):
        path = generate_job_reports(self.data, ["txt"], "banner_txt_test", self.tmp_dir)[0]
        content = path.read_text(encoding="utf-8")
        self.assertIn("Banner Information:", content)
        self.assertIn("SSH-2.0-OpenSSH_9.0", content)
        self.assertIn("Port 22", content)

    def test_json_report_contains_structured_banners(self):
        path = generate_job_reports(self.data, ["json"], "banner_json_test", self.tmp_dir)[0]
        import json as json_mod
        payload = json_mod.loads(path.read_text(encoding="utf-8"))
        section = payload["sections"][0]
        self.assertEqual(len(section["banners"]), 3)
        self.assertEqual(section["banners"][0]["port"], 22)
        self.assertTrue(section["banners"][0]["reachable"])

    def test_xml_report_contains_banner_information_element(self):
        path = generate_job_reports(self.data, ["xml"], "banner_xml_test", self.tmp_dir)[0]
        content = path.read_text(encoding="utf-8")
        self.assertIn("BannerInformation", content)
        self.assertIn("SSH-2.0-OpenSSH_9.0", content)

    def test_html_report_contains_banner_table(self):
        path = generate_job_reports(self.data, ["html"], "banner_html_test", self.tmp_dir)[0]
        content = path.read_text(encoding="utf-8")
        self.assertIn("Banner Information", content)
        self.assertIn("SSH-2.0-OpenSSH_9.0", content)

    def test_pdf_report_generates_with_banner_data(self):
        path = generate_job_reports(self.data, ["pdf"], "banner_pdf_test", self.tmp_dir)[0]
        self.assertTrue(path.exists())
        self.assertGreater(path.stat().st_size, 0)

    def test_all_formats_together(self):
        paths = generate_job_reports(self.data, ["txt", "json", "xml", "html", "pdf"],
                                      "banner_all_formats_test", self.tmp_dir)
        for path in paths:
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 0)


class TestFirewallValueValidation(unittest.TestCase):
    """Regression tests: techniques with no safe default must reject a
    missing/invalid value instead of silently building an incomplete
    Nmap command."""

    def test_explicit_value_required_set(self):
        self.assertEqual(firewall.REQUIRES_EXPLICIT_VALUE,
                          {"idle", "bounce", "spoof_ip", "spoof_iface"})

    def test_blank_value_rejected_for_explicit_required_techniques(self):
        for key in firewall.REQUIRES_EXPLICIT_VALUE:
            self.assertFalse(firewall.validate_technique_value(key, ""),
                              f"{key} should reject a blank value")
            self.assertFalse(firewall.validate_technique_value(key, None),
                              f"{key} should reject a missing value")

    def test_blank_value_accepted_for_optional_techniques(self):
        for key in firewall.OPTIONAL_VALUE_TECHNIQUES:
            self.assertTrue(firewall.validate_technique_value(key, ""),
                             f"{key} should accept a blank value (has a safe default)")

    def test_build_firewall_args_raises_on_missing_required_value(self):
        for key in firewall.REQUIRES_EXPLICIT_VALUE:
            with self.assertRaises(ValueError, msg=f"{key} should raise without a value"):
                firewall.build_firewall_args(key, None)
            with self.assertRaises(ValueError, msg=f"{key} should raise on blank value"):
                firewall.build_firewall_args(key, "")

    def test_build_firewall_args_succeeds_with_valid_required_value(self):
        self.assertEqual(firewall.build_firewall_args("idle", "10.0.0.5"), ["-sI", "10.0.0.5"])
        self.assertEqual(firewall.build_firewall_args("spoof_ip", "10.0.0.99"), ["-S", "10.0.0.99"])

    def test_invalid_spoof_ip_rejected(self):
        self.assertFalse(firewall.validate_technique_value("spoof_ip", "not-an-ip"))

    def test_invalid_mtu_rejected_not_multiple_of_eight(self):
        self.assertFalse(firewall.validate_technique_value("mtu", "25"))
        self.assertTrue(firewall.validate_technique_value("mtu", "24"))

    def test_invalid_source_port_out_of_range_rejected(self):
        self.assertFalse(firewall.validate_technique_value("source_port", "70000"))
        self.assertTrue(firewall.validate_technique_value("source_port", "53"))

    def test_optional_technique_with_supplied_invalid_value_rejected(self):
        """Even though these have a safe default, a *supplied* bad value
        must still be rejected rather than silently used."""
        self.assertFalse(firewall.validate_technique_value("custom_ttl", "999"))
        self.assertFalse(firewall.validate_technique_value("data_length", "-5"))


if __name__ == "__main__":
    unittest.main()
