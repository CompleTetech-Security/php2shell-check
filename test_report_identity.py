import argparse
import csv
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
import wordpress_check as m


class ReportIdentityTests(unittest.TestCase):
    def args(self, fmt):
        return argparse.Namespace(format=fmt, logo=Path('absent-logo.png'), brand='Synthetic')

    def test_all_formats_preserve_one_identity_and_distinct_times(self):
        row = m.asdict(m.Result(input_url='https://example.invalid/', checked_at='2001-01-01T00:00:00+00:00'))
        report = m.run_report([row], 1, complete=True)
        expected = hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
        self.assertEqual(report['provenance']['executable_sha256'], expected)
        for fmt in ('json', 'csv', 'html'):
            output = m.format_report(report, self.args(fmt))
            for value in report['provenance'].values():
                self.assertIn(value, output)
            self.assertIn(row['checked_at'], output)
        self.assertNotEqual(report['provenance']['generated_at'], row['checked_at'])

    def test_empty_incomplete_and_recovered_reports_retain_acquisition_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'checkpoint.json'
            report = m.run_report([], 2)
            path.write_text(m.checkpoint_json(report), encoding='utf-8')
            with patch.object(m, 'report_provenance', side_effect=AssertionError('must not replace acquisition identity')):
                restored = m.load_checkpoint(path)
                for fmt in ('json', 'csv', 'html'):
                    output = m.format_report(restored, self.args(fmt))
                    self.assertIn(report['provenance']['executable_sha256'], output)
            row = next(csv.DictReader(io.StringIO(m.format_report(restored, self.args('csv')))))
            self.assertEqual(row['record_type'], 'summary')
            self.assertEqual(row['complete'], 'False')
            self.assertEqual(row['pending_targets'], '2')

    def test_cli_interrupt_keeps_initial_run_identity(self):
        result = m.Result(input_url='https://one.invalid/')
        identity = m.report_provenance()
        with patch.object(m.Checker, 'check', side_effect=[result, KeyboardInterrupt]), patch.object(m, 'report_provenance', return_value=identity) as provenance, redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            self.assertEqual(m.main(['one.invalid', 'two.invalid', '--format', 'json']), 130)
        report = json.loads(out.getvalue())
        self.assertEqual(report['provenance'], identity)
        self.assertEqual(provenance.call_count, 1)
        self.assertFalse(report['complete'])
        self.assertEqual(report['completed_targets'], 1)

    def test_recovery_distinguishes_updated_reference_rules_from_acquisition(self):
        report = m.run_report([m.asdict(m.Result(input_url='old.invalid', php2shell_fixed_version='8.2.35'))], 1)
        original = dict(report['provenance'])
        with patch.object(m, 'PHP2SHELL_RULES_DATE', '2099-01-01'), patch.object(m, 'PHP2SHELL_FIXES', {(8, 2): 99}), patch.object(m, 'PHP2SHELL_SOURCES', ('https://reference.invalid/new',)):
            text = m.format_report(report, self.args('html'))
            self.assertIn('acquisition rules as of ' + original['rules_as_of'], text)
            self.assertIn('Current reference rules as of 2099-01-01', text)
            self.assertIn('8.2.99', text)
            self.assertIn('8.2.35', text)
            self.assertIn('Current reference sources:', text)
            for fmt in ('json', 'csv'):
                self.assertIn(original['rules_sha256'], m.format_report(report, self.args(fmt)))
        self.assertEqual(report['provenance'], original)

    def test_copied_and_symlinked_executable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory)/'standalone.py'
            shutil.copyfile(m.__file__, copy)
            copy.write_bytes(copy.read_bytes()+b'\n# synthetic distribution variant\n')
            with patch.object(m, '__file__', str(copy)):
                self.assertEqual(m.report_provenance()['executable_sha256'], hashlib.sha256(copy.read_bytes()).hexdigest())
            link = Path(directory)/'link.py'
            try:
                link.symlink_to(copy)
            except OSError:
                return
            with patch.object(m, '__file__', str(link)):
                self.assertEqual(m.report_provenance()['executable_sha256'], hashlib.sha256(copy.read_bytes()).hexdigest())

    def test_legacy_checkpoint_is_not_relabelled_and_invalid_provenance_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'checkpoint.json'
            report = m.run_report([], 1)
            legacy = dict(report)
            del legacy['provenance']
            path.write_text(json.dumps(legacy), encoding='utf-8')
            restored = m.load_checkpoint(path)
            self.assertIsNone(json.loads(m.format_report(restored, self.args('json')))['provenance'])
            self.assertIn('unknown', m.format_report(restored, self.args('csv')))
            for key, value in [('executable_sha256', '=unsafe'), ('generated_at', '2026-01-01T00:00:00'), ('tool', '<unsafe>')]:
                bad = {**report, 'provenance': {**report['provenance'], key: value}}
                path.write_text(json.dumps(bad), encoding='utf-8')
                with self.assertRaises(ValueError):
                    m.load_checkpoint(path)

if __name__ == '__main__':
    unittest.main()
