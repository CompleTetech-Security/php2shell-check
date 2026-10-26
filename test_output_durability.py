import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import wordpress_check as m


class DurableOutputTests(unittest.TestCase):
    def call(self, args):
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            return m.main(args)

    def test_existing_output_and_failed_force_remain_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'report.json'
            for fmt in ('json', 'csv', 'html'):
                target.write_text('PREVIOUS REPORT', encoding='utf-8')
                with patch.object(m.Checker, 'check') as check, self.assertRaises(SystemExit):
                    self.call(['one.example', '--output', str(target), '--format', fmt])
                check.assert_not_called()
                self.assertEqual(target.read_text(), 'PREVIOUS REPORT')
            with patch.object(m.Checker, 'check', side_effect=KeyboardInterrupt):
                self.assertEqual(self.call(['one.example', '--output', str(target), '--force']), 130)
            self.assertEqual(target.read_text(), 'PREVIOUS REPORT')
            journal = json.loads(Path(str(target) + '.partial.json').read_text())
            self.assertFalse(journal['complete'])
            self.assertEqual(journal['completed_targets'], 0)
            self.assertEqual(journal['pending_targets'], 1)

    def test_interrupted_completed_rows_recover_all_formats_without_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'initial.json'
            result = m.Result(input_url='https://one.example', title='=SUM(1)', http_status=200)
            with patch.object(m.Checker, 'check', side_effect=[result, KeyboardInterrupt]):
                self.assertEqual(self.call(['one.example', 'two.example', '--output', str(target)]), 130)
            self.assertFalse(target.exists())
            journal = Path(str(target) + '.partial.json')
            report = m.load_checkpoint(journal)
            self.assertEqual((report['completed_targets'], report['pending_targets']), (1, 1))
            for fmt in ('json', 'csv', 'html'):
                recovered = Path(directory) / ('recovered.' + fmt)
                with patch.object(m.Checker, 'check', side_effect=AssertionError('network')):
                    self.assertEqual(self.call(['--recover', str(journal), '--format', fmt, '--output', str(recovered)]), 130)
                text = recovered.read_text(encoding='utf-8')
                if fmt == 'json':
                    self.assertFalse(json.loads(text)['complete'])
                elif fmt == 'csv':
                    row = next(csv.DictReader(io.StringIO(text)))
                    self.assertEqual(row['title'], "'=SUM(1)")
                    self.assertEqual(row['pending_targets'], '1')
                else:
                    self.assertIn('incomplete / recovered', text)
                    self.assertIn('https://one.example', text)
            self.assertTrue(journal.exists())

    def test_forced_process_exit_preserves_checkpoint_for_html(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'killed.html'
            script = """import os,sys
import wordpress_check as m
calls=0
def check(self,url):
 global calls
 calls+=1
 if calls==2: os._exit(73)
 return m.Result(input_url=url,title='<private>')
m.Checker.check=check
m.main(['https://one.example','https://two.example','--output',sys.argv[1],'--format','html'])
"""
            run = subprocess.run([sys.executable, '-c', script, str(target)], capture_output=True, timeout=20)
            self.assertEqual(run.returncode, 73)
            self.assertFalse(target.exists())
            recovered = Path(directory) / 'recovered.html'
            self.assertEqual(self.call(['--recover', str(target) + '.partial.json', '--format', 'html', '--output', str(recovered)]), 130)
            self.assertIn('one.example', recovered.read_text(encoding='utf-8'))
            self.assertNotIn('<private>', recovered.read_text(encoding='utf-8'))

    def test_atomic_publish_race_and_render_failure_preserve_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'out.json'
            original_link = os.link
            def race(source, destination):
                if Path(destination) == target:
                    target.write_text('RACING REPORT', encoding='utf-8')
                return original_link(source, destination)
            with patch.object(m.Checker, 'check', return_value=m.Result(input_url='one.example')), patch.object(m.os, 'link', side_effect=race):
                self.assertEqual(self.call(['one.example', '--output', str(target)]), 2)
            self.assertEqual(target.read_text(), 'RACING REPORT')
            self.assertEqual(m.load_checkpoint(Path(str(target) + '.partial.json'))['completed_targets'], 1)
            target2 = Path(directory) / 'render.html'
            target2.write_text('OLDER', encoding='utf-8')
            with patch.object(m.Checker, 'check', return_value=m.Result(input_url='one.example')), patch.object(m, 'render_html', side_effect=ValueError('render failed')):
                self.assertEqual(self.call(['one.example', '--output', str(target2), '--force', '--format', 'html']), 2)
            self.assertEqual(target2.read_text(), 'OLDER')

    def test_success_and_explicit_force_with_conservative_retained_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'out.json'
            target.write_text('OLD', encoding='utf-8')
            with patch.object(m.Checker, 'check', return_value=m.Result(input_url='one.example')):
                self.assertEqual(self.call(['one.example', '--output', str(target), '--format', 'json', '--force']), 0)
            report = json.loads(target.read_text())
            self.assertTrue(report['complete'])
            self.assertEqual(report['pending_targets'], 0)
            # Existing journal is never silently overwritten, including --force.
            with patch.object(m.Checker, 'check') as check:
                self.assertEqual(self.call(['one.example', '--output', str(target), '--force']), 2)
                check.assert_not_called()
            self.assertEqual(json.loads(target.read_text()), report)

    def test_empty_incomplete_stdout_and_invalid_recovery(self):
        with patch.object(m.Checker, 'check', side_effect=KeyboardInterrupt), redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()):
            self.assertEqual(m.main(['one.example', '--format', 'json']), 130)
        self.assertEqual(json.loads(stdout.getvalue())['pending_targets'], 1)
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / 'bad.json'
            journal.write_text('{"results":[]}', encoding='utf-8')
            with patch.object(m.Checker, 'check') as check:
                self.assertEqual(self.call(['--recover', str(journal)]), 2)
                check.assert_not_called()


if __name__ == '__main__':
    unittest.main()
