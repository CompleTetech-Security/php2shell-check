import contextlib
import io
import json
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import wordpress_check as checker


class TargetDeadlineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                cls.requests.append(self.path)
                try:
                    if self.path == '/robots.txt':
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'User-agent: *\nDisallow: /private\n')
                    elif self.path == '/slow':
                        self.send_response(200)
                        self.end_headers()
                        for _ in range(40):
                            self.wfile.write(b'x')
                            self.wfile.flush()
                            time.sleep(.04)
                    elif self.path == '/idle':
                        time.sleep(.3)
                        self.send_response(200)
                        self.end_headers()
                    elif self.path == '/unicode':
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/html; charset=utf-8')
                        self.end_headers()
                        self.wfile.write('<title>\u65e5\u672c\u8a9e \u2603</title>'.encode('utf-8'))
                    elif self.path.startswith('/redirect'):
                        time.sleep(.12)
                        self.send_response(302)
                        self.send_header('Location', '/redirect' + str(int(self.path[9:]) + 1))
                        self.end_headers()
                    else:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'<title>synthetic</title>')
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass
            def log_message(self, *_):
                pass
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.requests.clear()

    def assert_incomplete(self, result):
        self.assertEqual(result.status, 'error')
        self.assertEqual(result.fetch_status, 'deadline_exceeded')
        self.assertEqual(result.php2shell_status, 'unknown')
        self.assertEqual(result.php2shell_exploitability, 'not_tested')

    def test_slow_trickle_is_cancelled_and_next_target_progresses(self):
        client = checker.Checker(timeout=.2, target_timeout=.65, delay=0)
        start = time.monotonic()
        self.assert_incomplete(client.check(self.url + '/slow'))
        self.assertLess(time.monotonic() - start, 1.5)
        # Cache and state survive cancellation, but the target gets a fresh budget.
        result = client.check(self.url + '/fast')
        self.assertEqual(result.status, 'no_evidence')
        self.assertEqual(self.requests.count('/robots.txt'), 1)

    def test_redirect_chain_shares_budget(self):
        client = checker.Checker(timeout=1, target_timeout=.65, delay=0)
        start = time.monotonic()
        self.assert_incomplete(client.check(self.url + '/redirect0'))
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertLess(len([p for p in self.requests if p.startswith('/redirect')]), 6)

    def test_pacing_does_not_sleep_past_budget_or_fetch_page(self):
        client = checker.Checker(timeout=1, target_timeout=.5, delay=1)
        start = time.monotonic()
        self.assert_incomplete(client.check(self.url + '/fast'))
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(self.requests, ['/robots.txt'])

    def test_dns_and_connect_stalls_are_killed_without_surviving_workers(self):
        real_popen = subprocess.Popen
        for operation in ('dns', 'connect'):
            with self.subTest(operation=operation):
                children = []
                def spawn(command, **kwargs):
                    script = "import runpy,sys,time;m=runpy.run_path(sys.argv[1]);"
                    if operation == 'dns':
                        script += "m['socket'].getaddrinfo=lambda *a,**k:time.sleep(20);"
                    else:
                        script += "m['socket'].socket.connect=lambda *a,**k:time.sleep(20);"
                    script += "m['_request_worker']()"
                    child = real_popen([sys.executable, '-I', '-c', script, str(Path(checker.__file__).resolve())], **kwargs)
                    children.append(child)
                    return child
                start = time.monotonic()
                with patch.object(checker.subprocess, 'Popen', side_effect=spawn):
                    result = checker.Checker(timeout=.1, target_timeout=.4, delay=0).check(self.url)
                self.assert_incomplete(result)
                self.assertLess(time.monotonic() - start, 1.4)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())

    def test_cli_deadline_keeps_result_and_continues_batch(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = checker.main([self.url + '/slow', self.url + '/fast', '--format', 'json',
                                 '--timeout', '.2', '--target-timeout', '.65', '--delay', '.001'])
        report = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(report['complete'])  # All inputs handled; first assessment failed.
        self.assertEqual(report['results'][0]['fetch_status'], 'deadline_exceeded')
        self.assertEqual(report['results'][0]['php2shell_status'], 'unknown')
        self.assertEqual(report['results'][1]['status'], 'no_evidence')

    def test_robots_scope_and_socket_timeout_remain_active(self):
        client = checker.Checker(timeout=.05, target_timeout=2, delay=0)
        result = client.check(self.url + '/private')
        self.assertEqual(result.status, 'blocked')
        self.assertNotIn('/private', self.requests)
        # An inactivity timeout remains distinct from total deadline exhaustion.
        with patch.object(client, '_fetch', side_effect=AssertionError('parent HTTP forbidden')):
            self.assertEqual(client.check(self.url + '/fast').status, 'no_evidence')
            self.assertEqual(client.check(self.url + '/idle').fetch_status, 'timeout')

    def test_expiry_during_parsing_never_publishes_a_positive_assessment(self):
        client = checker.Checker(target_timeout=1, delay=0)
        client.request = lambda *args: checker.Response(200, {}, '', False)
        client.robots[self.url] = (None, 0, 'synthetic robots')
        def late_parse(response, result):
            result.php_version = '8.3.36'
            client._deadline = 0
        with patch.object(checker, 'inspect_page', side_effect=late_parse):
            self.assert_incomplete(client.check(self.url))

    def test_invalid_total_budgets_are_rejected(self):
        for value in (0, -1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                checker.Checker(target_timeout=value)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            checker.main(['example.test', '--target-timeout', '0'])

    def test_unicode_response_survives_worker_boundary(self):
        result = checker.Checker(timeout=1, target_timeout=2, delay=0).check(self.url + '/unicode')
        self.assertEqual(result.status, 'no_evidence')
        self.assertEqual(result.title, '\u65e5\u672c\u8a9e \u2603')


if __name__ == '__main__':
    unittest.main()
