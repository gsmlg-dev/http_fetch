"""Pure controls for the bounded HTTPS peer observation policy."""

import errno
import importlib.util
import io
from pathlib import Path
import ssl
import unittest
from unittest.mock import MagicMock, Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "https_early_upload_peer", Path(__file__).resolve().parents[1] / "https_early_upload_peer.py"
)
peer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(peer)


class HTTPSPeerPolicyTests(unittest.TestCase):
    def invoke(self, receive, *, send_error=None, timeout_error=None, header_error=None):
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.send.return_value = 1
        self.connection.send.side_effect = send_error
        self.connection.settimeout.side_effect = timeout_error
        self.connection.getsockopt.return_value = 1024
        self.connection.recv.side_effect = [
            header_error or b"POST /upload HTTP/1.1\r\nHost: localhost\r\n\r\n",
            *receive,
        ]
        listener = MagicMock()
        listener.__enter__.return_value = listener
        listener.getsockname.return_value = ("127.0.0.1", 1234)
        listener.accept.return_value = (Mock(), ("127.0.0.1", 1235))
        context = Mock()
        context.wrap_socket.return_value = self.connection
        with patch.object(peer.socket, "socket", return_value=listener), \
                patch.object(peer.ssl, "SSLContext", return_value=context), \
                patch.object(peer.sys, "argv", ["peer", "--cert", "cert", "--key", "key"]), \
                patch.object(peer.sys, "stdin", io.StringIO("drain\n")), \
                patch.object(peer.time, "monotonic", return_value=10), \
                patch.object(peer, "event") as events:
            self.events = events
            peer.main()

    def assert_no_closed(self):
        self.assertNotIn("closed", [call.args[0] for call in self.events.call_args_list])

    def test_receive_epipe_is_terminal_after_actual_receive(self):
        self.invoke([BrokenPipeError(errno.EPIPE, "pipe")])
        self.connection.recv.assert_called_with(65536)
        self.events.assert_called_with("closed", drained_bytes=0)

    def test_wrong_errno_broken_pipe_is_not_terminal(self):
        with self.assertRaises(BrokenPipeError):
            self.invoke([BrokenPipeError(errno.EINVAL, "wrong errno")])
        self.assert_no_closed()

    def test_unknown_oserror_is_not_terminal(self):
        with self.assertRaises(OSError):
            self.invoke([OSError(errno.EIO, "unknown")])
        self.assert_no_closed()

    def test_settimeout_epipe_is_not_receive_evidence(self):
        with self.assertRaises(BrokenPipeError):
            self.invoke([b""], timeout_error=[None, BrokenPipeError(errno.EPIPE, "options")])
        self.connection.recv.assert_called_once_with(1)
        self.assert_no_closed()

    def test_header_epipe_is_not_drain_evidence(self):
        with self.assertRaises(BrokenPipeError):
            self.invoke([], header_error=BrokenPipeError(errno.EPIPE, "header"))
        self.connection.send.assert_not_called()
        self.assert_no_closed()

    def test_send_success_still_requires_receive(self):
        self.invoke([b""])
        self.connection.send.assert_called_once_with(b"\x00")
        self.connection.recv.assert_called_with(65536)
        self.events.assert_called_with("closed", drained_bytes=0)

    def test_terminal_send_error_still_requires_receive(self):
        for error in [ConnectionResetError(), BrokenPipeError(errno.EPIPE, "send"),
                      ssl.SSLEOFError(), ssl.SSLZeroReturnError()]:
            with self.subTest(error=type(error).__name__):
                self.invoke([b""], send_error=error)
                self.connection.recv.assert_called_with(65536)
                self.events.assert_called_with("closed", drained_bytes=0)

    def test_terminal_send_error_cannot_replace_failed_receive(self):
        with self.assertRaises(SystemExit) as stopped:
            self.invoke([TimeoutError()], send_error=BrokenPipeError(errno.EPIPE, "send"))
        self.assertEqual(stopped.exception.code, 1)
        self.connection.recv.assert_called_with(65536)
        self.assert_no_closed()

    def test_existing_terminal_receive_outcomes(self):
        for result in [b"", ConnectionResetError(), ssl.SSLEOFError(), ssl.SSLZeroReturnError()]:
            with self.subTest(result=repr(result)):
                self.invoke([b"body", result])
                self.events.assert_called_with("closed", drained_bytes=4)

    def test_receive_timeout_still_fails(self):
        with self.assertRaises(SystemExit) as stopped:
            self.invoke([TimeoutError()])
        self.assertEqual(stopped.exception.code, 1)
        self.events.assert_called_with("drain_timeout", drained_bytes=0, receive_buffer=1024)
        self.assert_no_closed()

    def probe(self, *, result=1, error=None, times=None, deadline=12):
        self.probe_connection = Mock(spec=["settimeout", "send"])
        self.probe_connection.send.return_value = result
        self.probe_connection.send.side_effect = error
        with patch.object(peer.time, "monotonic", side_effect=times or [10, 10, 10.05]), \
                patch.object(peer, "event") as events:
            self.probe_events = events
            peer.probe_once(self.probe_connection, deadline)

    def test_one_write_is_bounded_to_100ms(self):
        self.probe()
        self.assertAlmostEqual(self.probe_connection.settimeout.call_args.args[0], .1)
        self.probe_connection.send.assert_called_once_with(b"\x00")
        self.probe_events.assert_not_called()

    def test_send_budget_is_clipped_to_original_drain_deadline(self):
        self.probe(deadline=10.02, times=[10, 10, 10.01])
        self.assertAlmostEqual(self.probe_connection.settimeout.call_args.args[0], .02)
        self.probe_connection.send.assert_called_once()

    def test_exhausted_budget_never_starts_send(self):
        with self.assertRaises(TimeoutError):
            self.probe(deadline=10, times=[10, 10])
        self.probe_connection.send.assert_not_called()

    def test_timeout_and_unknown_tls_error_are_not_success(self):
        for error in [TimeoutError(), ssl.SSLError(1, "unknown"), OSError(errno.EIO, "unknown")]:
            with self.subTest(error=repr(error)), self.assertRaises(type(error)):
                self.probe(error=error)
            self.probe_connection.send.assert_called_once()
            self.probe_events.assert_not_called()

    def test_terminal_send_errors_do_not_emit_receive_success(self):
        for error in [ConnectionResetError(), BrokenPipeError(),
                      ssl.SSLEOFError(), ssl.SSLZeroReturnError()]:
            with self.subTest(error=repr(error)):
                self.probe(error=error)
                self.probe_events.assert_not_called()
                self.probe_connection.send.assert_called_once()

    def test_partial_send_fails_without_retry(self):
        with self.assertRaises(OSError):
            self.probe(result=0)
        self.probe_connection.send.assert_called_once()
        self.probe_events.assert_not_called()

    def test_late_send_return_fails(self):
        with self.assertRaises(TimeoutError):
            self.probe(times=[10, 10, 10.101])
        self.probe_connection.send.assert_called_once()
        self.probe_events.assert_not_called()


if __name__ == "__main__":
    unittest.main()
