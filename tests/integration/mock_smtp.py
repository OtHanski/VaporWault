"""
mock_smtp.py — minimal fake SMTP server for TASK-213's email-alert
integration tests.

Speaks just enough plaintext SMTP (RFC 5321's core commands) for
vw_smtp.c's real client (src/server/vw_smtp.c) to successfully deliver a
message against it: greeting, EHLO, MAIL FROM, RCPT TO, DATA (with
dot-stuffing removal), QUIT. No AUTH, no STARTTLS/TLS — the test server
config that points at this must set `smtp_username = ` (empty, so
vw_smtp.c's AUTH LOGIN/PLAIN step is skipped entirely — see
vw_smtp_send's own `cfg->username[0] != '\0'` gate) and
`smtp_tls_mode = none` / `smtp_verify_cert = 0`.

Captures every delivered message's envelope (MAIL FROM/RCPT TO) and full
raw DATA content (headers + body) so a test can assert on the actual
`To:`/`Subject:` header values and body text a real vw_notify.c trigger
produced — not a mocked/intercepted call, a real message that traveled
over a real TCP connection speaking real SMTP.
"""

import socketserver
import threading


class _Message:
    def __init__(self, mail_from, rcpt_to, raw):
        self.mail_from = mail_from
        self.rcpt_to = rcpt_to
        self.raw = raw
        # Split headers/body on the first blank line, same as RFC 5322.
        if "\r\n\r\n" in raw:
            head, _, self.body = raw.partition("\r\n\r\n")
        else:
            head, self.body = raw, ""
        self.headers = {}
        for line in head.split("\r\n"):
            if ":" in line:
                k, _, v = line.partition(":")
                self.headers[k.strip().lower()] = v.strip()

    @property
    def subject(self):
        return self.headers.get("subject", "")

    @property
    def to(self):
        return self.headers.get("to", "")


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.wfile.write(b"220 mock-smtp ready\r\n")
            mail_from = None
            rcpt_to = None
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not text:
                    continue
                cmd = text.split(" ", 1)[0].upper()

                if cmd in ("EHLO", "HELO"):
                    self.wfile.write(b"250 mock-smtp\r\n")
                elif cmd == "MAIL":
                    mail_from = text
                    self.wfile.write(b"250 OK\r\n")
                elif cmd == "RCPT":
                    rcpt_to = text
                    self.wfile.write(b"250 OK\r\n")
                elif cmd == "DATA":
                    self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    data_lines = []
                    while True:
                        dline = self.rfile.readline()
                        if not dline:
                            return
                        if dline in (b".\r\n", b".\n"):
                            break
                        # Dot-stuffing: a leading ".." on the wire means a
                        # literal "." at the start of that body line.
                        if dline.startswith(b".."):
                            dline = dline[1:]
                        data_lines.append(dline)
                    raw = b"".join(data_lines).decode("utf-8", errors="replace")
                    self.server.vw_messages.append(_Message(mail_from, rcpt_to, raw))
                    self.wfile.write(b"250 OK: queued\r\n")
                elif cmd == "QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                elif cmd == "RSET":
                    mail_from = None
                    rcpt_to = None
                    self.wfile.write(b"250 OK\r\n")
                else:
                    self.wfile.write(b"500 unrecognized command\r\n")
        except (ConnectionError, OSError):
            return


class MockSmtpServer:
    """Start with `with MockSmtpServer() as smtp:` or explicit start()/stop().
    `smtp.messages` is a live list of `_Message` — grows as real emails are
    delivered; `smtp.clear()` resets it between assertions within one test.
    """

    def __init__(self):
        self.messages = []
        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
        self._server.vw_messages = self.messages
        self._server.daemon_threads = True
        self.host = "127.0.0.1"
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def clear(self):
        self.messages.clear()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()
