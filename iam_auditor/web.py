
"""Interface do IAM Permission Auditor.
Suporta múltiplas portas, computadores na rede local e instâncias isoladas.
Apenas biblioteca padrão para o servidor HTTP.
"""
from __future__ import annotations

import configparser
import ipaddress
import json
import os
import secrets
import threading
import webbrowser

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .analyzer import affected_arns, analyze, build_report
from .report import render_html, render_json, render_markdown

UI_FILE = Path(__file__).with_name("ui") / "index.html"

DEFAULT_HOSTS = {"127.0.0.1", "localhost"}


class ScanError(Exception):
    pass


def aws_profiles() -> list[str]:
    names: set[str] = set()

    sources = (
        (os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials"), False),
        (os.environ.get("AWS_CONFIG_FILE", "~/.aws/config"), True),
    )

    for path, is_config in sources:
        cp = configparser.RawConfigParser()

        try:
            cp.read(Path(path).expanduser())
        except (configparser.Error, OSError):
            continue

        for sec in cp.sections():
            if not is_config:
                names.add(sec)
            elif sec == "default":
                names.add("default")
            elif sec.startswith("profile "):
                names.add(sec[8:].strip())

    return sorted(names)


def _int(v, default, lo=1, hi=3650):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def friendly_error(e: Exception) -> str:
    name = type(e).__name__
    code = ""

    resp = getattr(e, "response", None)

    if isinstance(resp, dict):
        code = resp.get("Error", {}).get("Code", "")

    if name in ("NoCredentialsError", "PartialCredentialsError"):
        return "Credenciais não encontradas. Verifique o perfil ou as chaves."

    if name == "ProfileNotFound":
        return "Perfil AWS não encontrado."

    if name in (
        "TokenRetrievalError",
        "SSOTokenLoadError",
        "UnauthorizedSSOTokenError",
    ):
        return "Sessão SSO expirada. Rode: aws sso login --profile <perfil>"

    if code in (
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "AuthFailure",
    ):
        return "Chaves de acesso inválidas."

    if code in ("ExpiredToken", "ExpiredTokenException"):
        return "Credenciais temporárias expiradas."

    if code in (
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
    ):
        return (
            "Permissão negada. Use a política somente leitura "
            "examples/auditor-readonly-policy.json."
        )

    if name in (
        "EndpointConnectionError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
    ):
        return "Sem conexão com a AWS. Verifique sua internet."

    return "%s: %s" % (name, e)


def run_scan(opts: dict) -> dict:
    stale = _int(opts.get("stale_days"), 90)
    key_age = _int(opts.get("key_max_age"), 90)

    session = None

    if opts.get("mode") == "aws":
        try:
            import boto3
            from .collector import collect_advisor, collect_snapshot
        except ImportError:
            raise ScanError(
                "boto3 não está instalado. Rode: pip install -r requirements.txt"
            )

        region = str(opts.get("region") or "us-east-1").strip()[:30]

        if opts.get("auth") == "keys":
            ak = str(opts.get("access_key_id") or "").strip()[:128]
            sk = str(opts.get("secret_access_key") or "").strip()[:256]
            tok = str(opts.get("session_token") or "").strip()[:4096] or None

            if not ak or not sk:
                raise ScanError("Informe Access Key ID e Secret Access Key.")

            session = boto3.Session(
                aws_access_key_id=ak,
                aws_secret_access_key=sk,
                aws_session_token=tok,
                region_name=region,
            )
        else:
            profile = opts.get("profile") or None

            if profile and profile not in aws_profiles():
                raise ScanError("Perfil AWS desconhecido.")

            session = boto3.Session(
                profile_name=profile,
                region_name=region,
            )

        try:
            snapshot = collect_snapshot(session)
        except Exception as e:
            raise ScanError(friendly_error(e))

    else:
        from .demo_data import demo_snapshot
        snapshot = demo_snapshot()

    findings = analyze(
        snapshot,
        stale_days=stale,
        key_max_age=key_age,
    )

    if opts.get("advisor") and session is not None:
        arns = affected_arns(findings, snapshot)[:25]

        try:
            snapshot["advisor"] = collect_advisor(session, arns)
            findings = analyze(
                snapshot,
                stale_days=stale,
                key_max_age=key_age,
            )
        except Exception:
            pass

    return build_report(snapshot, findings)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        addr,
        handler,
        allowed_hosts=None,
        allowed_ips=None,
    ):
        super().__init__(addr, handler)

        self.token = secrets.token_urlsafe(32)
        self.last_report: dict | None = None
        self.port = self.server_address[1]

        self.allowed_hosts = set(allowed_hosts or DEFAULT_HOSTS)
        self.allowed_ips = set(allowed_ips or [])

        self.report_lock = threading.Lock()
        self.scan_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *args):
        pass

    # -------------------------
    # SEGURANÇA
    # -------------------------

    def _send(
        self,
        code: int,
        body: bytes,
        ctype: str = "application/json; charset=utf-8",
        headers: dict | None = None,
    ):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

        for k, v in (headers or {}).items():
            self.send_header(k, v)

        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        body = json.dumps(
            obj,
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

        self._send(code, body)

    def _host_ok(self) -> bool:
        host_header = self.headers.get("Host", "")

        try:
            hostname = urlparse("//" + host_header).hostname
        except ValueError:
            return False

        return hostname in self.server.allowed_hosts

    def _ip_ok(self) -> bool:
        if not self.server.allowed_ips:
            return True

        try:
            client = ipaddress.ip_address(self.client_address[0])

            return any(
                client in ipaddress.ip_network(item, strict=False)
                for item in self.server.allowed_ips
            )
        except ValueError:
            return False

    def _authed(self, query: dict) -> bool:
        token = self.headers.get("X-Token") or (
            query.get("t") or [""]
        )[0]

        return secrets.compare_digest(
            str(token),
            self.server.token,
        )

    def _authorized(self) -> bool:
        return self._host_ok() and self._ip_ok()

    # -------------------------
    # GET
    # -------------------------

    def do_GET(self):
        if not self._authorized():
            return self._json(403, {"error": "acesso não permitido"})

        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path == "/":
            html = (
                UI_FILE.read_text(encoding="utf-8")
                .replace("__TOKEN__", self.server.token)
                .replace("__VERSION__", __version__)
            )

            return self._send(
                200,
                html.encode("utf-8"),
                "text/html; charset=utf-8",
                {
                    "Content-Security-Policy": (
                        "default-src 'self'; "
                        "style-src 'self' 'unsafe-inline'; "
                        "script-src 'self' 'unsafe-inline'; "
                        "connect-src 'self'; "
                        "frame-ancestors 'none'"
                    )
                },
            )

        if not url.path.startswith("/api/") or not self._authed(query):
            return self._json(
                403,
                {"error": "não autorizado"},
            )

        if url.path == "/api/profiles":
            return self._json(
                200,
                {"profiles": aws_profiles()},
            )

        if url.path == "/api/export":
            with self.server.report_lock:
                report = self.server.last_report

            if not report:
                return self._json(
                    404,
                    {"error": "execute uma auditoria primeiro"},
                )

            fmt = (query.get("fmt") or ["json"])[0]

            formats = {
                "html": (render_html, "text/html; charset=utf-8"),
                "json": (render_json, "application/json; charset=utf-8"),
                "md": (render_markdown, "text/markdown; charset=utf-8"),
            }

            if fmt not in formats:
                return self._json(
                    400,
                    {"error": "formato inválido"},
                )

            fn, content_type = formats[fmt]

            return self._send(
                200,
                fn(report).encode("utf-8"),
                content_type,
                {
                    "Content-Disposition": (
                        "attachment; filename=iam-audit.%s" % fmt
                    )
                },
            )

        return self._json(404, {"error": "não encontrado"})

    # -------------------------
    # POST
    # -------------------------

    def do_POST(self):
        if not self._authorized():
            return self._json(403, {"error": "acesso não permitido"})

        origin = self.headers.get("Origin")

        if origin:
            origin_host = urlparse(origin).hostname

            if origin_host not in self.server.allowed_hosts:
                return self._json(
                    403,
                    {"error": "origem não permitida"},
                )

        path = urlparse(self.path).path

        if path not in ("/api/scan", "/api/clear"):
            return self._json(404, {"error": "não encontrado"})

        if not self._authed({}):
            return self._json(403, {"error": "não autorizado"})

        if path == "/api/clear":
            with self.server.report_lock:
                self.server.last_report = None

            return self._json(200, {"ok": True})

        try:
            length = int(self.headers.get("Content-Length", "0"))

            if length < 0 or length > 10_000:
                return self._json(
                    413,
                    {"error": "requisição muito grande"},
                )

            raw = self.rfile.read(length)

            opts = json.loads(raw or b"{}")

            if not isinstance(opts, dict):
                raise ValueError("objeto JSON esperado")

        except (ValueError, UnicodeDecodeError):
            return self._json(400, {"error": "json inválido"})

        # Evita duas auditorias simultâneas na mesma instância.
        if not self.server.scan_lock.acquire(blocking=False):
            return self._json(
                409,
                {"error": "já existe uma auditoria em execução nesta instância"},
            )

        try:
            try:
                report = run_scan(opts)
            except ScanError as e:
                return self._json(400, {"error": str(e)})
            except Exception as e:
                return self._json(400, {"error": friendly_error(e)})

            with self.server.report_lock:
                self.server.last_report = report

            return self._json(200, report)

        finally:
            self.server.scan_lock.release()


# -------------------------
# GERENCIAMENTO DE SERVIDORES
# -------------------------

def _create_server(
    host: str,
    port: int,
    allowed_hosts=None,
    allowed_ips=None,
):
    hosts = set(allowed_hosts or DEFAULT_HOSTS)

    if host not in ("0.0.0.0", "::"):
        hosts.add(host)

    return _Server(
        (host, port),
        Handler,
        allowed_hosts=hosts,
        allowed_ips=allowed_ips,
    )


def serve(
    port: int = 8765,
    open_browser: bool = True,
    host: str = "127.0.0.1",
    allowed_hosts=None,
    allowed_ips=None,
) -> int:
    """Inicia uma instância independente do auditor."""

    srv = None

    for p in range(port, port + 11):
        try:
            srv = _create_server(
                host,
                p,
                allowed_hosts,
                allowed_ips,
            )
            break
        except OSError:
            continue

    if srv is None:
        print("Não foi possível encontrar uma porta livre.")
        return 1

    display_host = "127.0.0.1" if host == "0.0.0.0" else host
    url = "http://%s:%d" % (display_host, srv.port)

    print("\n IAM Permission Auditor")
    print(" Endereço: %s" % url)
    print(" Porta: %d" % srv.port)
    print(" Token individual gerado.")
    print(" Ctrl+C para encerrar.\n")

    if open_browser and host == "127.0.0.1":
        threading.Timer(
            0.6,
            lambda: webbrowser.open(url),
        ).start()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
    finally:
        srv.server_close()

    return 0


def serve_multiple(
    port: int = 8765,
    count: int = 4,
    host: str = "127.0.0.1",
    allowed_hosts=None,
    allowed_ips=None,
    open_browser: bool = True,
) -> int:
    """Inicia várias instâncias independentes em portas diferentes."""

    count = max(1, min(int(count), 20))

    servers = []
    threads = []

    try:
        for offset in range(count):
            srv = _create_server(
                host,
                port + offset,
                allowed_hosts,
                allowed_ips,
            )

            servers.append(srv)

        print("\n IAM Permission Auditor - múltiplas instâncias")

        for srv in servers:
            display_host = (
                "127.0.0.1" if host == "0.0.0.0" else host
            )

            url = "http://%s:%d" % (
                display_host,
                srv.port,
            )

            print(" -> %s" % url)
            print("    Token independente gerado.")

            thread = threading.Thread(
                target=srv.serve_forever,
                daemon=True,
            )

            thread.start()
            threads.append(thread)

        if open_browser and host == "127.0.0.1":
            webbrowser.open(
                "http://127.0.0.1:%d" % servers[0].port
            )

        print("\n%d instâncias ativas." % len(servers))
        print("Pressione Ctrl+C para encerrar todas.\n")

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        print("\nEncerrando todas as instâncias...")

    except OSError as e:
        print("Erro ao iniciar servidores: %s" % e)
        return 1

    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()

    return 0
