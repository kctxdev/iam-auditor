"""Interface local (http://127.0.0.1:PORT) para o auditor. Apenas biblioteca padrão."""
from __future__ import annotations

import configparser
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
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


class ScanError(Exception):
    pass


def aws_profiles() -> list[str]:
    names: set[str] = set()
    sources = ((os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials"), False),
               (os.environ.get("AWS_CONFIG_FILE", "~/.aws/config"), True))
    for path, is_config in sources:
        cp = configparser.RawConfigParser()
        try:
            cp.read(Path(path).expanduser())
        except configparser.Error:
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
        return "Credenciais não encontradas. Verifique o perfil ou as chaves informadas."
    if name == "ProfileNotFound":
        return "Perfil AWS não encontrado."
    if name in ("TokenRetrievalError", "SSOTokenLoadError", "UnauthorizedSSOTokenError"):
        return "Sessão SSO expirada. Rode: aws sso login --profile <perfil>"
    if code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "AuthFailure"):
        return "Chaves de acesso inválidas."
    if code in ("ExpiredToken", "ExpiredTokenException"):
        return "Credenciais temporárias expiradas. Gere novas e tente de novo."
    if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
        return "Permissão negada. Use a política somente leitura de examples/auditor-readonly-policy.json."
    if name in ("EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError"):
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
            raise ScanError("boto3 não esta instalado. Rode: pip install -r requirements.txt")
        region = str(opts.get("region") or "us-east-1").strip()[:30]
        if opts.get("auth") == "keys":
            ak = str(opts.get("access_key_id") or "").strip()[:128]
            sk = str(opts.get("secret_access_key") or "").strip()[:256]
            tok = str(opts.get("session_token") or "").strip()[:4096] or None
            if not ak or not sk:
                raise ScanError("Informe Access Key ID e Secret Access Key.")
            session = boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk,
                                    aws_session_token=tok, region_name=region)
        else:
            profile = opts.get("profile") or None
            if profile and profile not in aws_profiles():
                raise ScanError("Perfil AWS desconhecido.")
            session = boto3.Session(profile_name=profile, region_name=region)
        try:
            snapshot = collect_snapshot(session)
        except Exception as e:
            raise ScanError(friendly_error(e))
    else:
        from .demo_data import demo_snapshot
        snapshot = demo_snapshot()

    findings = analyze(snapshot, stale_days=stale, key_max_age=key_age)
    if opts.get("advisor") and session is not None:
        arns = affected_arns(findings, snapshot)[:25]
        try:
            snapshot["advisor"] = collect_advisor(session, arns)
            findings = analyze(snapshot, stale_days=stale, key_max_age=key_age)
        except Exception:
            pass  # advisor e opcional: segue sem as sugestões
    return build_report(snapshot, findings)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self.token = secrets.token_urlsafe(24)
        self.last_report: dict | None = None
        self.port = addr[1]


class Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *args):  # silencioso
        pass

    # ---- helpers
    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8", headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode())

    def _host_ok(self) -> bool:  # defesa contra DNS rebinding
        return self.headers.get("Host", "").rsplit(":", 1)[0] in ALLOWED_HOSTS

    def _authed(self, query: dict) -> bool:
        tok = self.headers.get("X-Token") or (query.get("t") or [""])[0]
        return secrets.compare_digest(tok, self.server.token)

    # ---- rotas
    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": "host não permitido"})
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/":
            html = UI_FILE.read_text(encoding="utf-8").replace("__TOKEN__", self.server.token).replace("__VERSION__", __version__)
            return self._send(200, html.encode(), "text/html; charset=utf-8",
                              {"Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"})
        if not url.path.startswith("/api/") or not self._authed(q):
            return self._json(403 if url.path.startswith("/api/") else 404, {"error": "não autorizado" if url.path.startswith("/api/") else "não encontrado"})
        if url.path == "/api/profiles":
            return self._json(200, {"profiles": aws_profiles()})
        if url.path == "/api/export":
            rep = self.server.last_report
            if not rep:
                return self._json(404, {"error": "execute uma auditoria primeiro"})
            fmt = (q.get("fmt") or ["json"])[0]
            table = {"html": (render_html, "text/html; charset=utf-8"), "json": (render_json, "application/json; charset=utf-8"),
                     "md": (render_markdown, "text/markdown; charset=utf-8")}
            if fmt not in table:
                return self._json(400, {"error": "formato inválido"})
            fn, ctype = table[fmt]
            return self._send(200, fn(rep).encode(), ctype, {"Content-Disposition": "attachment; filename=iam-audit.%s" % fmt})
        return self._json(404, {"error": "não encontrado"})

    def do_POST(self):
        if not self._host_ok():
            return self._json(403, {"error": "host não permitido"})
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).hostname not in ALLOWED_HOSTS:
            return self._json(403, {"error": "origem não permitida"})
        path = urlparse(self.path).path
        if path not in ("/api/scan", "/api/clear") or not self._authed({}):
            return self._json(403, {"error": "não autorizado"})
        if path == "/api/clear":
            self.server.last_report = None
            return self._json(200, {"ok": True})
        try:
            size = min(int(self.headers.get("Content-Length", "0")), 10_000)
            opts = json.loads(self.rfile.read(size) or b"{}")
        except ValueError:
            return self._json(400, {"error": "json inválido"})
        try:
            report = run_scan(opts)
        except ScanError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            return self._json(400, {"error": friendly_error(e)})
        self.server.last_report = report
        self._json(200, report)


def serve(port: int = 8765, open_browser: bool = True) -> int:
    srv = None
    for p in range(port, port + 11):
        try:
            srv = _Server(("127.0.0.1", p), Handler)
            break
        except OSError:
            continue
    if srv is None:
        print("Não consegui abrir uma porta livre perto de %d." % port)
        return 1
    url = "http://127.0.0.1:%d" % srv.port
    print("\n  IAM Permission Auditor - interface local")
    print("  -> %s" % url)
    print("  (somente esta maquina; Ctrl+C para encerrar)\n")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    finally:
        srv.server_close()
    return 0
