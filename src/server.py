#!/usr/bin/env python3

# kj-clipboard server, no frills public clipboard
# single-file server: sqlite, mojicrypt encryption, syntax highlighting
# usage: python3 src/server.py

import http.server
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse, unquote


# config

PORT = int(os.environ.get("KJ_CLIPBOARD_PORT", 5555))
BIND = os.environ.get("KJ_CLIPBOARD_BIND", "0.0.0.0")
BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / "data" / "kj-clipboard.db"
RANDOM_ID_LENGTH = 40  # random chars after unix epoch
MAX_PASTE_SIZE = 67 * 1024 * 1024 // 10  # 6.7 MiB
MAX_PASSPHRASE_SIZE = 512
MAX_LANGUAGE_SIZE = 32
MAX_DECRYPT_SIZE = 3 * 1024 * 1024  # headroom for decrypt requests with long passphrases
ID_PATTERN = re.compile(r"^[0-9]{10,}[a-f0-9]{40}$")
LANGUAGE_PATTERN = re.compile(r"^[a-z0-9_+#-]{1,32}$")

REQUESTS_PER_WINDOW = int(os.environ.get("KJ_CLIPBOARD_RATE_LIMIT", "60"))
RATE_WINDOW_SECONDS = int(os.environ.get("KJ_CLIPBOARD_RATE_WINDOW", "60"))

ALLOWED_LANGUAGES = {
    "1c",
    "abnf",
    "accesslog",
    "ada",
    "angelscript",
    "apache",
    "applescript",
    "arcade",
    "arduino",
    "armasm",
    "asciidoc",
    "aspectj",
    "autohotkey",
    "autoit",
    "avrasm",
    "awk",
    "bash",
    "basic",
    "bnf",
    "brainfuck",
    "c",
    "cal",
    "capnproto",
    "ceylon",
    "clean",
    "clojure",
    "clojure-repl",
    "cmake",
    "coffeescript",
    "coq",
    "cos",
    "cpp",
    "crmsh",
    "crystal",
    "csharp",
    "csp",
    "css",
    "d",
    "dart",
    "delphi",
    "diff",
    "django",
    "dns",
    "dockerfile",
    "dos",
    "dsconfig",
    "dts",
    "dust",
    "ebnf",
    "elixir",
    "elm",
    "erb",
    "erlang",
    "excel",
    "fix",
    "flix",
    "fortran",
    "fsharp",
    "gams",
    "gauss",
    "gcode",
    "gherkin",
    "glsl",
    "gml",
    "go",
    "golo",
    "gradle",
    "graphql",
    "groovy",
    "haml",
    "handlebars",
    "haskell",
    "haxe",
    "hsp",
    "http",
    "hy",
    "inform7",
    "ini",
    "irpf90",
    "isbl",
    "java",
    "javascript",
    "jboss-cli",
    "json",
    "julia",
    "julia-repl",
    "kotlin",
    "lasso",
    "latex",
    "ldif",
    "leaf",
    "less",
    "lisp",
    "livecodeserver",
    "livescript",
    "llvm",
    "lsl",
    "lua",
    "makefile",
    "markdown",
    "mathematica",
    "matlab",
    "maxima",
    "mel",
    "mercury",
    "mipsasm",
    "mizar",
    "mojolicious",
    "monkey",
    "moonscript",
    "n1ql",
    "nestedtext",
    "nginx",
    "nim",
    "nix",
    "node-repl",
    "nsis",
    "objectivec",
    "ocaml",
    "openscad",
    "oxygene",
    "parser3",
    "perl",
    "pf",
    "pgsql",
    "php",
    "php-template",
    "plaintext",
    "pony",
    "powershell",
    "processing",
    "profile",
    "prolog",
    "properties",
    "protobuf",
    "puppet",
    "purebasic",
    "python",
    "python-repl",
    "q",
    "qml",
    "r",
    "reasonml",
    "rib",
    "roboconf",
    "routeros",
    "rsl",
    "ruby",
    "ruleslanguage",
    "rust",
    "sas",
    "scala",
    "scheme",
    "scilab",
    "scss",
    "shell",
    "smali",
    "smalltalk",
    "sml",
    "sqf",
    "sql",
    "stan",
    "stata",
    "step21",
    "stylus",
    "subunit",
    "swift",
    "taggerscript",
    "tap",
    "tcl",
    "thrift",
    "tp",
    "twig",
    "typescript",
    "vala",
    "vbnet",
    "vbscript",
    "vbscript-html",
    "verilog",
    "vhdl",
    "vim",
    "wasm",
    "wren",
    "x86asm",
    "xl",
    "xml",
    "xquery",
    "yaml",
    "zephir",
}


# in-memory fixed-window rate limiter (cheap guardrail behind nginx)
_rate_lock = threading.Lock()
_rate_state = {}


# database


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pastes (
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            language TEXT DEFAULT NULL,
            is_code INTEGER DEFAULT 0,
            is_encrypted INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL
        )
    """
    )
    conn.commit()
    conn.close()


def generate_id():
    """generate id in format: <unix-epoch><40-char-random-hex>"""
    return f"{int(time.time())}{secrets.token_hex(RANDOM_ID_LENGTH // 2)}"


def is_valid_paste_id(paste_id):
    """validate id format: unix epoch prefix + 40 hex chars"""
    return bool(ID_PATTERN.match(paste_id))


def save_paste(content, language=None, is_code=False, is_encrypted=False):
    """store a paste in the database, return its id"""
    conn = sqlite3.connect(str(DB_PATH))
    try:
        for _ in range(5):
            paste_id = generate_id()
            try:
                conn.execute(
                    "INSERT INTO pastes (id, content, language, is_code, is_encrypted, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        paste_id,
                        content,
                        language,
                        int(is_code),
                        int(is_encrypted),
                        int(time.time()),
                    ),
                )
                conn.commit()
                return paste_id
            except sqlite3.IntegrityError:
                continue
        raise RuntimeError("failed to generate unique paste id")
    finally:
        conn.close()


def get_paste(paste_id):
    """retrieve a paste by id, returns dict or None"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


# mojicrypt helpers


def mojicrypt_encrypt(text, passphrase):
    """encrypt text with mojicrypt, return glyph string or None on failure"""
    try:
        result = subprocess.run(
            ["mojicrypt", "encrypt", "-p", passphrase],
            input=text,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def mojicrypt_decrypt(encrypted_blob, passphrase):
    """decrypt a mojicrypt glyph string, return plaintext or None on failure"""
    try:
        result = subprocess.run(
            ["mojicrypt", "decrypt", "-p", passphrase],
            input=encrypted_blob,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


# html templates


def landing_page():
    return (BASE_DIR / "index.html").read_text(encoding="utf-8")


def paste_page(paste):
    """render the view page for a paste"""
    paste_id = paste["id"]
    content = paste["content"]
    is_code = paste["is_code"]
    is_encrypted = paste["is_encrypted"]
    language = paste["language"] or ""
    created = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(paste["created_at"]))

    if is_encrypted:
        # show decrypt form instead of content
        content_block = f"""
        <form id="decrypt-form">
            <p>this paste is password-protected.</p>
            <input type="password" id="decrypt-pass" placeholder="passphrase" required>
            <button type="submit" id="decrypt-btn">decrypt</button>
            <span id="decrypt-status" style="margin-left:0.5rem;"></span>
        </form>
        <div id="paste-content" style="display:none;"></div>
        <script>
        document.getElementById("decrypt-form").addEventListener("submit", async function(e) {{
            e.preventDefault();
            const btn = document.getElementById("decrypt-btn");
            const status = document.getElementById("decrypt-status");
            const pass = document.getElementById("decrypt-pass").value;
            btn.disabled = true;
            btn.textContent = "--->";
            status.textContent = "decrypting...";
            const resp = await fetch("/api/decrypt", {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify({{id: "{paste_id}", passphrase: pass}})
            }});
            const data = await resp.json();
            if (data.error) {{
                alert(data.error);
                btn.disabled = false;
                btn.textContent = "decrypt";
                status.textContent = "";
                return;
            }}
            status.textContent = "decrypted.";
            document.getElementById("decrypt-form").style.display = "none";
            const el = document.getElementById("paste-content");
            el.style.display = "block";
            {"" if not is_code else f'''
            const codeEl = document.createElement("pre");
            const codeInner = document.createElement("code");
            codeInner.className = "{("language-" + language) if language else ""}";
            codeInner.textContent = data.content;
            codeEl.appendChild(codeInner);
            el.appendChild(codeEl);
            hljs.highlightElement(codeInner);
            '''}
            {"" if is_code else '''
            const pre = document.createElement("pre");
            pre.textContent = data.content;
            el.appendChild(pre);
            '''}
            // update copy button
            document.getElementById("copy-btn").onclick = function() {{
                copyPaste();
            }};
            // keep decrypted text in a runtime-only container for copy.
            el.dataset.decryptedContent = data.content;
        }});
        </script>"""
    else:
        escaped = html_escape(content)
        if is_code:
            lang_class = f'class="language-{language}"' if language else ""
            content_block = (
                f'<pre><code id="paste-code" {lang_class}>{escaped}</code></pre>'
            )
        else:
            content_block = f'<pre id="paste-plain">{escaped}</pre>'

    highlight_css = ""
    highlight_js = ""
    if is_code:
        highlight_css = '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/vs2015.min.css">'
        highlight_js = """<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script>hljs.highlightAll();</script>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <meta name="robots" content="noindex, nofollow">
    <title>kj-clipboard - {paste_id}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kj-sh604/noir.css@latest/out/noir.min.css">
    {highlight_css}
</head>
<body>
    <h1><a href="/" style="text-decoration:none;color:inherit;">kj-clipboard</a></h1>
    <p class="meta">created {created}{(" · " + language) if language else ""}{" · encrypted" if is_encrypted else ""}</p>
    <div class="actions">
        <button id="copy-btn" onclick="copyPaste()">copy to clipboard</button>
        <a href="/raw/{paste_id}">raw</a>
    </div>
    {content_block}
    {highlight_js}
    <script>
    function copyPaste() {{
        const btn = document.getElementById("copy-btn");
        let text = "";

        const decryptedWrap = document.getElementById("paste-content");
        if (decryptedWrap && decryptedWrap.dataset && decryptedWrap.dataset.decryptedContent) {{
            text = decryptedWrap.dataset.decryptedContent;
        }} else {{
            const code = document.getElementById("paste-code");
            const plain = document.getElementById("paste-plain");
            if (code) {{
                text = code.textContent || "";
            }} else if (plain) {{
                text = plain.textContent || "";
            }}
        }}

        if (!text) {{
            btn.textContent = "nothing to copy";
            setTimeout(() => btn.textContent = "copy to clipboard", 1500);
            return;
        }}

        navigator.clipboard.writeText(text);
        btn.textContent = "copied!";
        setTimeout(() => btn.textContent = "copy to clipboard", 1500);
    }}
    </script>
</body>
</html>"""


def not_found_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <title>kj-clipboard - not found</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kj-sh604/noir.css@latest/out/noir.min.css">
</head>
<body>
    <h1><a href="/" style="text-decoration:none;color:inherit;">kj-clipboard</a></h1>
    <p>paste not found.</p>
</body>
</html>"""


# helpers


def html_escape(text):
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def html_escape_attr(text):
    return html_escape(text).replace("\n", "&#10;").replace("\r", "&#13;")


def normalize_language(value):
    """normalize and validate highlight.js language token"""
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    lang = value.strip().lower()
    if not lang:
        return None
    if len(lang) > MAX_LANGUAGE_SIZE:
        return None
    if not LANGUAGE_PATTERN.match(lang):
        return None
    if lang not in ALLOWED_LANGUAGES:
        return None
    return lang


def get_client_ip(handler):
    """use x-forwarded-for first when present (nginx reverse proxy)"""
    xff = handler.headers.get("X-Forwarded-For", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return handler.client_address[0]


def is_rate_limited(client_ip):
    """fixed window limiter for POST endpoints"""
    now = int(time.time())
    window = now // RATE_WINDOW_SECONDS

    with _rate_lock:
        key = (client_ip, window)
        count = _rate_state.get(key, 0) + 1
        _rate_state[key] = count

        # cheap cleanup to avoid unbounded growth
        stale_before = window - 2
        stale_keys = [k for k in _rate_state if k[1] < stale_before]
        for k in stale_keys:
            _rate_state.pop(k, None)

    return count > REQUESTS_PER_WINDOW


# request handler


class ClipboardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        client_ip = get_client_ip(self)
        sys.stderr.write(
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {client_ip} - {fmt % args}\n"
        )

    def add_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "interest-cohort=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        # CSP allows required CDNs and inline scripts currently used in templates.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'",
        )

    def send_html(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.add_security_headers()
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, code, obj):
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.add_security_headers()
        self.end_headers()
        self.wfile.write(data)

    def send_plain(self, code, text):
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.add_security_headers()
        self.end_headers()
        self.wfile.write(data)

    def read_body(self, max_size):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > max_size:
            return None
        return self.rfile.read(length)

    def read_json_body(self, max_size):
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return None
        body = self.read_body(max_size)
        if body is None:
            return None
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        return data

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = unquote(parsed.path).rstrip("/") or "/"

            if path == "/healthz":
                self.send_plain(200, "ok")
                return

            if path == "/":
                self.send_html(200, landing_page())
                return

            if path == "/main.js":
                js_path = BASE_DIR / "main.js"
                if not js_path.exists():
                    self.send_plain(404, "not found")
                    return
                data = js_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.add_security_headers()
                self.end_headers()
                self.wfile.write(data)
                return

            if path.startswith("/raw/"):
                paste_id = path[5:]
                if not is_valid_paste_id(paste_id):
                    self.send_plain(404, "not found")
                    return
                paste = get_paste(paste_id)
                if not paste:
                    self.send_plain(404, "not found")
                    return
                if paste["is_encrypted"]:
                    self.send_plain(
                        403,
                        "403: this paste is encrypted; raw view is not available - use the web interface to decrypt and view the content",
                    )
                    return
                self.send_plain(200, paste["content"])
                return

            # treat anything else as a paste id
            paste_id = path.lstrip("/")
            if not is_valid_paste_id(paste_id):
                self.send_html(404, not_found_page())
                return

            paste = get_paste(paste_id)
            if not paste:
                self.send_html(404, not_found_page())
                return

            self.send_html(200, paste_page(paste))
        except Exception:
            self.send_json(500, {"error": "internal server error"})

    def do_POST(self):
        try:
            client_ip = get_client_ip(self)
            if is_rate_limited(client_ip):
                self.send_json(429, {"error": "rate limit exceeded"})
                return

            parsed = urlparse(self.path)
            path = unquote(parsed.path)

            if path == "/api/paste":
                self.handle_create_paste()
            elif path == "/api/decrypt":
                self.handle_decrypt()
            else:
                self.send_json(404, {"error": "not found"})
        except Exception:
            self.send_json(500, {"error": "internal server error"})

    def handle_create_paste(self):
        data = self.read_json_body(MAX_PASTE_SIZE)
        if data is None:
            self.send_json(400, {"error": "invalid request"})
            return

        content = data.get("content", "")
        if not isinstance(content, str):
            self.send_json(400, {"error": "content is required"})
            return

        # preserve exact content while blocking empty/oversized payloads
        if not content.strip():
            self.send_json(400, {"error": "content is required"})
            return
        if len(content.encode("utf-8")) > MAX_PASTE_SIZE:
            self.send_json(413, {"error": "paste too large (max 6.7 MiB)"})
            return

        is_code = bool(data.get("is_code", False))
        language = normalize_language(data.get("language", ""))
        passphrase = data.get("passphrase", "")
        if passphrase is None:
            passphrase = ""
        if not isinstance(passphrase, str):
            self.send_json(400, {"error": "invalid passphrase"})
            return
        passphrase = passphrase.strip()
        if len(passphrase.encode("utf-8")) > MAX_PASSPHRASE_SIZE:
            self.send_json(400, {"error": "passphrase too long"})
            return

        if data.get("language", "") and language is None:
            self.send_json(400, {"error": "invalid language name"})
            return

        is_encrypted = False
        store_content = content

        if passphrase:
            encrypted = mojicrypt_encrypt(content, passphrase)
            if encrypted is None:
                self.send_json(
                    500, {"error": "encryption failed - is mojicrypt installed?"}
                )
                return
            store_content = encrypted
            is_encrypted = True

        paste_id = save_paste(
            content=store_content,
            language=language,
            is_code=is_code,
            is_encrypted=is_encrypted,
        )

        self.send_json(200, {"id": paste_id, "url": f"/{paste_id}"})

    def handle_decrypt(self):
        data = self.read_json_body(MAX_DECRYPT_SIZE)
        if data is None:
            self.send_json(400, {"error": "invalid request"})
            return

        paste_id = data.get("id", "")
        passphrase = data.get("passphrase", "")

        if not isinstance(paste_id, str) or not isinstance(passphrase, str):
            self.send_json(400, {"error": "id and passphrase are required"})
            return
        passphrase = passphrase.strip()
        if len(passphrase.encode("utf-8")) > MAX_PASSPHRASE_SIZE:
            self.send_json(400, {"error": "passphrase too long"})
            return

        if not paste_id or not passphrase:
            self.send_json(400, {"error": "id and passphrase are required"})
            return

        if not is_valid_paste_id(paste_id):
            self.send_json(404, {"error": "paste not found"})
            return

        paste = get_paste(paste_id)
        if not paste:
            self.send_json(404, {"error": "paste not found"})
            return

        if not paste["is_encrypted"]:
            self.send_json(400, {"error": "paste is not encrypted"})
            return

        plaintext = mojicrypt_decrypt(paste["content"], passphrase)
        if plaintext is None:
            self.send_json(403, {"error": "wrong passphrase or corrupted data"})
            return

        self.send_json(200, {"content": plaintext})


# main


class ClipboardHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    init_db()
    print(f"kj-clipboard - listening on {BIND}:{PORT}")

    server = ClipboardHTTPServer((BIND, PORT), ClipboardHandler)
    shutdown_requested = threading.Event()

    def request_shutdown(msg):
        if shutdown_requested.is_set():
            return
        shutdown_requested.set()
        print(msg)
        # shutdown() should run outside the serving thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    def _shutdown_handler(signum, _frame):
        request_shutdown(f"\nreceived signal {signum}, shutting down.")

    signal.signal(signal.SIGTERM, _shutdown_handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nreceived keyboard interrupt, shutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
