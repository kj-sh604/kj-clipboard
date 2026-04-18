#!/usr/bin/env python3

# kj-clipboard server, no frills public clipboard
# single-file server: sqlite, mojicrypt encryption, syntax highlighting
# usage: python3 src/server.py

import http.server
import json
import ipaddress
import queue
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

PORT = 5555
BIND = "0.0.0.0"
BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / "data" / "kj-clipboard.db"
RANDOM_ID_LENGTH = 40  # random chars after unix epoch
MAX_PASTE_SIZE = 67 * 1024 * 1024 // 10  # 6.7 MiB
MAX_PASSPHRASE_SIZE = 512
MAX_LANGUAGE_SIZE = 32
# decrypt requests only need id+passphrase json, keep this small against body-flood abuse.
MAX_DECRYPT_SIZE = 16 * 1024
ID_PATTERN = re.compile(r"^[0-9]{10,}[a-f0-9]{40}$")
LANGUAGE_PATTERN = re.compile(r"^[a-z0-9_.+#-]{1,32}$")

# per-ip post limit (create/decrypt).
REQUESTS_PER_WINDOW = 150
RATE_WINDOW_SECONDS = 60

# sqlite concurrency defaults
SQLITE_BUSY_TIMEOUT_MS = 2500
SQLITE_WRITE_RETRIES = 5
SQLITE_READ_RETRIES = 3
SQLITE_RETRY_BASE_MS = 20
SQLITE_CACHE_SIZE_KIB = 6144
SQLITE_MMAP_SIZE_BYTES = 134217728
SQLITE_WAL_AUTOCHECKPOINT_PAGES = 2000
SQLITE_JOURNAL_SIZE_LIMIT_BYTES = 67108864
SQLITE_SYNCHRONOUS = "NORMAL"  # OFF | NORMAL | FULL | EXTRA

# accept short bursts without immediately refusing tcp connections.
HTTP_REQUEST_QUEUE_SIZE = 64

# single sqlite writer with queue + micro-batching reduces lock contention under load.
WRITE_QUEUE_MAX_SIZE = 4096
WRITE_QUEUE_WAIT_SECONDS = 8
WRITE_QUEUE_ENQUEUE_TIMEOUT_SECONDS = 0.25
WRITE_BATCH_SIZE = 32
WRITE_BATCH_MAX_DELAY_MS = 12
WRITE_WORKER_JOIN_TIMEOUT_SECONDS = 5

TRUST_PROXY = False
TRUSTED_PROXY_IPS = {"127.0.0.1", "::1"}
# hsts off by default to avoid breaking plain-http setups.
ENABLE_HSTS = False
HSTS_MAX_AGE = 31536000

ALLOWED_LANGUAGES = {
    "1c",
    "abnf",
    "accesslog",
    "actionscript",
    "ada",
    "angelscript",
    "apache",
    "applescript",
    "arcade",
    "arduino",
    "armasm",
    "xml",
    "asciidoc",
    "aspectj",
    "autohotkey",
    "autoit",
    "avrasm",
    "awk",
    "axapta",
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
    "markdown",
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
    "ruby",
    "erb",
    "erlang-repl",
    "erlang",
    "excel",
    "fix",
    "flix",
    "fsharp",
    "fortran",
    "gcode",
    "gams",
    "gauss",
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
    "mathematica",
    "matlab",
    "maxima",
    "mel",
    "mercury",
    "mipsasm",
    "mizar",
    "perl",
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
    "pf",
    "pgsql",
    "php",
    "php-template",
    "plaintext",
    "pony",
    "powershell",
    "processing",
    "prolog",
    "properties",
    "protobuf",
    "puppet",
    "purebasic",
    "python",
    "profile",
    "python-repl",
    "q",
    "qml",
    "r",
    "reasonml",
    "rib",
    "roboconf",
    "routeros",
    "rsl",
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
    "yaml",
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
    "xquery",
    "zephir",

}


# in-memory fixed-window rate limiter (cheap guardrail behind nginx)
_rate_lock = threading.Lock()
_rate_state = {}

_write_queue = queue.Queue(maxsize=WRITE_QUEUE_MAX_SIZE)
_write_worker_thread = None
_write_worker_stop = threading.Event()


# database


class DatabaseBusyError(RuntimeError):
    pass


def is_sqlite_busy_error(err):
    msg = str(err).lower()
    return "database is locked" in msg or "database is busy" in msg


def sqlite_retry_sleep(attempt):
    delay_ms = SQLITE_RETRY_BASE_MS * (2**attempt)
    jitter_ms = secrets.randbelow(SQLITE_RETRY_BASE_MS + 1)
    time.sleep(min((delay_ms + jitter_ms) / 1000.0, 1.0))


def build_write_job(content, language, is_code, is_encrypted):
    return {
        "content": content,
        "language": language,
        "is_code": int(is_code),
        "is_encrypted": int(is_encrypted),
        "created_at": int(time.time()),
        "paste_id": None,
        "error": None,
        "done": threading.Event(),
    }


def execute_write_batch(conn, jobs):
    for write_attempt in range(SQLITE_WRITE_RETRIES + 1):
        try:
            conn.execute("BEGIN IMMEDIATE")
            for job in jobs:
                for _ in range(5):
                    paste_id = generate_id()
                    try:
                        conn.execute(
                            "INSERT INTO pastes (id, content, language, is_code, is_encrypted, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                paste_id,
                                job["content"],
                                job["language"],
                                job["is_code"],
                                job["is_encrypted"],
                                job["created_at"],
                            ),
                        )
                        job["paste_id"] = paste_id
                        break
                    except sqlite3.IntegrityError:
                        continue
                if not job["paste_id"]:
                    raise RuntimeError("failed to generate unique paste id")

            conn.commit()
            return
        except sqlite3.OperationalError as err:
            try:
                conn.rollback()
            except sqlite3.DatabaseError:
                pass

            if is_sqlite_busy_error(err):
                if write_attempt >= SQLITE_WRITE_RETRIES:
                    raise DatabaseBusyError("database is busy; retry shortly") from err
                sqlite_retry_sleep(write_attempt)
                continue

            raise
        except Exception:
            try:
                conn.rollback()
            except sqlite3.DatabaseError:
                pass
            raise


def flush_write_batch(conn, jobs):
    try:
        execute_write_batch(conn, jobs)
    except Exception as err:
        for job in jobs:
            job["error"] = err
            job["done"].set()
        return

    for job in jobs:
        job["done"].set()


def collect_write_batch(first_job):
    jobs = [first_job]
    deadline = time.monotonic() + (WRITE_BATCH_MAX_DELAY_MS / 1000.0)

    while len(jobs) < WRITE_BATCH_SIZE:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        try:
            next_job = _write_queue.get(timeout=remaining)
        except queue.Empty:
            break

        jobs.append(next_job)

    return jobs


def write_worker_loop():
    conn = open_db()
    try:
        while True:
            if _write_worker_stop.is_set() and _write_queue.empty():
                break

            try:
                first_job = _write_queue.get(timeout=0.25)
            except queue.Empty:
                continue

            jobs = collect_write_batch(first_job)
            flush_write_batch(conn, jobs)
            for _ in jobs:
                _write_queue.task_done()
    finally:
        conn.close()


def start_write_worker():
    global _write_worker_thread

    if _write_worker_thread and _write_worker_thread.is_alive():
        return

    _write_worker_stop.clear()
    _write_worker_thread = threading.Thread(
        target=write_worker_loop,
        daemon=True,
        name="sqlite-write-worker",
    )
    _write_worker_thread.start()


def stop_write_worker():
    global _write_worker_thread

    if not _write_worker_thread:
        return

    _write_worker_stop.set()
    _write_worker_thread.join(timeout=WRITE_WORKER_JOIN_TIMEOUT_SECONDS)
    _write_worker_thread = None


def open_db():
    conn = sqlite3.connect(
        str(DB_PATH),
        timeout=SQLITE_BUSY_TIMEOUT_MS / 1000.0,
    )
    conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA cache_size=-{SQLITE_CACHE_SIZE_KIB}")
    conn.execute("PRAGMA temp_store=MEMORY")
    if SQLITE_MMAP_SIZE_BYTES > 0:
        try:
            conn.execute(f"PRAGMA mmap_size={SQLITE_MMAP_SIZE_BYTES}")
        except sqlite3.DatabaseError:
            pass
    # defense-in-depth: ignore if running on an older sqlite without this pragma.
    try:
        conn.execute("PRAGMA trusted_schema=OFF")
    except sqlite3.DatabaseError:
        pass
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA synchronous={SQLITE_SYNCHRONOUS}")
    conn.execute(f"PRAGMA wal_autocheckpoint={SQLITE_WAL_AUTOCHECKPOINT_PAGES}")
    conn.execute(f"PRAGMA journal_size_limit={SQLITE_JOURNAL_SIZE_LIMIT_BYTES}")
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
    job = build_write_job(content, language, is_code, is_encrypted)

    try:
        _write_queue.put(job, timeout=WRITE_QUEUE_ENQUEUE_TIMEOUT_SECONDS)
    except queue.Full as err:
        raise DatabaseBusyError("write queue is full; retry shortly") from err

    if not job["done"].wait(WRITE_QUEUE_WAIT_SECONDS):
        raise DatabaseBusyError("write queue timeout; retry shortly")

    if job["error"]:
        if isinstance(job["error"], Exception):
            raise job["error"]
        raise RuntimeError("write failed")

    if not job["paste_id"]:
        raise RuntimeError("write completed without paste id")

    return job["paste_id"]


def get_paste(paste_id):
    """retrieve a paste by id, returns dict or None"""
    for read_attempt in range(SQLITE_READ_RETRIES + 1):
        conn = open_db()
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()
            if row:
                return sanitize_paste_record(dict(row))
            return None
        except sqlite3.OperationalError as err:
            if is_sqlite_busy_error(err):
                if read_attempt >= SQLITE_READ_RETRIES:
                    raise DatabaseBusyError("database is busy; retry shortly") from err
                sqlite_retry_sleep(read_attempt)
                continue
            raise
        finally:
            conn.close()

    raise DatabaseBusyError("database is busy; retry shortly")


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


def paste_page(paste, csp_nonce):
    """render the view page for a paste"""
    paste_id = paste["id"]
    content = paste["content"]
    is_code = coerce_bool_flag(paste.get("is_code", 0))
    is_encrypted = coerce_bool_flag(paste.get("is_encrypted", 0))
    language = normalize_language(paste.get("language", "")) or ""
    created = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(paste["created_at"])))

    escaped_paste_id = html_escape(paste_id)
    escaped_paste_id_attr = html_escape_attr(paste_id)
    escaped_language = html_escape(language)

    paste_id_json = json.dumps(paste_id)
    code_lang_class = f"language-{language}" if language else ""
    code_lang_class_json = json.dumps(code_lang_class)

    script_nonce_attr = f' nonce="{html_escape_attr(csp_nonce)}"'

    if is_encrypted:
        # show decrypt form instead of content
        content_block = f"""
        <form id="decrypt-form">
            <p>this paste is password-protected.</p>
            <input type="password" id="decrypt-pass" placeholder="passphrase" autocomplete="off" required>
            <button type="submit" id="decrypt-btn">decrypt</button>
            <span id="decrypt-status" style="margin-left:0.5rem;"></span>
        </form>
        <div id="paste-content" style="display:none;"></div>
        <script{script_nonce_attr}>
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
                body: JSON.stringify({{id: {paste_id_json}, passphrase: pass}})
            }});
            let data = null;
            try {{
                data = await resp.json();
            }} catch (_err) {{
                btn.disabled = false;
                btn.textContent = "decrypt";
                status.textContent = "";
                alert("decrypt request failed");
                return;
            }}
            if (!resp.ok || data.error) {{
                alert(data && data.error ? data.error : "decrypt failed");
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
            codeInner.className = {code_lang_class_json};
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
            // keep decrypted text in a runtime-only container for copy.
            el.dataset.decryptedContent = data.content;
        }});
        </script>"""
    else:
        escaped = html_escape(content)
        if is_code:
            lang_class = f'class="language-{html_escape_attr(language)}"' if language else ""
            content_block = (
                f'<pre><code id="paste-code" {lang_class}>{escaped}</code></pre>'
            )
        else:
            content_block = f'<pre id="paste-plain">{escaped}</pre>'

    highlight_css = ""
    highlight_js = ""
    if is_code:
        highlight_css = '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.11.1/styles/vs2015.min.css">'
        highlight_js = f"""<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.11.1/highlight.min.js"></script>
    <script{script_nonce_attr}>hljs.highlightAll();</script>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <meta name="robots" content="noindex, nofollow">
    <title>kj-clipboard - {escaped_paste_id}</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kj-sh604/noir.css@latest/out/noir.min.css">
    {highlight_css}
</head>
<body>
    <h1><a href="/" style="text-decoration:none;color:inherit;">kj-clipboard</a></h1>
    <p class="meta">created {created}{(" · " + escaped_language) if language else ""}{" · encrypted" if is_encrypted else ""}</p>
    <div class="actions">
        <button id="copy-btn" type="button">copy to clipboard</button>
        <a href="/raw/{escaped_paste_id_attr}">raw</a>
    </div>
    {content_block}
    {highlight_js}
    <script{script_nonce_attr}>
    async function copyPaste() {{
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

        try {{
            await navigator.clipboard.writeText(text);
            btn.textContent = "copied!";
        }} catch (_err) {{
            btn.textContent = "copy failed";
        }}
        setTimeout(() => btn.textContent = "copy to clipboard", 1500);
    }}
    document.getElementById("copy-btn").addEventListener("click", copyPaste);
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
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kj-sh604/noir.css@latest/out/noir.min.css">
</head>
<body>
    <h1><a href="/" style="text-decoration:none;color:inherit;">kj-clipboard</a></h1>
    <p>paste not found.</p>
</body>
</html>"""


# helpers


def html_escape(text):
    text = str(text)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def html_escape_attr(text):
    return html_escape(text).replace("\n", "&#10;").replace("\r", "&#13;")


def generate_csp_nonce():
    return secrets.token_urlsafe(18)


def coerce_bool_flag(value):
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return bool(value)


def sanitize_paste_record(row):
    if not isinstance(row, dict):
        return None

    paste_id = row.get("id")
    if not isinstance(paste_id, str) or not is_valid_paste_id(paste_id):
        return None

    content = row.get("content")
    if not isinstance(content, str):
        return None

    language = normalize_language(row.get("language", "")) or ""
    is_code = coerce_bool_flag(row.get("is_code", 0))
    is_encrypted = coerce_bool_flag(row.get("is_encrypted", 0))

    try:
        created_at = int(row.get("created_at", 0))
    except (TypeError, ValueError):
        created_at = 0

    now = int(time.time())
    if created_at < 0:
        created_at = 0
    if created_at > now + 315360000:
        created_at = now

    if not is_code:
        language = ""

    return {
        "id": paste_id,
        "content": content,
        "language": language,
        "is_code": int(is_code),
        "is_encrypted": int(is_encrypted),
        "created_at": created_at,
    }


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
    if lang in {"ls", "ml"}:
        return None
    if not LANGUAGE_PATTERN.match(lang):
        return None
    if lang not in ALLOWED_LANGUAGES:
        return None
    return lang


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_client_ip(handler):
    """resolve client ip safely, only trusting proxy headers when configured"""
    remote_ip = handler.client_address[0]

    if not TRUST_PROXY or remote_ip not in TRUSTED_PROXY_IPS:
        return remote_ip

    xff = handler.headers.get("X-Forwarded-For", "").strip()
    if xff:
        candidate = xff.split(",")[0].strip()
        if is_valid_ip(candidate):
            return candidate

    xri = handler.headers.get("X-Real-IP", "").strip()
    if xri and is_valid_ip(xri):
        return xri

    return remote_ip


def is_same_origin_post(handler):
    # block cross-site browser requests while allowing non-browser clients.
    sec_fetch_site = handler.headers.get("Sec-Fetch-Site", "").strip().lower()
    if sec_fetch_site == "cross-site":
        return False

    origin = handler.headers.get("Origin", "").strip()
    if not origin:
        return True

    host = handler.headers.get("Host", "").strip().lower()
    if not host:
        return False

    try:
        parsed_origin = urlparse(origin)
    except ValueError:
        return False

    if parsed_origin.scheme not in {"http", "https"}:
        return False

    return secrets.compare_digest(parsed_origin.netloc.lower(), host)


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
    server_version = "kj-clipboard"
    sys_version = ""

    def log_message(self, fmt, *args):
        client_ip = get_client_ip(self)
        sys.stderr.write(
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {client_ip} - {fmt % args}\n"
        )

    def add_security_headers(self, csp_nonce=None):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), gyroscope=(), magnetometer=(), payment=(), usb=()",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")

        if ENABLE_HSTS and HSTS_MAX_AGE > 0:
            self.send_header(
                "Strict-Transport-Security",
                f"max-age={HSTS_MAX_AGE}; includeSubDomains",
            )

        script_sources = ["'self'", "https://cdnjs.cloudflare.com"]
        if csp_nonce:
            script_sources.append(f"'nonce-{csp_nonce}'")

        # keep style-src permissive due inline styles and the shared theme css.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            f"script-src {' '.join(script_sources)}; img-src 'self' data:; connect-src 'self'; "
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'",
        )

    def send_html(self, code, body, csp_nonce=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.add_security_headers(csp_nonce=csp_nonce)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, code, obj):
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
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

            if path == "/favicon.svg":
                icon_path = BASE_DIR / "favicon.svg"
                if not icon_path.exists():
                    self.send_plain(404, "not found")
                    return
                data = icon_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
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

            csp_nonce = generate_csp_nonce()
            self.send_html(200, paste_page(paste, csp_nonce), csp_nonce=csp_nonce)
        except DatabaseBusyError:
            self.send_plain(503, "service busy, retry shortly")
        except Exception:
            self.send_json(500, {"error": "internal server error"})

    def do_POST(self):
        try:
            if not is_same_origin_post(self):
                self.send_json(403, {"error": "cross-origin request blocked"})
                return

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
        except DatabaseBusyError:
            self.send_json(503, {"error": "database busy, retry shortly"})
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
    request_queue_size = HTTP_REQUEST_QUEUE_SIZE


def main():
    init_db()
    start_write_worker()
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
        stop_write_worker()
        server.server_close()


if __name__ == "__main__":
    main()
