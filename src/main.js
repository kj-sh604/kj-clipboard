const FORM_STATE_KEY = "kj-clipboard-form-state-v1";

const HIGHLIGHTJS_LANGUAGES = [
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
    "html",
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
];

function syncLanguageOptions() {
    const langSelect = document.getElementById("lang-select");
    const selected = langSelect.value;

    langSelect.innerHTML = "";

    const autoOption = document.createElement("option");
    autoOption.value = "";
    autoOption.textContent = "(auto)";
    langSelect.appendChild(autoOption);

    for (const language of HIGHLIGHTJS_LANGUAGES) {
        const option = document.createElement("option");
        option.value = language;
        option.textContent = language;
        langSelect.appendChild(option);
    }

    if (selected && HIGHLIGHTJS_LANGUAGES.includes(selected)) {
        langSelect.value = selected;
    }
}

function saveFormState() {
    const state = {
        content: document.getElementById("content").value,
        isCode: document.getElementById("is-code").checked,
        language: document.getElementById("lang-select").value,
    };
    sessionStorage.setItem(FORM_STATE_KEY, JSON.stringify(state));
}

function restoreFormState() {
    const raw = sessionStorage.getItem(FORM_STATE_KEY);
    if (!raw) {
        toggleLang();
        return;
    }
    try {
        const state = JSON.parse(raw);
        document.getElementById("content").value =
            typeof state.content === "string" ? state.content : "";
        document.getElementById("is-code").checked = !!state.isCode;
        const langSelect = document.getElementById("lang-select");
        if (typeof state.language === "string") {
            const langExists = Array.from(langSelect.options).some(
                (opt) => opt.value === state.language
            );
            langSelect.value = langExists ? state.language : "";
        }
    } catch (_err) {
        sessionStorage.removeItem(FORM_STATE_KEY);
    }
    toggleLang();
}

function toggleLang() {
    const sel = document.getElementById("lang-select");
    sel.style.display = document.getElementById("is-code").checked
        ? "inline-block"
        : "none";
    saveFormState();
}

async function createPaste() {
    const content = document.getElementById("content").value.trim();
    if (!content) {
        setStatus("nothing to paste.");
        return;
    }
    const btn = document.getElementById("get-link-btn");
    btn.disabled = true;
    btn.textContent = "generating...";
    setStatus("");
    const body = {
        content: content,
        is_code: document.getElementById("is-code").checked,
        language: document.getElementById("lang-select").value,
        passphrase: document.getElementById("passphrase").value,
    };
    try {
        const resp = await fetch("/api/paste", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        let data = null;
        try {
            data = await resp.json();
        } catch (_err) {
            setStatus("error: invalid server response");
            return;
        }

        if (!resp.ok || !data || data.error || typeof data.url !== "string") {
            const msg = data && data.error ? data.error : "request failed";
            setStatus("error: " + msg);
            return;
        }

        const url = window.location.origin + data.url;
        const linkEl = document.getElementById("result-link");
        linkEl.href = url;
        linkEl.textContent = url;
        document.getElementById("result").style.display = "block";
        setStatus("done.");
    } catch (e) {
        setStatus("error: " + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = "generate link";
    }
}

async function copyLink() {
    const url = document.getElementById("result-link").textContent;
    if (!url) {
        setStatus("nothing to copy.");
        return;
    }

    try {
        await navigator.clipboard.writeText(url);
        setStatus("link copied.");
    } catch (_err) {
        setStatus("error: clipboard copy failed");
    }
}

function setStatus(msg) {
    document.getElementById("status").textContent = msg;
}

syncLanguageOptions();
restoreFormState();

document.getElementById("get-link-btn").addEventListener("click", createPaste);
document.getElementById("copy-link-btn").addEventListener("click", function () {
    void copyLink();
});
document.getElementById("is-code").addEventListener("change", toggleLang);
document.getElementById("content").addEventListener("input", saveFormState);
document.getElementById("lang-select").addEventListener("change", saveFormState);

// allow tab key in textarea
document.getElementById("content").addEventListener("keydown", function (e) {
    if (e.key === "Tab") {
        e.preventDefault();
        const start = this.selectionStart;
        const end = this.selectionEnd;
        this.value =
            this.value.substring(0, start) + "\t" + this.value.substring(end);
        this.selectionStart = this.selectionEnd = start + 1;
        saveFormState();
    }
});
