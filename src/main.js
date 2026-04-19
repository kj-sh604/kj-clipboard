const FORM_STATE_KEY = "kj-clipboard-form-state-v1";

const HIGHLIGHTJS_LANGUAGES = [
    "1c",
    "SAS",
    "abnf",
    "accesslog",
    "actionscript",
    "ada",
    "adoc",
    "angelscript",
    "apache",
    "apacheconf",
    "applescript",
    "arcade",
    "arduino",
    "arm",
    "armasm",
    "as",
    "asc",
    "asciidoc",
    "aspectj",
    "atom",
    "autohotkey",
    "autoit",
    "avrasm",
    "awk",
    "axapta",
    "bash",
    "basic",
    "bat",
    "bf",
    "bind",
    "bnf",
    "brainfuck",
    "c",
    "c++",
    "cal",
    "capnp",
    "capnproto",
    "cc",
    "clj",
    "clojure",
    "cls",
    "cmake",
    "cmake.in",
    "cmd",
    "coffee",
    "coffeescript",
    "console",
    "coq",
    "cos",
    "cpp",
    "cr",
    "craftcms",
    "crm",
    "crmsh",
    "crystal",
    "cs",
    "csharp",
    "cson",
    "csp",
    "css",
    "cts",
    "cxx",
    "d",
    "dart",
    "dfm",
    "diff",
    "django",
    "dns",
    "docker",
    "dockerfile",
    "dos",
    "dpr",
    "dsconfig",
    "dst",
    "dts",
    "dust",
    "ebnf",
    "elixir",
    "elm",
    "erl",
    "erlang",
    "excel",
    "f90",
    "f95",
    "fix",
    "fortran",
    "fs",
    "fsharp",
    "fsi",
    "fsscript",
    "fsx",
    "gams",
    "gauss",
    "gawk",
    "gcode",
    "gemspec",
    "gherkin",
    "glsl",
    "gms",
    "go",
    "golang",
    "golo",
    "gololang",
    "gradle",
    "graph",
    "graphql",
    "groovy",
    "gss",
    "gyp",
    "h",
    "h++",
    "haml",
    "handlebars",
    "haskell",
    "haxe",
    "hbs",
    "hh",
    "hpp",
    "hs",
    "html",
    "html.handlebars",
    "html.hbs",
    "http",
    "https",
    "hx",
    "hxx",
    "hy",
    "hylang",
    "i7",
    "iced",
    "inform7",
    "ini",
    "ino",
    "instances",
    "irb",
    "irpf90",
    "java",
    "javascript",
    "jinja",
    "jl",
    "js",
    "json",
    "jsp",
    "jsx",
    "julia",
    "julia-repl",
    "k",
    "kdb",
    "kotlin",
    "kt",
    "lasso",
    "lassoscript",
    "ldif",
    "leaf",
    "less",
    "lisp",
    "livecodeserver",
    "livescript",
    "lua",
    "mak",
    "make",
    "makefile",
    "markdown",
    "mathematica",
    "matlab",
    "mawk",
    "maxima",
    "md",
    "mel",
    "mercury",
    "mips",
    "mipsasm",
    "mizar",
    "mk",
    "mkd",
    "mkdown",
    "mm",
    "mma",
    "mojolicious",
    "monkey",
    "moon",
    "moonscript",
    "mts",
    "n1ql",
    "nawk",
    "nc",
    "nginx",
    "nginxconf",
    "nim",
    "nimrod",
    "nix",
    "nsis",
    "obj-c",
    "obj-c++",
    "objc",
    "objective-c++",
    "objectivec",
    "ocaml",
    "openscad",
    "osascript",
    "oxygene",
    "p21",
    "parser3",
    "pas",
    "pascal",
    "patch",
    "pcmk",
    "perl",
    "pf",
    "pf.conf",
    "pgsql",
    "php",
    "pl",
    "plaintext",
    "plist",
    "pm",
    "podspec",
    "pony",
    "postgres",
    "postgresql",
    "powershell",
    "pp",
    "processing",
    "profile",
    "prolog",
    "properties",
    "proto",
    "protobuf",
    "ps",
    "ps1",
    "puppet",
    "py",
    "pycon",
    "python",
    "python-repl",
    "qml",
    "r",
    "rb",
    "re",
    "reasonml",
    "rib",
    "rs",
    "rsl",
    "rss",
    "ruby",
    "ruleslanguage",
    "rust",
    "sas",
    "scad",
    "scala",
    "scheme",
    "sci",
    "scilab",
    "scss",
    "sh",
    "shell",
    "smali",
    "smalltalk",
    "sml",
    "sql",
    "st",
    "stan",
    "stanfuncs",
    "stata",
    "step",
    "stp",
    "styl",
    "stylus",
    "subunit",
    "svg",
    "swift",
    "tao",
    "tap",
    "tcl",
    "tex",
    "text",
    "thor",
    "thrift",
    "tk",
    "toml",
    "tp",
    "ts",
    "tsx",
    "twig",
    "txt",
    "typescript",
    "v",
    "vala",
    "vb",
    "vbnet",
    "vbs",
    "vbscript",
    "verilog",
    "vhdl",
    "vim",
    "wl",
    "x++",
    "x86asm",
    "xhtml",
    "xjb",
    "xl",
    "xls",
    "xlsx",
    "xml",
    "xpath",
    "xq",
    "xqm",
    "xquery",
    "xsd",
    "xsl",
    "yaml",
    "yml",
    "zep",
    "zephir",
    "zone",
    "zsh",
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
