const FORM_STATE_KEY = "kj-clipboard-form-state-v1";

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
        const data = await resp.json();
        if (data.error) {
            setStatus("error: " + data.error);
            btn.disabled = false;
            btn.textContent = "generate link";
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
    }
    btn.disabled = false;
    btn.textContent = "generate link";
}

function copyLink() {
    const url = document.getElementById("result-link").textContent;
    navigator.clipboard.writeText(url);
}

function setStatus(msg) {
    document.getElementById("status").textContent = msg;
}

restoreFormState();

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
