# kj-clipboard

no frills, just a public clipboard on the internet that you can use to share snippets around. that's it.

## features

- paste text, get a shareable link
- syntax highlighting (highlight.js) with language selection
- password-protect pastes with [mojicrypt](https://github.com/kj-sh604/mojicrypt) (emojified aes-256-gcm)
- copy to clipboard
- raw paste view (for snippets with no encryption)
- sqlite 🐐
- single-file python server, no frameworks, no bloat

## dependencies

- python 3.12+
- [mojicrypt](https://github.com/kj-sh604/mojicrypt) (optional, only needed for encrypted pastes)

## run

```sh
python3 src/server.py
```

## config

all runtime/security/sqlite values are edited directly in `src/server.py` under `# config`.

- sqlite wal + retry/backoff enabled
- moderate post rate-limit (`150/min` per ip)
- hsts disabled by default (safe for non-https setups)

if you terminate tls at nginx/caddy, enable hsts by setting `ENABLE_HSTS = True`.

## docker

```sh
docker build -t kj-clipboard .
docker run -p 5555:5555 -v kj-clipboard-data:/app/src/data kj-clipboard
```

## screenshot

it looks exactly how you'd expect, a textarea and a button.

![screenshot](https://kj-media.online/pics/kj-clipboard-ss/ss.png)

## license

MIT