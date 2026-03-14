FROM python:3.13-alpine AS builder

RUN apk add --no-cache git make \
    && git clone --depth=1 https://github.com/kj-sh604/mojicrypt /tmp/mojicrypt \
    && make -C /tmp/mojicrypt install PREFIX=/usr/local


FROM python:3.13-alpine

RUN pip install --no-cache-dir pycryptodome

COPY --from=builder /usr/local/bin/mojicrypt /usr/local/bin/mojicrypt

WORKDIR /app

COPY . .

RUN mkdir -p /app/src/data \
    && adduser -D appuser && chown -R appuser:appuser /app

EXPOSE 5555

USER appuser

CMD ["python3", "src/server.py"]
