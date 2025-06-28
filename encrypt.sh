#!/bin/bash
KEEY="1234567812345678"  # 16-byte AES key
PLAINTEXT=$1  # explain: "exec:shutdown /s /t 0"

# how to use:
# ./encrypt.sh "exec:shutdown /s /t 0"

echo "[*] Buyruq: $PLAINTEXT"

echo -n "$PLAINTEXT" | \
openssl enc -aes-128-ecb -K $(echo -n "$KEEY" | xxd -p) -nosalt -base64
