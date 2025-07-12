import base64
from PIL import Image
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
##
KEY = b"1234567812345678"

def encrypt_payload(payload):
    ################Encrypt payload with AES and return base64#################
    cipher = AES.new(KEY, AES.MODE_ECB)
    padded_data = pad(payload.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode()

def embed_png(input_image, output_image, secret_data):
    
    encrypted_data = encrypt_payload(secret_data)
    encrypted_data += "EOF"
    binary_data = ''.join([format(ord(i), '08b') for i in encrypted_data])

    img = Image.open(input_image)
    if img.mode != 'RGB':img = img.convert('RGB')

    pixels = list(img.getdata())
    new_pixels = []
    data_index = 0

    for pixel in pixels:
        r, g, b = pixel[:3]
        if data_index < len(binary_data):
            r = (r & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            g = (g & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            b = (b & ~1) | int(binary_data[data_index])
            data_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_image)
    print(f"Embed completed: {output_image}")

from mutagen.id3 import ID3, COMM, ID3NoHeaderError

def embed_mp3(input_file, output_file, secret_data):
    # Encrypt the payload first
    encrypted_data = encrypt_payload(secret_data)
    
    shutil.copy(input_file, output_file)
    try:audio = ID3(output_file)
    except ID3NoHeaderError:audio = ID3()
    audio.add(COMM(encoding=3, lang='eng', desc='desc', text=encrypted_data))
    audio.save(output_file)
    print(f"MP3 Hiding completed: {output_file}")


def embed_mp4(input_file, output_file, secret_data):
    # Encrypt the payload first
    encrypted_data = encrypt_payload(secret_data)
    
    with open(input_file, "rb") as f:content = f.read()
    tag = f"HIDDEN_CMD:{encrypted_data}".encode()
    with open(output_file, "wb") as f:f.write(content + tag)
    print(f"MP4 Hiding completed: {output_file}")


import argparse
import sys

def main():
    banner = """
 MAI-SHADOW-exec(media-audio-images) 
 Shadow Stego Embedder (by Kamron Saparbayev, 2025)
 Supported formats: PNG, MP3, MP4
 AES-Encrypted Payloads | Steganography | Red Team Tools
"""
    parser = argparse.ArgumentParser(
        description="Shadow Stego Embedder: Hide AES-encrypted base64 payloads inside PNG, MP3, or MP4 files.",
        epilog="Example: python3 embed_stego.py -f png -i clear.png -o stego.png -s 'exec:shutdown /s /t 0'",
        add_help=True
    )
    parser.add_argument("-f", "--format", type=str, help="Format: png / mp3 / mp4", required=False)
    parser.add_argument("-i", "--input", type=str, help="Input media file", required=False)
    parser.add_argument("-o", "--output", type=str, help="Output stego file", required=False)
    parser.add_argument("-s", "--secret", type=str, help="Secret payload (will be AES encrypted)", required=False)

    args = parser.parse_args()
    
    if not any(vars(args).values()):
        print(banner)
        parser.print_help()
        sys.exit(0)

    ftype = args.format
    infile = args.input
    outfile = args.output
    secret = args.secret

    if not (ftype and infile and outfile and secret):
        print("Require all parameters!\n")
        parser.print_help()
        sys.exit(1)

    if ftype.lower() == "png":embed_png(infile, outfile, secret)
    elif ftype.lower() == "mp3":embed_mp3(infile, outfile, secret)
    elif ftype.lower() == "mp4":embed_mp4(infile, outfile, secret)
    else:print(" Not correct format oonly: png mp3 mp4")

if __name__ == "__main__":
    main()
