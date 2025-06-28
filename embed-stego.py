import base64
from PIL import Image
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
import shutil

def embed_png(input_image, output_image, secret_data):
    secret_data += "EOF"
    binary_data = ''.join([format(ord(i), '08b') for i in secret_data])
    img = Image.open(input_image)
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
    print(f"[PNG] : {output_image}")

def embed_mp3(input_file, output_file, secret_data):
    shutil.copy(input_file, output_file)
    audio = MP3(output_file, ID3=EasyID3)
    audio['comment'] = secret_data
    audio.save()
    print(f"[MP3] : {output_file}")

def embed_mp4(input_file, output_file, secret_data):
    with open(input_file, "rb") as f:content = f.read()
    tag = f"\nHIDDEN_CMD:{secret_data}\n".encode()
    with open(output_file, "wb") as f:f.write(content + tag)
    print(f"[MP4] : {output_file}")

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
        epilog="Example: python3 embed_stego.py -f png -i clear.png -o stego.png -s ZXhlYzpzaHV0ZG93biAvcyAvdCAw",
        add_help=True
    )
    parser.add_argument("-f", "--format", type=str, help="Format: png / mp3 / mp4", required=False)
    parser.add_argument("-i", "--input", type=str, help="Input media file", required=False)
    parser.add_argument("-o", "--output", type=str, help="Output stego file", required=False)
    parser.add_argument("-s", "--secret", type=str, help="AES+base64 encoded secret payload", required=False)

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
    else:print(" Not correct format . only: png, mp3, mp4")

if __name__ == "__main__":
    main()
