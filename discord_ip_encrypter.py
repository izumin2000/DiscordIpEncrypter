import json
import re
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import hashlib
import requests
from time import sleep
from dateutil import parser
import re

DEBUG = True

if DEBUG:
    from local_settings import *
else:
    from config.local_settings import *

SYMBOLS = ".◘#∴¹▼᠂（◆ን∮♭▘・ｷᛜ"
CHANNEL = {
    # "contact": CONTACT_DISCORD_URL,
    "new": NEW_DISCORD_URL,
    "delete": DELETE_DISCORD_URL,
}
    

def sha256(check) :
    check += SECRET_KEY
    return hashlib.sha256(check.encode()).hexdigest()

# ハッシュを利用して鍵を指定の長さに調整する
def derive_key(key, length):
    return hashlib.sha256(key.encode()).digest()[:length]

# 16進数を記号に
def hex_to_symbols(hex_str):
    return "".join(SYMBOLS[int(c, 16)] for c in hex_str.lower())

# 記号を16進数に
def symbols_to_hex(symbol_str):
    symbol_map = {symbol: hex(i)[2:] for i, symbol in enumerate(SYMBOLS)}
    return "".join(symbol_map[c] for c in symbol_str)

# IPアドレスから記号暗号に
def encrypt(ip):
    key_bytes = derive_key(SECRET_KEY, 16)
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    formated_ip = ip
    ciphertext = cipher.encrypt(pad(formated_ip.encode(), AES.block_size))
    encrypted_hex = binascii.hexlify(cipher.iv + ciphertext).decode()
    return hex_to_symbols(encrypted_hex)

def is_ip_address(s):
    return bool(re.fullmatch(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s))

def send_discord(url, content):
    content = content.replace("\n            ", "\n")
    content = content.replace("\n        ", "\n")
    
    res = requests.post(url, data={'content': content})
    if (400 <= res.status_code < 600):
        print(res.reason)
        return False
        
    return True

for file, channel in CHANNEL.items():
    path = f"{file}.json" if DEBUG else f"/home/izuminapp/izuminapp/static/subekashi/{file}.json"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for message in data.get("messages", []):
        dt = message.get("timestamp", "")
        dt = parser.parse(dt).strftime("%Y年%m月%d日%H時%M分%S秒")
        content = "=" * 30 + dt + "=" * 30 + "\n"
        content += message.get("content", "")
        content = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lambda m: encrypt(m.group()) if is_ip_address(m.group()) else m.group(), content)
        content = content.replace("\n            ", "\n")
        content = content.replace("\n        ", "\n")
        sleep(2.1)
        send_discord(channel, content)
