from flask import Flask, request, jsonify
from flask_cors import CORS
import hmac
import hashlib
import requests
import string
import random
import time
import json
import base64
import concurrent.futures
import threading
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)
CORS(app)

# -------------------- CONFIGURATION --------------------
NAME_PREFIX = "TutorSensi"

# Game key (from Free Fire client)
GAME_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")

# Regions and their language codes
REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th",
    "BD": "bn", "PK": "ur", "TW": "zh", "EU": "en", "RU": "ru",
    "NA": "en", "SAC": "es", "BR": "pt", "SG": "en"
}

REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/",
    "ID": "https://clientbp.ggblueshark.com/",
    "BR": "https://client.us.freefiremobile.com/",
    "ME": "https://clientbp.common.ggbluefox.com/",
    "VN": "https://clientbp.ggblueshark.com/",
    "TH": "https://clientbp.common.ggbluefox.com/",
    "RU": "https://clientbp.ggblueshark.com/",
    "BD": "https://clientbp.ggblueshark.com/",
    "PK": "https://clientbp.ggblueshark.com/",
    "SG": "https://clientbp.ggblueshark.com/",
    "NA": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.us.freefiremobile.com/",
    "EU": "https://clientbp.ggblueshark.com/",
    "TW": "https://clientbp.ggblueshark.com/"
}

# AES encryption keys (hardcoded from game)
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        thread_local.session.mount("http://", adapter)
        thread_local.session.mount("https://", adapter)
    return thread_local.session

# -------------------- Helper Functions --------------------
def generate_password():
    chars = string.ascii_letters + string.digits
    rand = ''.join(random.choice(chars) for _ in range(9)).upper()
    return f"TUTOR-{rand}-SENSI"

def generate_nickname():
    chars = string.ascii_letters + string.digits
    suffix = ''.join(random.choice(chars) for _ in range(6)).upper()
    return f"{NAME_PREFIX}{suffix}"

def protobuf_varint(value):
    result = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            break
    return bytes(result)

def make_field(field_num, field_type, value):
    header = (field_num << 3) | field_type
    if field_type == 0:  # varint
        return protobuf_varint(header) + protobuf_varint(value)
    elif field_type == 2:  # length-delimited
        if isinstance(value, str):
            value = value.encode('utf-8')
        return protobuf_varint(header) + protobuf_varint(len(value)) + value
    return b''

def build_protobuf(fields):
    # fields is list of (field_num, field_type, value)
    return b''.join(make_field(fn, ft, val) for fn, ft, val in fields)

def aes_encrypt(data_hex):
    data = bytes.fromhex(data_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return encrypted.hex()

def xor_encode(original):
    keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
                 0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    encoded = ""
    for i, ch in enumerate(original):
        encoded += chr(ord(ch) ^ keystream[i % len(keystream)])
    return encoded

# -------------------- Account Creation Steps --------------------
def step1_guest_register(password):
    session = get_session()
    data = f"password={password}&client_type=2&source=2&app_id=100067"
    sig = hmac.new(GAME_KEY, data.encode(), hashlib.sha256).hexdigest()
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD;Android12;en;US;)",
        "Authorization": f"Signature {sig}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resp = session.post("https://100067.connect.garena.com/oauth/guest/register",
                        headers=headers, data=data, timeout=30)
    if resp.status_code == 200:
        uid = resp.json().get('uid')
        if uid:
            return uid
    return None

def step2_token_grant(uid, password):
    session = get_session()
    body = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": GAME_KEY.hex(),
        "client_id": "100067"
    }
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD;Android12;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resp = session.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                        headers=headers, data=body, timeout=30)
    if resp.status_code == 200:
        j = resp.json()
        open_id = j.get('open_id')
        access_token = j.get('access_token')
        if open_id and access_token:
            return open_id, access_token
    return None, None

def step3_major_register(access_token, open_id, nickname, region):
    session = get_session()
    encoded_field = xor_encode(open_id).encode('latin1')
    fields = [
        (1, 2, nickname),
        (2, 2, access_token),
        (3, 2, open_id),
        (5, 0, 102000007),
        (6, 0, 4),
        (7, 0, 1),
        (13, 0, 1),
        (14, 2, encoded_field),
        (15, 2, "en"),
        (16, 0, 1),
        (17, 0, 1),
    ]
    payload_hex = build_protobuf(fields).hex()
    encrypted = aes_encrypt(payload_hex)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": "OB52",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "Authorization": "Bearer",
    }
    url = "https://loginbp.ggblueshark.com/MajorRegister"
    resp = session.post(url, headers=headers, data=bytes.fromhex(encrypted), timeout=30)
    return resp.status_code == 200

def step4_major_login(access_token, open_id, region):
    session = get_session()
    lang = REGION_LANG.get(region, "en")
    lang_bytes = lang.encode()
    # Static payload template (from original working gen.py)
    template = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' + lang_bytes + b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    # Replace placeholders
    payload = template.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
    payload = payload.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
    encrypted = aes_encrypt(payload.hex())
    final = bytes.fromhex(encrypted)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    if region.upper() == "ME":
        url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": "OB52",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "Authorization": "Bearer",
    }
    resp = session.post(url, headers=headers, data=final, timeout=30)
    if resp.status_code == 200 and len(resp.text) > 10:
        # Extract JWT
        start = resp.text.find("eyJhbGci")
        if start != -1:
            jwt = resp.text[start:-1]
            # Trim to full token length
            second_dot = jwt.find(".", jwt.find(".") + 1)
            if second_dot != -1:
                jwt = jwt[:second_dot+44]  # typical length
            return jwt
    return None

def step5_get_login_data(jwt_token, region):
    """Optional: finalise login to ensure account is fully activated."""
    url_base = REGION_URLS.get(region.upper(), "https://clientbp.ggblueshark.com/")
    url = f"{url_base}GetLoginData"
    # Minimal payload – usually not required for account existence, but helps
    payload = b''
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; G011A Build/PI)",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB52",
    }
    try:
        session = get_session()
        resp = session.post(url, headers=headers, data=payload, timeout=30)
        return resp.status_code == 200
    except:
        return False

def create_single_account(region):
    try:
        password = generate_password()
        uid = step1_guest_register(password)
        if not uid:
            return None
        open_id, access_token = step2_token_grant(uid, password)
        if not open_id:
            return None
        nickname = generate_nickname()
        if not step3_major_register(access_token, open_id, nickname, region):
            return None
        jwt = step4_major_login(access_token, open_id, region)
        if not jwt:
            return None
        # Optional: call GetLoginData to fully activate
        step5_get_login_data(jwt, region)
        return {
            "uid": uid,
            "password": password,
            "nickname": nickname,
            "region": region,
            "jwt": jwt[:100] + "..."
        }
    except Exception as e:
        print(f"Error: {e}")
        return None

def create_accounts(region, count, max_workers=3):
    results = []
    attempts = 0
    max_attempts = count * 5
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        while len(results) < count and attempts < max_attempts:
            needed = count - len(results)
            batch = min(needed, max_workers)
            futures = [ex.submit(create_single_account, region) for _ in range(batch)]
            for f in concurrent.futures.as_completed(futures):
                attempts += 1
                res = f.result()
                if res:
                    results.append(res)
                    print(f"✓ Created {res['uid']} ({len(results)}/{count})")
                if len(results) >= count:
                    break
            if len(results) < count:
                time.sleep(2)
    return results

# -------------------- Flask Endpoints --------------------
@app.route('/gen', methods=['GET', 'POST'])
def generate():
    if request.method == 'GET':
        region = request.args.get('region', 'SG').upper()
        try:
            count = int(request.args.get('count', 1))
        except:
            count = 1
    else:
        data = request.get_json(silent=True) or {}
        region = data.get('region', 'SG').upper()
        try:
            count = int(data.get('count', 1))
        except:
            count = 1

    if count < 1:
        count = 1
    if count > 10:
        count = 10
    if region not in REGION_LANG:
        return jsonify({"success": False, "error": f"Invalid region. Choose from {list(REGION_LANG.keys())}"}), 400

    accounts = create_accounts(region, count)
    return jsonify({
        "success": True,
        "message": "TutorSensi FreeFire Guest Account Generator",
        "requested": count,
        "created": len(accounts),
        "region": region,
        "accounts": accounts
    })

@app.route('/regions', methods=['GET'])
def regions():
    return jsonify({"success": True, "regions": list(REGION_LANG.keys())})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "name": "TutorSensi FF Guest Account Generator",
        "endpoints": {
            "GET /gen?region=SG&count=1": "Generate accounts",
            "POST /gen": "JSON: {'region':'SG','count':2}",
            "GET /regions": "List regions",
            "GET /health": "Health check"
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=False)