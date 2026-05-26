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

# ==================== CONFIGURATION ====================
NAME_PREFIX = "TutorSensi"  # Fixed name prefix as requested

# Game keys (from original Free Fire client)
GAME_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")

# Supported regions
REGIONS = {
    "IND": {"name": "India", "url": "https://client.ind.freefiremobile.com/"},
    "SG": {"name": "Singapore", "url": "https://clientbp.ggblueshark.com/"},
    "BD": {"name": "Bangladesh", "url": "https://clientbp.ggblueshark.com/"},
    "PK": {"name": "Pakistan", "url": "https://clientbp.ggblueshark.com/"},
    "ID": {"name": "Indonesia", "url": "https://clientbp.ggblueshark.com/"},
    "TH": {"name": "Thailand", "url": "https://clientbp.common.ggbluefox.com/"},
    "VN": {"name": "Vietnam", "url": "https://clientbp.ggblueshark.com/"},
    "BR": {"name": "Brazil", "url": "https://client.us.freefiremobile.com/"},
    "ME": {"name": "Middle East", "url": "https://clientbp.common.ggbluefox.com/"},
    "RU": {"name": "Russia", "url": "https://clientbp.ggblueshark.com/"},
    "NA": {"name": "North America", "url": "https://client.us.freefiremobile.com/"},
    "EU": {"name": "Europe", "url": "https://clientbp.ggblueshark.com/"}
}

# AES encryption keys (from game client)
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Thread-local session
thread_local = threading.local()

def get_session():
    """Get or create thread-local requests session"""
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        thread_local.session.mount("http://", adapter)
        thread_local.session.mount("https://", adapter)
    return thread_local.session

# ==================== HELPER FUNCTIONS ====================

def generate_password():
    """Generate a random password for guest account"""
    chars = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(chars) for _ in range(9)).upper()
    return f"TUTOR-{random_part}-SENSI"

def generate_nickname():
    """Generate a random nickname with TutorSensi prefix"""
    chars = string.ascii_letters + string.digits
    random_suffix = ''.join(random.choice(chars) for _ in range(6)).upper()
    return f"TutorSensi{random_suffix}"

def protobuf_varint(value):
    """Encode integer as protobuf varint"""
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

def protobuf_field(field_num, field_type, value):
    """Create a protobuf field"""
    field_header = (field_num << 3) | field_type
    if field_type == 0:  # Varint
        return protobuf_varint(field_header) + protobuf_varint(value)
    elif field_type == 2:  # Length-delimited (string/bytes)
        if isinstance(value, str):
            value = value.encode('utf-8')
        return protobuf_varint(field_header) + protobuf_varint(len(value)) + value
    return b''

def build_protobuf(fields):
    """Build a complete protobuf message"""
    result = bytearray()
    for field_num, field_type, value in fields:
        result.extend(protobuf_field(field_num, field_type, value))
    return bytes(result)

def aes_encrypt(data):
    """AES-CBC encryption for game requests"""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    if isinstance(data, str):
        data = bytes.fromhex(data)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return encrypted.hex()

def encrypt_api(plain_text):
    """Specific encryption for login requests"""
    if isinstance(plain_text, str):
        plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(plain_text, AES.block_size))
    return encrypted.hex()

# ==================== ACCOUNT CREATION FLOW ====================

def step1_guest_register(password):
    """Step 1: Register guest account with Garena"""
    session = get_session()
    
    data = f"password={password}&client_type=2&source=2&app_id=100067"
    signature = hmac.new(GAME_KEY, data.encode('utf-8'), hashlib.sha256).hexdigest()
    
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD;Android12;en;US;)",
        "Authorization": f"Signature {signature}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }
    
    response = session.post(
        "https://100067.connect.garena.com/oauth/guest/register",
        headers=headers,
        data=data,
        timeout=30
    )
    
    result = response.json()
    if result.get('uid'):
        return result['uid']
    return None

def step2_token_grant(uid, password):
    """Step 2: Get access token from guest credentials"""
    session = get_session()
    
    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD;Android12;en;US;)"
    }
    
    body = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": GAME_KEY.hex(),
        "client_id": "100067"
    }
    
    response = session.post(
        "https://100067.connect.garena.com/oauth/guest/token/grant",
        headers=headers,
        data=body,
        timeout=30
    )
    
    result = response.json()
    if result.get('open_id') and result.get('access_token'):
        return result['open_id'], result['access_token']
    return None, None

def xor_encode(original):
    """XOR encoding for field_14 in login request"""
    keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
                 0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    encoded = ""
    for i, char in enumerate(original):
        encoded += chr(ord(char) ^ keystream[i % len(keystream)])
    return encoded

def step3_major_register(access_token, open_id, nickname, region):
    """Step 3: MajorRegister - create game account"""
    session = get_session()
    
    encoded_field = xor_encode(open_id)
    field_bytes = encoded_field.encode('latin1')
    
    # Protobuf payload for MajorRegister
    fields = [
        (1, 2, nickname),           # player name
        (2, 2, access_token),       # access token
        (3, 2, open_id),            # open_id
        (5, 0, 102000007),          # app_id
        (6, 0, 4),                  # client_type
        (7, 0, 1),                  # unknown
        (13, 0, 1),                 # unknown
        (14, 2, field_bytes),       # encoded open_id
        (15, 2, "en"),              # language
        (16, 0, 1),                 # unknown
        (17, 0, 1)                  # unknown
    ]
    
    payload_hex = build_protobuf(fields).hex()
    encrypted = aes_encrypt(payload_hex)
    
    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": "OB52",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }
    
    response = session.post(
        "https://loginbp.ggblueshark.com/MajorRegister",
        headers=headers,
        data=bytes.fromhex(encrypted),
        timeout=30
    )
    
    return response.status_code == 200

def step4_major_login(access_token, open_id, region, nickname):
    """Step 4: MajorLogin - get JWT token"""
    session = get_session()
    
    lang = "en"
    lang_bytes = lang.encode('ascii')
    
    # Static payload template (from original gen.py)
    payload_template = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' + lang_bytes + b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    
    # Replace placeholders
    payload = payload_template.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
    payload = payload.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
    
    encrypted_payload = encrypt_api(payload.hex())
    final_payload = bytes.fromhex(encrypted_payload)
    
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    if region.upper() == "ME":
        url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    
    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": "OB52",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }
    
    response = session.post(url, headers=headers, data=final_payload, timeout=30)
    
    if response.status_code == 200 and len(response.text) > 10:
        # Extract JWT token
        start = response.text.find("eyJhbGci")
        if start != -1:
            jwt_token = response.text[start:-1]
            # Trim to reasonable length
            second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
            if second_dot != -1:
                jwt_token = jwt_token[:second_dot + 44]
            return jwt_token
    return None

def extract_uid_from_jwt(jwt_token):
    """Extract UID from JWT token payload"""
    try:
        payload_b64 = jwt_token.split('.')[1]
        payload_b64 += '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        return payload.get('external_id', '')
    except:
        return None

# ==================== MAIN ACCOUNT CREATION ====================

def create_account(region):
    """Create a single complete Free Fire guest account"""
    try:
        password = generate_password()
        
        # Step 1: Register guest
        uid = step1_guest_register(password)
        if not uid:
            return None
        
        # Step 2: Get tokens
        open_id, access_token = step2_token_grant(uid, password)
        if not open_id:
            return None
        
        # Step 3: Major Register
        nickname = generate_nickname()
        if not step3_major_register(access_token, open_id, nickname, region):
            return None
        
        # Step 4: Major Login - get JWT
        jwt_token = step4_major_login(access_token, open_id, region, nickname)
        if not jwt_token:
            return None
        
        # Extract final UID from JWT
        final_uid = extract_uid_from_jwt(jwt_token)
        if not final_uid:
            final_uid = uid
        
        return {
            "uid": final_uid,
            "password": password,
            "nickname": nickname,
            "region": region,
            "jwt_token": jwt_token[:100] + "..."  # Truncated for display
        }
        
    except Exception as e:
        print(f"Error creating account: {e}")
        return None

def create_multiple_accounts(region, count, max_workers=3):
    """Create multiple accounts concurrently"""
    results = []
    attempts = 0
    max_attempts = count * 5
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        while len(results) < count and attempts < max_attempts:
            needed = count - len(results)
            batch_size = min(needed, max_workers)
            
            futures = [executor.submit(create_account, region) for _ in range(batch_size)]
            
            for future in concurrent.futures.as_completed(futures):
                attempts += 1
                result = future.result()
                if result:
                    results.append(result)
                    print(f"✓ Created account {len(results)}/{count}: {result['uid']}")
                
                if len(results) >= count:
                    break
            
            if len(results) < count:
                time.sleep(2)  # Rate limiting
    
    return results

# ==================== FLASK API ENDPOINTS ====================

@app.route('/gen', methods=['GET'])
def generate_get():
    """GET endpoint for account generation"""
    region = request.args.get('region', 'SG').upper()
    count = request.args.get('count', 1)
    
    try:
        count = int(count)
        count = min(max(count, 1), 10)  # Max 10 accounts per request
    except:
        count = 1
    
    if region not in REGIONS:
        return jsonify({
            "success": False,
            "error": f"Invalid region. Supported: {', '.join(REGIONS.keys())}"
        }), 400
    
    accounts = create_multiple_accounts(region, count)
    
    return jsonify({
        "success": True,
        "message": "Free Fire Guest Account Generator - TutorSensi Edition",
        "requested": count,
        "created": len(accounts),
        "region": region,
        "region_name": REGIONS[region]["name"],
        "accounts": accounts,
        "note": "JWT tokens are truncated for display. Use the full token for API calls."
    })

@app.route('/gen', methods=['POST'])
def generate_post():
    """POST endpoint for account generation"""
    data = request.get_json(silent=True) or {}
    region = data.get('region', 'SG').upper()
    count = data.get('count', 1)
    
    try:
        count = int(count)
        count = min(max(count, 1), 10)
    except:
        count = 1
    
    if region not in REGIONS:
        return jsonify({
            "success": False,
            "error": f"Invalid region. Supported: {', '.join(REGIONS.keys())}"
        }), 400
    
    accounts = create_multiple_accounts(region, count)
    
    return jsonify({
        "success": True,
        "message": "Free Fire Guest Account Generator - TutorSensi Edition",
        "requested": count,
        "created": len(accounts),
        "region": region,
        "region_name": REGIONS[region]["name"],
        "accounts": accounts
    })

@app.route('/regions', methods=['GET'])
def list_regions():
    """List all supported regions"""
    return jsonify({
        "success": True,
        "regions": REGIONS
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "name": "TutorSensi FF Generator",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/', methods=['GET'])
def home():
    """API information"""
    return jsonify({
        "name": "TutorSensi Free Fire Guest Account Generator",
        "version": "1.0.0",
        "description": "Generate real Free Fire guest accounts through official Garena registration flow",
        "endpoints": {
            "GET /gen?region=SG&count=5": "Generate accounts via query params",
            "POST /gen": "Generate accounts via JSON body",
            "GET /regions": "List all supported regions",
            "GET /health": "Health check"
        },
        "default_name_prefix": "TutorSensi",
        "max_accounts_per_request": 10,
        "supported_regions": list(REGIONS.keys())
    })

# Vercel handler
def application(environ, start_response):
    return app(environ, start_response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=False)