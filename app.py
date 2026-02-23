# -*- coding: utf-8 -*-
import os
import sys
import time
import json
import random
import asyncio
import threading
import binascii
import requests
import aiohttp
import urllib3
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Protobuf imports (Ensure these files exist in the same directory)
import like_pb2
import like_count_pb2
import uid_generator_pb2

# =========================================================
# ⚙️ CONFIGURATION & CONSTANTS
# =========================================================

# Application Info
APP_DEV = "Riduanul Islam"
AI_MODEL = "Gemini 1.5 Pro (Google DeepMind)"
API_PREFIX = "RIDUAN_API"

# Game Configuration (Must match current live version)
# সর্বশেষ আপডেটের সাথে এই ভার্সনগুলো মিল থাকতে হবে
CLIENT_VERSION      = "1.120.1"      
CLIENT_VERSION_CODE = "2019119621"   
UNITY_VERSION       = "2018.4.11f1"  
RELEASE_VERSION     = "OB52"         
MSDK_VERSION        = "5.5.2P3"      

# Device Info (High-end device ensures better token trust)
USER_AGENT_MODEL    = "ASUS_I005DA"   
ANDROID_OS_VER      = "Android 10"   

# Networking & Security
TOKEN_REFRESH_INTERVAL = 2500  # Refresh token slightly earlier to be safe
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# =========================================================
# 🎨 TERMINAL UI & DESIGN
# =========================================================
# =========================================================
# 🎨 TERMINAL UI & DESIGN (UPDATED)
# =========================================================

class UI:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"

    @staticmethod
    def banner():
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""{UI.CYAN}
    ██████╗ ██╗██████╗ ██╗   ██╗ █████╗ ███╗   ██╗
    ██╔══██╗██║██╔══██╗██║   ██║██╔══██╗████╗  ██║
    ██████╔╝██║██║  ██║██║   ██║███████║██╔██╗ ██║
    ██╔══██╗██║██║  ██║██║   ██║██╔══██║██║╚██╗██║
    ██║  ██║██║██████╔╝╚██████╔╝██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
    {UI.RESET}""")
        print(f"{UI.BOLD}{UI.BLUE}╔══════════════════════════════════════════════════╗{UI.RESET}")
        print(f"{UI.BOLD}{UI.BLUE}║ {UI.YELLOW}DEVELOPER  : {UI.RESET}{APP_DEV:<34} {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BOLD}{UI.BLUE}║ {UI.YELLOW}AI MODEL   : {UI.RESET}{AI_MODEL:<34} {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BOLD}{UI.BLUE}║ {UI.YELLOW}STATUS     : {UI.RESET}{UI.GREEN}ONLINE & READY{UI.RESET}{' '*20} {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BOLD}{UI.BLUE}║ {UI.YELLOW}VERSION    : {UI.RESET}{RELEASE_VERSION:<34} {UI.BLUE}║{UI.RESET}")
        print(f"{UI.BOLD}{UI.BLUE}╚══════════════════════════════════════════════════╝{UI.RESET}")
        
        # 👇 নতুন যোগ করা অংশ (API USAGE) 👇
        print(f"\n{UI.BOLD}{UI.WHITE}[ 🚀 API USAGE GUIDE ]{UI.RESET}")
        print(f"{UI.CYAN}➤ Endpoint :{UI.RESET} {UI.GREEN}/like{UI.RESET}")
        print(f"{UI.CYAN}➤ Format   :{UI.RESET} ?uid={UI.YELLOW}UID{UI.RESET}&server_name={UI.YELLOW}REGION{UI.RESET}")
        print(f"{UI.CYAN}➤ Copy Link:{UI.RESET} {UI.YELLOW}http://127.0.0.1:5001/like?uid=123456789&server_name=BD{UI.RESET}")
        print(f"{UI.BOLD}{UI.BLUE}──────────────────────────────────────────────────{UI.RESET}")

        print(f"\n{UI.RED} ➤ {UI.RESET}Server running on: {UI.BOLD}http://0.0.0.0:5001{UI.RESET}")
        print(f"{UI.RED} ➤ {UI.RESET}Waiting for requests...\n")


# =========================================================
# 🔐 ENCRYPTION & SECURITY LOGIC
# =========================================================

LOGIN_HEX_KEY = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
LOGIN_CLIENT_KEY = bytes.fromhex(LOGIN_HEX_KEY)

def encrypt_login_api(plain_text):
    """Encrypts payload for Garena Login API"""
    try:
        plain_bytes = bytes.fromhex(plain_text)
        # Static Key/IV for Garena Login (Standard for this version)
        key_bytes = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(plain_bytes, AES.block_size)).hex()
    except Exception as e:
        print(f"{UI.RED}[ERROR] Encryption Failed: {e}{UI.RESET}")
        return None

class GameCrypto:
    """Handles encryption for Game Action APIs (Like, Profile)"""
    KEY = b'Yg&tc%DEuh6%Zc^8'
    IV = b'6oyZDr22E3ychjM%'

    @staticmethod
    def encrypt(plaintext):
        cipher = AES.new(GameCrypto.KEY, AES.MODE_CBC, GameCrypto.IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')

# =========================================================
# 🌐 NETWORK & LOGIN MANAGER
# =========================================================

REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", 
    "BD": "bn", "PK": "ur", "TW": "zh", "CIS": "ru", "SAC": "es", 
    "BR": "pt", "SG": "en", "NA": "en"
}

def perform_login(uid, password, region):
    """Logs in to Garena Guest Account to retrieve Access Token"""
    try:
        # 1. OAuth Grant - Get Token
        ua_login = f"GarenaMSDK/{MSDK_VERSION}({USER_AGENT_MODEL};{ANDROID_OS_VER};en;US;)"
        
        url_grant = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers_grant = {
            "User-Agent": ua_login, 
            "Content-Type": "application/x-www-form-urlencoded"
        }
        body_grant = {
            "uid": uid, 
            "password": password, 
            "response_type": "token", 
            "client_type": "2", 
            "client_secret": LOGIN_CLIENT_KEY, 
            "client_id": "100067"
        }
        
        resp_grant = requests.post(url_grant, headers=headers_grant, data=body_grant, timeout=15, verify=False)
        data_grant = resp_grant.json()

        if 'access_token' not in data_grant:
            # Login Failed
            return None
            
        access_token, open_id = data_grant['access_token'], data_grant['open_id']

        # 2. Game Login - Exchange Token for Session
        if region in ["ME", "TH"]: 
            url_login = "https://loginbp.common.ggbluefox.com/MajorLogin"
            host = "loginbp.common.ggbluefox.com"
        else: 
            url_login = "https://loginbp.ggblueshark.com/MajorLogin"
            host = "loginbp.ggblueshark.com"
            
        lang = REGION_LANG.get(region, "en")
        
        # Binary Blob Construction (Must be precise)
        # Using a generic blob structure compatible with recent Unity builds
        binary_head = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.120.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02'
        binary_tail = b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019119621\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        
        full_payload = binary_head + lang.encode("ascii") + binary_tail
        # Inject fresh token/ID
        temp_data = full_payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        temp_data = temp_data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        
        final_body = bytes.fromhex(encrypt_login_api(temp_data.hex()))
        
        headers_login = {
            "User-Agent": f"Dalvik/2.1.0 (Linux; U; {ANDROID_OS_VER}; {USER_AGENT_MODEL} Build/PI)", 
            "Content-Type": "application/x-www-form-urlencoded", 
            "Host": host, 
            "X-GA": "v1 1", 
            "ReleaseVersion": RELEASE_VERSION
        }
        
        resp_login = requests.post(url_login, headers=headers_login, data=final_body, verify=False, timeout=30)
        
        if "eyJ" in resp_login.text:
            token = resp_login.text[resp_login.text.find("eyJ"):]
            end = token.find(".", token.find(".") + 1)
            final_token = token[:end + 44] if end != -1 else token
            return final_token
        return None
    except Exception as e:
        # Silently fail for login to keep logs clean, or print if debugging
        return None

class AccountManager:
    """Manages loading and token caching for bot accounts"""
    def __init__(self):
        self.accounts_cache = {}
        self.server_lists = {} 
        self.lock = threading.Lock()
        
    def load_accounts(self, server_name):
        # File mapping
        fname = "Accounts.bd.json" # Default
        if server_name == "IND": fname = "Accounts.ind.json"
        elif server_name in ["BR", "US", "SAC", "NA"]: fname = "Accounts.br.json"

        try:
            if not os.path.exists(fname):
                print(f"{UI.YELLOW}[WARN] File {fname} not found!{UI.RESET}")
                return 0
                
            with open(fname, "r") as f:
                data = json.load(f)
                with self.lock:
                    self.server_lists[server_name] = []
                    for acc in data:
                        uid = str(acc.get("uid"))
                        pwd = acc.get("password")
                        if uid and pwd:
                            if uid not in self.accounts_cache:
                                self.accounts_cache[uid] = {"password": pwd, "token": None, "token_time": 0}
                            self.server_lists[server_name].append(uid)
            return len(self.server_lists[server_name])
        except Exception as e:
            print(f"{UI.RED}[ERROR] JSON Load Error: {e}{UI.RESET}")
            return 0

    def get_token(self, uid, region):
        """Returns a cached valid token or logs in to get a new one"""
        account = self.accounts_cache.get(str(uid))
        if not account: return None
        
        current_time = time.time()
        # Reuse token if not expired
        if account["token"] and (current_time - account["token_time"] < TOKEN_REFRESH_INTERVAL):
            return account["token"]
        
        # Get new token
        new_token = perform_login(uid, account["password"], region)
        if new_token:
            with self.lock:
                self.accounts_cache[uid]["token"] = new_token
                self.accounts_cache[uid]["token_time"] = current_time
            return new_token
        return None

    def get_batch(self, server_name, batch_size=100, random_mode=False):
        uids = self.server_lists.get(server_name, [])
        if not uids:
            self.load_accounts(server_name)
            uids = self.server_lists.get(server_name, [])
        
        if not uids: return []
        if random_mode: 
            return random.sample(uids, min(len(uids), batch_size))
        return uids[:batch_size]

    def get_profile_token(self, server_name):
        """Get one valid token to check profile stats"""
        uids = self.server_lists.get(server_name, [])
        if not uids: return None
        for uid in uids[:5]: # Try first 5
            token = self.get_token(uid, server_name)
            if token: return token
        return None

acc_manager = AccountManager()

# =========================================================
# ⚡ CORE LOGIC: LIKES & PROFILE
# =========================================================

async def send_single_like(session, url, encrypted_payload, uid, region):
    """Sends a single like request async"""
    token = acc_manager.get_token(uid, region)
    if not token: return 401 # Unauthorized / Login Failed

    headers = {
        'User-Agent': f"Dalvik/2.1.0 (Linux; U; {ANDROID_OS_VER}; {USER_AGENT_MODEL} Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': UNITY_VERSION,
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASE_VERSION
    }
    
    try:
        async with session.post(url, data=bytes.fromhex(encrypted_payload), headers=headers, timeout=10) as response:
            # Only 200 is success. 400/403 means game version mismatch or ban.
            return response.status
    except:
        return 999 # Connection Error

async def process_batch_likes(target_uid, region, server_name, account_uids):
    # Determine Endpoint
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        url = "https://clientbp.ggblueshark.com/LikeProfile"

    # Create Protobuf Payload
    try:
        msg = like_pb2.like()
        msg.uid = int(target_uid)
        msg.region = region
        payload = msg.SerializeToString()
        encrypted_payload = GameCrypto.encrypt(payload)
    except:
        return []

    # Execute Async Batch
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50)) as session:
        tasks = []
        for acc_uid in account_uids:
            tasks.append(send_single_like(session, url, encrypted_payload, acc_uid, server_name))
        return await asyncio.gather(*tasks)

def get_player_info(target_uid, server_name):
    """Fetches Name and Likes count"""
    token = acc_manager.get_profile_token(server_name)
    if not token:
        return "Unknown", 0

    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    try:
        msg = uid_generator_pb2.uid_generator()
        msg.krishna_ = int(target_uid)
        msg.teamXdarks = 1
        encrypted_data = GameCrypto.encrypt(msg.SerializeToString())
        
        headers = {
            'User-Agent': f"Dalvik/2.1.0 (Linux; U; {ANDROID_OS_VER}; {USER_AGENT_MODEL} Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': UNITY_VERSION,
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASE_VERSION
        }
        
        resp = requests.post(url, data=bytes.fromhex(encrypted_data), headers=headers, verify=False, timeout=10)
        
        if resp.status_code == 200:
            info = like_count_pb2.Info()
            info.ParseFromString(resp.content)
            return info.AccountInfo.PlayerNickname, int(info.AccountInfo.Likes)
    except Exception as e:
        print(f"[Profile] Error: {e}")
    
    return "N/A", 0

# =========================================================
# 🚀 API ROUTES
# =========================================================

@app.route('/like', methods=['GET'])
def handle_like_request():
    target_uid = request.args.get("uid")
    server_name = request.args.get("server_name", "BD").upper()
    batch_size = request.args.get("batch_size", 100, type=int)

    # 1. Validation
    if not target_uid:
        return jsonify({"status": "error", "msg": "UID Required"}), 400

    print(f"{UI.YELLOW}[REQ] Like Request for UID: {target_uid} ({server_name}){UI.RESET}")

    # 2. Load Accounts
    count = acc_manager.load_accounts(server_name)
    if count == 0:
        return jsonify({"status": "error", "msg": "No accounts loaded"}), 500

    # 3. Pre-Check Info
    nickname, likes_before = get_player_info(target_uid, server_name)
    
    # 4. Start Like Process
    uids_to_use = acc_manager.get_batch(server_name, batch_size)
    
    if uids_to_use:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(process_batch_likes(target_uid, server_name, server_name, uids_to_use))
            loop.close()
            
            # Count success (200 OK)
            success_count = results.count(200)
        except Exception as e:
            print(f"Loop Error: {e}")
            success_count = 0
    else:
        success_count = 0
    
    # 5. Post-Check Info
    # Add small delay for server update
    time.sleep(1) 
    _, likes_after = get_player_info(target_uid, server_name)
    
    # Calculate real increment (fallback to API success count if server laggy)
    likes_given = likes_after - likes_before
    if likes_given <= 0 and success_count > 0:
        likes_given = success_count  # Trust the API 200 OK responses
    
    status_code = 1 if likes_given > 0 else 2

    # 6. Response Construction
    response_data = {
        "LikesGivenByAPI": likes_increment,
        "LikesafterCommand": after_like_count,
        "LikesbeforeCommand": before_like_count,
        "PlayerNickname": player_nickname_from_profile,
        "UID": actual_player_uid_from_profile,
        "status": request_status,
        "Note": f"Used visit token for profile check and {'random' if use_random else 'rotating'} batch of {len(tokens_for_like_sending)} tokens for like sending."
    }
    return jsonify(response_data)

@app.route('/reload', methods=['GET'])
def reload_acc():
    server = request.args.get("server_name", "BD").upper()
    count = acc_manager.load_accounts(server)
    return jsonify({"status": "success", "loaded": count, "server": server})

# =========================================================
# 🔥 ENTRY POINT
# =========================================================

if __name__ == '__main__':
    UI.banner()
    # Run simple server, debug disabled for production look
    app.run(host='0.0.0.0', port=5001, debug=False, use_reloader=False)
