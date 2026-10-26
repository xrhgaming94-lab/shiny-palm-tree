#!/usr/bin/env python3
"""
TELEGRAM : @DANGER_FF_DEV | @BORN_FOR_THE_SACRIFICE
Free Fire Wallet API v2.0 (Flask)
Endpoint: POST /api/wallet   Body: {"token": "<JWT or Access Token>"}
          GET  /api/wallet?token=<JWT or Access Token>
"""

import asyncio
import base64
import json
import random
import ssl
from datetime import datetime
from typing import Any, Dict, Optional

import aiohttp
import requests
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Protobuf modules
import MajoRLoGinrEq_pb2, MajoRLoGinrEs_pb2
import wallet_pb2

# ----------------------------------------------------------------------
# Fixed keys and helpers
# ----------------------------------------------------------------------
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
XOR_SECRET = b"1e5898ccb8dfdd921f9bdea848768b64a201"

app = Flask(__name__)


# ----------------------------------------------------------------------
# User-Agent randomizer
# ----------------------------------------------------------------------
def uaa() -> str:
    versions = ['4.0.18P6','4.0.19P7','4.0.20P1','4.1.0P3','4.1.5P2','4.2.1P8',
                '4.2.3P1','5.0.1B2','5.0.2P4','5.1.0P1','5.2.0B1','5.2.5P3',
                '5.3.0B1','5.3.2P2','5.4.0P1','5.4.3B2','5.5.0P1','5.5.2P3']
    models = ['SM-A125F','SM-A225F','SM-A325M','SM-A515F','SM-A725F','SM-M215F','SM-M325FV',
              'Redmi 9A','Redmi 9C','POCO M3','POCO M4 Pro','RMX2185','RMX3085',
              'moto g(9) play','CPH2239','V2027','OnePlus Nord','ASUS_Z01QD']
    android_versions = ['9','10','11','12','13','14']
    languages = ['en-US','es-MX','pt-BR','id-ID','ru-RU','hi-IN']
    countries = ['USA','MEX','BRA','IDN','RUS','IND']
    return (f"GarenaMSDK/{random.choice(versions)}({random.choice(models)};"
            f"Android {random.choice(android_versions)};{random.choice(languages)};"
            f"{random.choice(countries)};)")


# ----------------------------------------------------------------------
# Manual protobuf encoding (varint, length-delimited)
# ----------------------------------------------------------------------
async def encode_varint(n: int) -> bytes:
    result = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        result.append(b)
        if not n:
            break
    return bytes(result)


async def make_varint_field(field: int, value: int) -> bytes:
    header = (field << 3) | 0
    return await encode_varint(header) + await encode_varint(value)


async def make_length_field(field: int, value: bytes) -> bytes:
    header = (field << 3) | 2
    return await encode_varint(header) + await encode_varint(len(value)) + value


async def build_protobuf(fields: Dict[int, Any]) -> bytes:
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = await build_protobuf(value)
            packet.extend(await make_length_field(field, nested))
        elif isinstance(value, int):
            packet.extend(await make_varint_field(field, value))
        elif isinstance(value, str):
            packet.extend(await make_length_field(field, value.encode()))
        elif isinstance(value, bytes):
            packet.extend(await make_length_field(field, value))
    return bytes(packet)


async def build_csgetwallet_req(login_token: str, topup_rebate: bool = True) -> bytes:
    fields = {
        1: login_token,
        2: 1 if topup_rebate else 0
    }
    return await build_protobuf(fields)


# ----------------------------------------------------------------------
# JWT Decoding with XOR nickname decode
# ----------------------------------------------------------------------
def decode_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ XOR_SECRET[i % len(XOR_SECRET)])
        return dec.decode('utf-8', errors='replace')
    except Exception:
        return "[DECODE_FAILED]"


def decode_jwt(token: str) -> Dict[str, Any]:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        payload_b64 = parts[1]
        payload_b64 += '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        if 'nickname' in payload and isinstance(payload['nickname'], str):
            payload['nickname'] = decode_nickname(payload['nickname'])
        account_id = payload.get('account_id', payload.get('uid', 'N/A'))
        lock_region = payload.get('lock_region', 'UNKNOWN')
        return {
            'nickname': payload.get('nickname', 'N/A'),
            'account_id': account_id,
            'lock_region': lock_region,
            'raw_payload': payload
        }
    except Exception as e:
        return {'error': str(e)}


# ----------------------------------------------------------------------
# Region -> Wallet API base URL
# ----------------------------------------------------------------------
def wallet_url_for_region(region: str) -> str:
    region_upper = region.upper()
    if region_upper == "IND":
        return "https://client.ind.freefiremobile.com/GetWallet"
    elif region_upper in ("BR", "US", "NA", "SAC"):
        return "https://client.us.freefiremobile.com/GetWallet"
    else:
        return "https://clientbp.ggpolarbear.com/GetWallet"


# ----------------------------------------------------------------------
# Access token -> JWT (MajorLogin flow)
# ----------------------------------------------------------------------
async def inspect_token(access_token: str) -> Optional[Dict]:
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    headers = {"User-Agent": uaa(), "Connection": "close"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, ssl=False) as resp:
            if resp.status == 200:
                return await resp.json()
            return None


def auto_update():
    from google_play_scraper import app as gps_app
    result = gps_app('com.dts.freefireth', lang="fr", country='fr')
    version = result['version']
    r = requests.get(
        f'https://version.ggwhitehawk.com/live/ver.php?version={version}&lang=en&device=android&channel=android&appsttore=googleplay&region=ME&whitelist_version=1.3.0&whitelist_sp_version=1.0.0&device_name=google%20G011A&device_CPU=ARMv7%20VFPv3%20NEON%20VMH&device_GPU=Adreno%20(TM)%20640&device_mem=1993'
    ).json()
    return r['server_url'], r['latest_release_version'], version


async def build_major_login_payload(open_id: str, access_token: str, game_version: str, platform: int = None) -> bytes:
    major = MajoRLoGinrEq_pb2.MajorLogin()
    major.event_time = str(datetime.now())[:-7]
    major.game_name = "free fire"
    major.platform_id = 1
    major.client_version = game_version
    major.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major.system_hardware = "Handheld"
    major.telecom_operator = "Verizon"
    major.network_type = "WIFI"
    major.screen_width = 1920
    major.screen_height = 1080
    major.screen_dpi = "280"
    major.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major.memory = 3003
    major.gpu_renderer = "Adreno (TM) 640"
    major.gpu_version = "OpenGL ES 3.1 v1.46"
    major.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major.client_ip = "223.191.51.89"
    major.language = "en"
    major.open_id = open_id
    major.open_id_type = "4"
    major.device_type = "Handheld"
    major.memory_available.version = 55
    major.memory_available.hidden_value = 81
    major.access_token = access_token
    major.platform_sdk_id = 1
    major.network_operator_a = "Verizon"
    major.network_type_a = "WIFI"
    major.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major.external_storage_total = 36235
    major.external_storage_available = 31335
    major.internal_storage_total = 2519
    major.internal_storage_available = 703
    major.game_disk_storage_available = 25010
    major.game_disk_storage_total = 26628
    major.external_sdcard_avail_storage = 32992
    major.external_sdcard_total_storage = 36235
    major.login_by = 3
    major.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major.reg_avatar = 1
    major.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major.channel_type = 3
    major.cpu_type = 2
    major.cpu_architecture = "64"
    major.client_version_code = "2019118695"
    major.graphics_api = "OpenGLES2"
    major.supported_astc_bitset = 16383
    major.login_open_id_type = 4
    major.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major.loading_time = 13564
    major.release_channel = "android"
    major.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major.android_engine_init_flag = 110009
    major.if_push = 1
    major.is_vpn = 1
    if platform is not None:
        major.origin_platform_type = str(platform)
        major.primary_platform_type = str(platform)
    else:
        major.origin_platform_type = "4"
        major.primary_platform_type = "4"
    raw = major.SerializeToString()
    cipher = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    return cipher.encrypt(pad(raw, AES.block_size))


async def major_login(base_url: str, payload: bytes, headers: dict) -> Optional[bytes]:
    url = f"{base_url}MajorLogin"
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_ctx) as resp:
            if resp.status == 200:
                return await resp.read()
            return None


async def get_jwt_from_access_token(access_token: str) -> Dict:
    token_data = await inspect_token(access_token)
    if not token_data:
        raise Exception("Invalid or expired access token")
    open_id = token_data["open_id"]
    platform = token_data.get("platform")
    base_url, ob_version, game_version = auto_update()
    headers = {
        'User-Agent': uaa(),
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': ob_version
    }
    payload = await build_major_login_payload(open_id, access_token, game_version, platform)
    resp_data = await major_login(base_url, payload, headers)
    if not resp_data:
        raise Exception("MajorLogin request failed")
    major_res = MajoRLoGinrEs_pb2.MajorLoginRes()
    major_res.ParseFromString(resp_data)
    return {
        "jwt": major_res.token,
        "account_uid": major_res.account_uid,
        "key": major_res.key,
        "iv": major_res.iv,
        "timestamp": major_res.timestamp,
        "url": major_res.url
    }


# ----------------------------------------------------------------------
# GetWallet request (encrypted)
# ----------------------------------------------------------------------
async def get_wallet(jwt: str, login_token: str, base_url: str) -> Any:
    proto_bytes = await build_csgetwallet_req(login_token, topup_rebate=True)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(pad(proto_bytes, AES.block_size))
    headers = {
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None, lambda: requests.post(base_url, headers=headers, data=encrypted, timeout=20)
    )
    if response.status_code != 200:
        raise Exception(f"GetWallet failed: {response.status_code}")
    if len(response.content) % 16 == 0:
        try:
            cipher2 = AES.new(KEY, AES.MODE_CBC, IV)
            plain = unpad(cipher2.decrypt(response.content), AES.block_size)
        except Exception:
            plain = response.content
    else:
        plain = response.content
    res = wallet_pb2.CSGetWalletRes()
    res.ParseFromString(plain)
    return res


# ----------------------------------------------------------------------
# Convert wallet protobuf -> dict (JSON serializable)
# ----------------------------------------------------------------------
def wallet_to_dict(wallet_res) -> Dict[str, Any]:
    w = wallet_res.wallet
    last_topup_readable = None
    if w.last_topup_time:
        try:
            dt = datetime.fromtimestamp(w.last_topup_time)
            last_topup_readable = dt.strftime('%d %b %Y, %I:%M:%S %p')
        except Exception:
            last_topup_readable = None
    return {
        "account_id": wallet_res.account_id,
        "paid_level": wallet_res.paid_level,
        "coins": w.coins,
        "gems": w.gems,
        "gop_gems": w.gop_gems,
        "total_topup": w.total_topup,
        "last_topup_time": w.last_topup_time,
        "last_topup_readable": last_topup_readable,
    }


# ----------------------------------------------------------------------
# Main logic (async)
# ----------------------------------------------------------------------
async def process_token(token: str) -> Dict[str, Any]:
    is_jwt = '.' in token and len(token.split('.')) == 3

    if is_jwt:
        decoded = decode_jwt(token)
        if 'error' in decoded:
            raise Exception(f"JWT decode error: {decoded['error']}")
        region = decoded['lock_region']
        wallet_url = wallet_url_for_region(region)
        wallet_res = await get_wallet(token, token, wallet_url)
        return {
            "token_type": "JWT",
            "nickname": decoded['nickname'],
            "game_uid": decoded['account_id'],
            "region": region,
            "wallet_url": wallet_url,
            "wallet": wallet_to_dict(wallet_res),
        }
    else:
        jwt_info = await get_jwt_from_access_token(token)
        jwt = jwt_info['jwt']
        decoded = decode_jwt(jwt)
        if 'error' not in decoded:
            region = decoded['lock_region']
            nickname = decoded['nickname']
            game_uid = decoded['account_id']
        else:
            region = "UNKNOWN"
            nickname = "N/A"
            game_uid = jwt_info['account_uid']
        wallet_url = wallet_url_for_region(region)
        wallet_res = await get_wallet(jwt, token, wallet_url)
        return {
            "token_type": "AccessToken",
            "nickname": nickname,
            "game_uid": game_uid,
            "region": region,
            "wallet_url": wallet_url,
            "wallet": wallet_to_dict(wallet_res),
        }


def run_async(coro):
    """Helper to run async in Flask (sync) context safely."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.close()
        except Exception:
            pass


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "ok",
        "name": "Free Fire Wallet API",
        "credit": "@DANGER_FF_DEV | @BORN_FOR_THE_SACRIFICE",
        "endpoints": {
            "POST /api/wallet": 'Body: {"token":"<JWT or AccessToken>"}',
            "GET /api/wallet": "?token=<JWT or AccessToken>"
        }
    })


@app.route("/api/wallet", methods=["POST"])
def wallet_api_post():
    try:
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()
        if not token:
            return jsonify({
                "success": False,
                "credit": "@DANGER_FF_DEV | @BORN_FOR_THE_SACRIFICE",
                "error": "Token is required"
            }), 400
        result = run_async(process_token(token))
        return jsonify({
            "success": True,
            "credit": "@DANGER_FF_DEV | @BORN_FOR_THE_SACRIFICE",
            "data": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "credit": "@DANGER_FF_DEV | @BORN_FOR_THE_SACRIFICE",
            "error": str(e)
        }), 200


@app.route("/api/wallet", methods=["GET"])
def wallet_api_get():
    try:
        token = (request.args.get("token") or "").strip()
        if not token:
            return jsonify({
                "success": False,
                "credit": "@DANGER_FF_DEV | @BORN_FOR_THE_SACRIFICE",
                "error": "token query param required"
            }), 400
        result = run_async(process_token(token))
        return jsonify({
            "success": True,
            "credit": "@DANGER_FF_DEV | @BORN_FOR_THE_SACRIFICE",
            "data": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "credit": "@DANGER_FF_DEV | @BORN_FOR_THE_SACRIFICE",
            "error": str(e)
        }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)