import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import sqlite3
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import quote, urlparse  # noqa: F401

import httpx
import uvicorn
from aioquic.asyncio import connect as quic_connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.websockets import WebSocketDisconnect

app = FastAPI()

DOWNLOADS_DIR = Path(tempfile.mkdtemp(prefix="tapo_downloads_"))
HLS_DIR = Path(tempfile.mkdtemp(prefix="tapo_hls_"))
STATIC_DIR = Path(__file__).parent / "static"
DB_PATH = Path(__file__).parent / "tapo.db"

TAPO_ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
TAPO_SECRET_KEY = "6ed7d97f3e73467f8a5bab90b577ba4c"
BASE_URL = "https://n-wap-gw.tplinkcloud.com"

cloud_state: dict = {
    "token": None,
    "app_server_url": None,
    "care_url": None,
    "email": None,
    "password": None,
    "terminal_uuid": str(uuid.uuid4()).replace("-", "").upper(),
    "mfa_process_id": None,
    "mfa_pending": False,
    "iot_server_url": None,
    "security_url": None,
    "cipc_url": None,
    "jwt": None,
    "jwt_expires": 0,
}

tapo_instances: dict = {}
streamers: dict = {}
download_tasks: dict = {}
iot_things_cache: dict = {}
relay_sessions: dict = {}  # stream_id -> {task, ffmpeg_proc, stop_event, ...}


# --- Session persistence ---


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS session (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()
    conn.close()


def _save_session():
    conn = sqlite3.connect(DB_PATH)
    for key in ("token", "app_server_url", "care_url", "email", "password", "terminal_uuid",
                "iot_server_url", "security_url", "cipc_url"):
        val = cloud_state.get(key) or ""
        conn.execute(
            "INSERT OR REPLACE INTO session (key, value) VALUES (?, ?)",
            (key, val),
        )
    conn.commit()
    conn.close()


def _load_session():
    if not DB_PATH.exists():
        return False
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT key, value FROM session").fetchall()
    conn.close()
    if not rows:
        return False
    for key, value in rows:
        if key in cloud_state and value:
            cloud_state[key] = value
    return bool(cloud_state.get("token"))


def _clear_session():
    if DB_PATH.exists():
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM session")
        conn.commit()
        conn.close()


_init_db()
_load_session()


def sign_request(body_json: str, url_path: str) -> dict[str, str]:
    nonce = str(uuid.uuid1())
    now = str(int(time.time()))
    content_md5 = base64.b64encode(
        hashlib.md5(body_json.encode("UTF-8")).digest()
    ).decode("UTF-8")
    payload = f"{content_md5}\n{now}\n{nonce}\n{url_path}".encode("UTF-8")
    sig = hmac.new(
        TAPO_SECRET_KEY.encode("UTF-8"), payload, hashlib.sha1
    ).digest().hex()
    return {
        "Content-Md5": content_md5,
        "X-Authorization": f"Timestamp={now}, Nonce={nonce}, AccessKey={TAPO_ACCESS_KEY}, Signature={sig}",
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/3.12.13",
    }


def headers_get(token: str) -> dict:
    return {
        "Authorization": f"ut|{token}",
        "X-App-Name": "TP-Link_Tapo_Android",
    }


async def cloud_post(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint: str,
    body: dict | str,
    token: str | None = None,
) -> dict:
    url = f"{base_url}{endpoint}"
    if token:
        url += f"?token={token}"
    body_json = json.dumps(body) if isinstance(body, dict) else body
    headers = sign_request(body_json, endpoint)
    resp = await client.post(url, content=body_json, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("error_code", 0) != 0:
        raise HTTPException(
            status_code=400,
            detail=f"TP-Link error {data.get('error_code')}: {data.get('msg', json.dumps(data))}",
        )
    result = data.get("result", {})
    # TP-Link sometimes returns error_code:0 but with errorCode/errorMsg inside result
    if isinstance(result, dict) and result.get("errorCode") and str(result.get("errorMsg", "")) != "Success":
        raise HTTPException(
            status_code=400,
            detail=f"TP-Link error {result['errorCode']}: {result.get('errorMsg', 'unknown')}",
        )
    return result


async def cloud_get(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint: str,
    raw_params: str,
    token: str,
) -> dict:
    url = f"{base_url}{endpoint}?{raw_params}"
    print(f"[GET] {url}")
    resp = await client.get(url, headers=headers_get(token))
    resp.raise_for_status()
    return resp.json()


def decrypt_video(content: bytes, key_b64: str) -> bytes:
    key = base64.b64decode(key_b64)
    iv = content[:16]
    enc_data = content[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc_data), AES.block_size)


def decrypt_image_ctr(content: bytes, key_b64: str, iv_b64: str) -> bytes:
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    return cipher.decrypt(content)


def remux_ts_to_mp4(ts_data: bytes) -> bytes:
    proc = subprocess.run(
        ["ffmpeg", "-y", "-i", "pipe:0", "-c", "copy", "-movflags", "+frag_keyframe+empty_moov+faststart", "-f", "mp4", "pipe:1"],
        input=ts_data,
        capture_output=True,
    )
    if proc.returncode != 0:
        print(f"[FFMPEG] stderr: {proc.stderr.decode()[-500:]}")
        raise HTTPException(500, "Failed to remux video")
    return proc.stdout


# --- Auth ---


@app.post("/api/login")
async def login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        raise HTTPException(400, "email and password required")

    async with httpx.AsyncClient(verify=False) as client:
        # Login — handle MFA error code specially
        login_body = {
            "appType": "TP-Link_Tapo_Android",
            "appVersion": "2.12.705",
            "cloudPassword": password,
            "cloudUserName": email,
            "platform": "Android 12",
            "refreshTokenNeeded": False,
            "terminalMeta": "1",
            "terminalName": "Tapo CLI",
            "terminalUUID": cloud_state["terminal_uuid"],
        }
        login_json = json.dumps(login_body)
        endpoint = "/api/v2/account/login"
        headers = sign_request(login_json, endpoint)
        resp = await client.post(f"{BASE_URL}{endpoint}", content=login_json, headers=headers)
        resp.raise_for_status()
        login_data = resp.json()
        print(f"[LOGIN] Raw response: {json.dumps(login_data)[:500]}")
        error_code = login_data.get("error_code", 0)
        result = login_data.get("result", {}) or {}
        print(f"[LOGIN] error_code={error_code} result_type={type(result).__name__} result_keys={list(result.keys()) if isinstance(result, dict) else 'N/A'}")

        # -20677 = MFA required (can appear as top-level error_code OR nested in result.errorCode)
        if error_code not in (0, -20677):
            err_msg = result.get("errorMsg") or login_data.get("msg") or json.dumps(login_data)
            raise HTTPException(400, f"TP-Link error {error_code}: {err_msg}")

        # Handle MFA — check BEFORE generic nested error check
        nested_error = str(result.get("errorCode", ""))
        if error_code == -20677 or "MFAProcessId" in result or nested_error == "-20677":
            mfa_id = result.get("MFAProcessId", "") if isinstance(result, dict) else ""

            # Always trigger push MFA to send the code to the Tapo app
            try:
                push_body = json.dumps({
                    "appType": "TP-Link_Tapo_Android",
                    "cloudPassword": password,
                    "cloudUserName": email,
                    "terminalUUID": cloud_state["terminal_uuid"],
                })
                push_endpoint = "/api/v2/account/getPushVC4TerminalMFA"
                push_headers = sign_request(push_body, push_endpoint)
                push_resp = await client.post(f"{BASE_URL}{push_endpoint}", content=push_body, headers=push_headers)
                push_data = push_resp.json()
                print(f"[MFA PUSH] Response: {json.dumps(push_data)[:500]}")
                if not mfa_id:
                    mfa_id = push_data.get("result", {}).get("MFAProcessId", "") if isinstance(push_data.get("result"), dict) else ""
            except Exception as e:
                print(f"[MFA PUSH] Error: {e}")

            if not mfa_id:
                mfa_id = "pending"

            cloud_state["email"] = email
            cloud_state["password"] = password
            cloud_state["mfa_process_id"] = mfa_id
            cloud_state["mfa_pending"] = True
            return {"status": "mfa_required", "message": "Check your Tapo App for the MFA code"}

        # Check for other nested errors
        nested_ec = result.get("errorCode")
        if nested_ec is not None and int(nested_ec) != 0 and str(result.get("errorMsg", "")) != "Success":
            raise HTTPException(400, f"TP-Link error {nested_ec}: {result.get('errorMsg', 'unknown')}")

        # Success — store state
        token = result.get("token")
        if not token:
            raise HTTPException(400, f"Login failed: no token in response. Result: {json.dumps(result)}")

        cloud_state["email"] = email
        cloud_state["password"] = password
        cloud_state["token"] = token
        cloud_state["app_server_url"] = result.get("appServerUrl", BASE_URL)

        await _discover_service_urls(client)

    _save_session()
    return {"status": "ok", "email": email}


@app.post("/api/mfa")
async def verify_mfa(request: Request):
    body = await request.json()
    code = body.get("code")
    if not code:
        raise HTTPException(400, "MFA code required")
    if not cloud_state.get("mfa_pending"):
        raise HTTPException(400, "No MFA pending")

    async with httpx.AsyncClient(verify=False) as client:
        result = await cloud_post(
            client,
            BASE_URL,
            "/api/v2/account/checkMFACodeAndLogin",
            {
                "appType": "TP-Link_Tapo_Android",
                "cloudUserName": cloud_state["email"],
                "code": code,
                "MFAProcessId": cloud_state["mfa_process_id"],
                "MFAType": 1,
                "terminalBindEnabled": True,
            },
        )

        token = result.get("token")
        if not token:
            raise HTTPException(400, f"MFA failed: no token. Result: {json.dumps(result)}")

        cloud_state["token"] = token
        cloud_state["app_server_url"] = result.get("appServerUrl", BASE_URL)
        cloud_state["mfa_pending"] = False

        await _discover_service_urls(client)

    _save_session()
    return {"status": "ok", "email": cloud_state["email"]}


async def _discover_service_urls(client: httpx.AsyncClient):
    if not cloud_state["token"]:
        cloud_state["care_url"] = "https://euw1-app-tapo-care.i.tplinknbu.com"
        return

    try:
        result = await cloud_post(
            client,
            cloud_state["app_server_url"],
            "/api/v2/common/getAppServiceUrl",
            {"serviceIds": [
                "nbu.iot-app-server.app-v2",
                "nbu.iot-security.appdevice-v2",
                "tapocare.app.cloud",
                "cipc.api.cloud",
                "cipc.stun",
            ]},
            token=cloud_state["token"],
        )
        urls = result.get("serviceUrls", {})
        print(f"[DISCOVERY] Service URLs: {json.dumps(urls)[:500]}")

        if urls.get("nbu.iot-app-server.app-v2"):
            cloud_state["iot_server_url"] = urls["nbu.iot-app-server.app-v2"]
        if urls.get("nbu.iot-security.appdevice-v2"):
            cloud_state["security_url"] = urls["nbu.iot-security.appdevice-v2"]
        if urls.get("tapocare.app.cloud"):
            cloud_state["care_url"] = urls["tapocare.app.cloud"]
        if urls.get("cipc.api.cloud"):
            cloud_state["cipc_url"] = urls["cipc.api.cloud"]
        return
    except Exception as e:
        print(f"[DISCOVERY] Failed: {e}")

    app_url = cloud_state.get("app_server_url", "")
    region_match = re.search(r"n-(\w+)-wap", app_url)
    if region_match:
        region = region_match.group(1)
        cloud_state["care_url"] = cloud_state.get("care_url") or f"https://{region}-app-tapo-care.i.tplinkcloud.com"
        cloud_state["iot_server_url"] = cloud_state.get("iot_server_url") or f"https://{region}-app-server.iot.i.tplinkcloud.com"
        cloud_state["security_url"] = cloud_state.get("security_url") or f"https://{region}-security.iot.i.tplinknbu.com"
        cloud_state["cipc_url"] = cloud_state.get("cipc_url") or f"https://{region}-cipc-api.i.tplinkcloud.com"
        print(f"[DISCOVERY] Derived from region '{region}'")
        return

    cloud_state["care_url"] = "https://euw1-app-tapo-care.i.tplinknbu.com"
    print(f"[DISCOVERY] Defaulting care_url")


def _require_login():
    if not cloud_state["token"]:
        raise HTTPException(401, "Not logged in")


@app.get("/api/session")
async def get_session():
    if cloud_state.get("token") and cloud_state.get("email"):
        return {"logged_in": True, "email": cloud_state["email"]}
    return {"logged_in": False}


@app.post("/api/logout")
async def logout():
    cloud_state["token"] = None
    cloud_state["app_server_url"] = None
    cloud_state["care_url"] = None
    cloud_state["email"] = None
    cloud_state["password"] = None
    cloud_state["mfa_process_id"] = None
    cloud_state["mfa_pending"] = False
    tapo_instances.clear()
    _clear_session()
    return {"status": "ok"}


# --- Devices ---


@app.get("/api/devices")
async def list_devices():
    _require_login()

    async with httpx.AsyncClient(verify=False) as client:
        things = await _get_things(client)

    cameras = []
    for t in things:
        if t.get("deviceType") != "SMART.IPCAMERA":
            continue
        nickname = t.get("nickname", "")
        try:
            nickname = base64.b64decode(nickname).decode("utf-8")
        except Exception:
            pass
        cameras.append({
            "deviceId": t.get("thingName", ""),
            "alias": nickname or t.get("deviceName", "Unknown"),
            "model": t.get("model", ""),
            "mac": t.get("mac", ""),
            "status": t.get("status", 0),
            "fwVer": t.get("fwVer", ""),
        })

    for c in cameras:
        print(f"[DEVICES]   {c['alias']} model={c['model']} status={c['status']} id={c['deviceId'][:30]}...")
    return {"cameras": cameras}


@app.post("/api/device/info")
async def device_info(request: Request):
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    if not device_id:
        raise HTTPException(400, "device_id required")

    request_data = {
        "method": "multipleRequest",
        "params": {
            "requests": [
                {"method": "getDeviceInfo", "params": {"device_info": {"name": ["basic_info"]}}},
                {"method": "getLastAlarmInfo", "params": {"system": {"name": ["last_alarm_info"]}}},
                {"method": "getAppComponentList", "params": {"app_component": {"name": ["app_component_list"]}}},
            ]
        },
    }

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)
        result = await _services_sync(client, device_id, request_data, use_edge=True)

    return result



@app.post("/api/device/privacy")
async def set_privacy_mode(request: Request):
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    enabled = body.get("enabled", True)

    if not device_id:
        raise HTTPException(400, "device_id required")

    request_data = {
        "method": "multipleRequest",
        "params": {
            "requests": [{
                "method": "setLensMaskConfig",
                "params": {"lens_mask": {"lens_mask_info": {"enabled": "on" if enabled else "off"}}},
            }],
        },
    }

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)
        result = await _services_sync(client, device_id, request_data, use_edge=True)

    return result


@app.post("/api/device/detection")
async def set_detection(request: Request):
    """Set individual detection settings. Body: {device_id, type, enabled, sensitivity?}
    type: motion | person | pet | vehicle | baby_cry | bark | meow | glass_break
    """
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    det_type = body.get("type", "person")
    enabled = body.get("enabled", True)
    sensitivity = str(body.get("sensitivity", "80"))

    if not device_id:
        raise HTTPException(400, "device_id required")

    val = "on" if enabled else "off"
    requests_list = []

    _SET_MAP = {
        "motion":      {"method": "setDetectionConfig", "params": {"motion_detection": {"motion_det": {"digital_sensitivity": sensitivity, "enabled": val}}}},
        "person":      {"method": "setPersonDetectionConfig", "params": {"people_detection": {"detection": {"enabled": val, "sensitivity": sensitivity}}}},
        "pet":         {"method": "setPetDetectionConfig", "params": {"pet_detection": {"detection": {"enabled": val, "sensitivity": sensitivity}}}},
        "vehicle":     {"method": "setVehicleDetectionConfig", "params": {"vehicle_detection": {"detection": {"enabled": val, "sensitivity": sensitivity}}}},
        "baby_cry":    {"method": "setBCDConfig", "params": {"sound_detection": {"bcd": {"enabled": val, "sensitivity": body.get("sensitivity", "high")}}}},
        "bark":        {"method": "setBarkDetectionConfig", "params": {"bark_detection": {"detection": {"enabled": val, "sensitivity": sensitivity}}}},
        "meow":        {"method": "setMeowDetectionConfig", "params": {"meow_detection": {"detection": {"enabled": val, "sensitivity": sensitivity}}}},
        "glass_break": {"method": "setGlassDetectionConfig", "params": {"glass_detection": {"detection": {"enabled": val, "sensitivity": sensitivity}}}},
        "linecrossing": {"method": "setLinecrossingDetectionConfig", "params": {"linecrossing_detection": {"detection": {"enabled": val, "sensitivity": sensitivity}}}},
        "tamper":      {"method": "setTamperDetectionConfig", "params": {"tamper_detection": {"tamper_det": {"enabled": val, "sensitivity": sensitivity}}}},
    }

    if det_type in _SET_MAP:
        requests_list.append(_SET_MAP[det_type])

    if not requests_list:
        raise HTTPException(400, f"Unknown detection type: {det_type}")

    request_data = {"method": "multipleRequest", "params": {"requests": requests_list}}

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)
        result = await _services_sync(client, device_id, request_data, use_edge=True)

    return result


_STATUS_PARSE_MAP = {
    "motion_detection": ("motion_det", "motion"),
    "people_detection": ("detection", "person"),
    "pet_detection": ("detection", "pet"),
    "vehicle_detection": ("detection", "vehicle"),
    "sound_detection": ("bcd", "baby_cry"),
    "bark_detection": ("detection", "bark"),
    "meow_detection": ("detection", "meow"),
    "glass_detection": ("detection", "glass_break"),
    "linecrossing_detection": ("detection", "linecrossing"),
    "tamper_detection": ("tamper_det", "tamper"),
}


_STATUS_QUERIES = [
    {"method": "getLensMaskConfig", "params": {"lens_mask": {"name": ["lens_mask_info"]}}},
    {"method": "getDetectionConfig", "params": {"motion_detection": {"name": ["motion_det"], "table": ["region_info"]}}},
    {"method": "getAlertConfig", "params": {"msg_alarm": {"name": ["chn1_msg_alarm_info"]}}},
    {"method": "getLinecrossingDetectionConfig", "params": {"linecrossing_detection": {"name": ["detection", "arming_schedule"]}}},
    {"method": "getTamperDetectionConfig", "params": {"tamper_detection": {"name": ["tamper_det"]}}},
    {"method": "getBCDConfig", "params": {"sound_detection": {"name": "bcd"}}},
    {"method": "getPersonDetectionConfig", "params": {"people_detection": {"name": ["detection"]}}},
    {"method": "getPetDetectionConfig", "params": {"pet_detection": {"name": ["detection"]}}},
    {"method": "getVehicleDetectionConfig", "params": {"vehicle_detection": {"name": ["detection"]}}},
    {"method": "getBarkDetectionConfig", "params": {"bark_detection": {"name": ["detection"]}}},
    {"method": "getMeowDetectionConfig", "params": {"meow_detection": {"name": ["detection"]}}},
    {"method": "getGlassDetectionConfig", "params": {"glass_detection": {"name": ["detection"]}}},
]


async def _services_sync_safe(client, device_id, request_data):
    """Like _services_sync but returns None on any error instead of raising."""
    thing = _get_thing(device_id)
    base_url = thing.get("edgeAppServerUrlV2") or thing.get("edgeAppServerUrl")
    if not base_url:
        base_url = cloud_state.get("iot_server_url", "https://aps1-app-server.iot.i.tplinkcloud.com")
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"

    body = {"inputParams": {"requestData": request_data}, "serviceId": "passthrough"}
    headers = _iot_headers(use_jwt=True)
    url = f"{base_url}/v1/things/{device_id}/services-sync"
    try:
        resp = await client.post(url, json=body, headers=headers, timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        output = data.get("outputParams", {}).get("responseData", {})
        return output.get("result", output)
    except Exception:
        return None


@app.post("/api/device/detection/status")
async def get_detection_status(request: Request):
    """Fetch all detection + alert + privacy status. Each query sent individually to skip unsupported ones."""
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    if not device_id:
        raise HTTPException(400, "device_id required")

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)

        async def _query(req):
            wrapped = {"method": "multipleRequest", "params": {"requests": [req]}}
            return await _services_sync_safe(client, device_id, wrapped)

        results = await asyncio.gather(*[_query(q) for q in _STATUS_QUERIES])

    status = {}
    for result in results:
        if not result or not isinstance(result, dict):
            continue
        responses = result.get("responses", [])
        if not responses:
            responses = [{"result": result}]
        for r in responses:
            res = r.get("result", {})
            if not isinstance(res, dict):
                continue
            for key, (sub_key, name) in _STATUS_PARSE_MAP.items():
                info = res.get(key, {}).get(sub_key, {})
                if isinstance(info, dict) and "enabled" in info:
                    status[name] = info["enabled"] == "on"
            alarm_info = res.get("msg_alarm", {}).get("chn1_msg_alarm_info", {})
            if isinstance(alarm_info, dict) and "enabled" in alarm_info:
                status["alert"] = alarm_info["enabled"] == "on"
            privacy_info = res.get("lens_mask", {}).get("lens_mask_info", {})
            if isinstance(privacy_info, dict) and "enabled" in privacy_info:
                status["privacy"] = privacy_info["enabled"] == "on"

    print(f"[DET-STATUS] {status}")
    return status


@app.post("/api/device/alert")
async def set_alert(request: Request):
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    enabled = body.get("enabled", True)

    if not device_id:
        raise HTTPException(400, "device_id required")

    val = "on" if enabled else "off"
    request_data = {
        "method": "multipleRequest",
        "params": {
            "requests": [{
                "method": "setAlertConfig",
                "params": {"msg_alarm": {"chn1_msg_alarm_info": {"enabled": val}}},
            }],
        },
    }

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)
        result = await _services_sync(client, device_id, request_data, use_edge=True)

    return result



@app.post("/api/device/audio_config")
async def get_audio_config(request: Request):
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    if not device_id:
        raise HTTPException(400, "device_id required")

    request_data = {
        "method": "multipleRequest",
        "params": {
            "requests": [
                {"method": "getAudioConfig", "params": {
                    "audio_config": {"name": ["speaker", "microphone"]},
                }},
            ],
        },
    }

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)
        result = await _services_sync(client, device_id, request_data, use_edge=True)

    mic_vol = None
    speaker_vol = None
    try:
        for r in result.get("responses", []):
            ac = r.get("result", {}).get("audio_config", {})
            if "speaker" in ac and "volume" in ac["speaker"]:
                speaker_vol = int(ac["speaker"]["volume"])
            if "microphone" in ac and "volume" in ac["microphone"]:
                mic_vol = int(ac["microphone"]["volume"])
    except Exception:
        pass

    print(f"[AUDIO-CONFIG] result={json.dumps(result)[:500]}")
    return {"mic_volume": mic_vol, "speaker_volume": speaker_vol}


@app.post("/api/device/mic_volume")
async def set_mic_volume(request: Request):
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    volume = body.get("volume", 50)

    if not device_id:
        raise HTTPException(400, "device_id required")

    volume = max(0, min(100, int(volume)))

    request_data = {
        "method": "multipleRequest",
        "params": {
            "requests": [{
                "method": "setMicrophoneVolume",
                "params": {"audio_config": {"microphone": {
                    "bitrate": "64",
                    "channels": "1",
                    "encode_type": "G711ulaw",
                    "sampling_rate": "16",
                    "volume": str(volume),
                }}},
            }],
        },
    }

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)
        result = await _services_sync(client, device_id, request_data, use_edge=True)

    return result



@app.post("/api/device/motor")
async def motor_move(request: Request):
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    x = body.get("x", 0)
    y = body.get("y", 0)

    if not device_id:
        raise HTTPException(400, "device_id required")

    request_data = {
        "method": "multipleRequest",
        "params": {
            "requests": [{
                "method": "motorMove",
                "params": {"motor": {"move": {"x_coord": str(x), "y_coord": str(y)}}},
            }],
        },
    }

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)
        result = await _services_sync(client, device_id, request_data, use_edge=True)

    return result


# --- Cloud Videos (Tapo Care) ---


@app.post("/api/videos/list")
async def list_videos(request: Request):
    _require_login()

    body = await request.json()
    device_id = body.get("device_id")
    days = body.get("days", 1)
    start_date = body.get("start_date")
    end_date = body.get("end_date")

    if not device_id:
        raise HTTPException(400, "device_id required")

    from datetime import datetime, timedelta

    if start_date and end_date:
        start_time = f"{start_date} 00:00:00"
        end_time = f"{end_date} 23:59:59"
    elif start_date:
        # "Last N days" from the selected date — go backwards
        anchor = datetime.strptime(start_date, "%Y-%m-%d")
        start_dt = anchor - timedelta(days=days - 1)
        start_time = f"{start_dt.strftime('%Y-%m-%d')} 00:00:00"
        end_time = f"{start_date} 23:59:59"
    else:
        end_unixtime = time.time() + 86400
        start_unixtime = end_unixtime - (days + 1) * 86400
        end_time = time.strftime("%Y-%m-%d 00:00:00", time.gmtime(end_unixtime))
        start_time = time.strftime("%Y-%m-%d 00:00:00", time.gmtime(start_unixtime))

    care_url = cloud_state["care_url"]
    print(f"[VIDEOS] care_url={care_url} device_id={device_id} days={days}")
    print(f"[VIDEOS] startTime={start_time} endTime={end_time}")

    raw_params = f"deviceId={device_id}&page=0&pageSize=200&order=desc&startTime={start_time}&endTime={end_time}"

    async with httpx.AsyncClient(verify=False) as client:
        data = await cloud_get(
            client, care_url, "/v2/videos/list", raw_params, cloud_state["token"]
        )

    print(f"[VIDEOS] Response keys={list(data.keys())} total={data.get('total', 'N/A')}")
    if data.get("total", 0) == 0:
        print(f"[VIDEOS] Full response: {json.dumps(data)[:1000]}")

    total = data.get("total", 0)
    videos = []
    for v in data.get("index", []):
        video_entry = v.get("video", [{}])[0] if v.get("video") else {}
        image_entry = v.get("image", [{}])[0] if v.get("image") else {}
        encrypted = "encryptionMethod" in video_entry
        img_encrypted = "encryptionMethod" in image_entry

        videos.append({
            "uuid": v.get("uuid", ""),
            "eventLocalTime": v.get("eventLocalTime", ""),
            "createdTime": v.get("createdTime", 0),
            "duration": video_entry.get("duration", 0),
            "resolution": video_entry.get("resolution", ""),
            "size": video_entry.get("size", 0),
            "channelId": video_entry.get("channelId", ""),
            "uri": video_entry.get("uri", ""),
            "encrypted": encrypted,
            "key": video_entry.get("decryptionInfo", {}).get("key", "") if encrypted else "",
            "eventTypes": v.get("eventTypeList", []),
            "thumbnailUri": image_entry.get("uri", ""),
            "thumbnailKey": image_entry.get("decryptionInfo", {}).get("key", "") if img_encrypted else "",
            "thumbnailIv": image_entry.get("decryptionInfo", {}).get("iv", "") if img_encrypted else "",
            "thumbnailEncrypted": img_encrypted,
        })

    return {"total": total, "videos": videos}


@app.post("/api/videos/download")
async def download_video(request: Request):
    body = await request.json()
    uri = body.get("uri")
    key = body.get("key", "")
    filename = body.get("filename", "video.mp4")

    if not uri:
        raise HTTPException(400, "uri required")

    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        resp = await client.get(uri)
        resp.raise_for_status()
        content = resp.content

    if key:
        content = decrypt_video(content, key)

    mp4_content = await asyncio.get_event_loop().run_in_executor(None, remux_ts_to_mp4, content)

    file_path = DOWNLOADS_DIR / filename
    file_path.write_bytes(mp4_content)

    return FileResponse(file_path, media_type="video/mp4", filename=filename)


@app.post("/api/videos/stream")
async def stream_video(request: Request):
    body = await request.json()
    uri = body.get("uri")
    key = body.get("key", "")

    if not uri:
        raise HTTPException(400, "uri required")

    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        resp = await client.get(uri)
        resp.raise_for_status()
        content = resp.content

    if key:
        content = decrypt_video(content, key)

    mp4_content = await asyncio.get_event_loop().run_in_executor(None, remux_ts_to_mp4, content)

    return Response(
        content=mp4_content,
        media_type="video/mp4",
        headers={"Content-Disposition": "inline"},
    )


@app.post("/api/videos/thumbnail")
async def proxy_thumbnail(request: Request):
    body = await request.json()
    uri = body.get("uri")
    key = body.get("key", "")
    iv = body.get("iv", "")

    if not uri:
        raise HTTPException(400, "uri required")

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.get(uri)
        resp.raise_for_status()
        content = resp.content

    if key and iv:
        content = decrypt_image_ctr(content, key, iv)

    return Response(content=content, media_type="image/jpeg")


# --- Notifications ---


@app.get("/api/notifications")
async def get_notifications():
    _require_login()

    now_ts = int(time.time())
    async with httpx.AsyncClient(verify=False) as client:
        result = await cloud_post(
            client,
            cloud_state["app_server_url"],
            "/api/v2/common/getAppNotificationByPage",
            {
                "appType": "TP-Link_Tapo_Android",
                "contentVersion": 2,
                "deviceToken": "",
                "direction": "asc",
                "index": 0,
                "indexTime": now_ts,
                "limit": 50,
                "locale": "en_US",
                "mobileType": "ANDROID",
                "msgTypes": [
                    "Motion", "PersonDetected", "PersonEnhanced", "Audio",
                    "BabyCry", "PetDetected", "VehicleDetected",
                    "tapoCameraAreaIntrusionDetection", "tapoCameraLinecrossingDetection",
                    "tapoCameraCameraTampering", "tapoGlassBreakingDetected",
                    "deliverPackageDetected", "pickUpPackageDetected",
                ],
                "terminalUUID": cloud_state["terminal_uuid"],
            },
            token=cloud_state["token"],
        )

    return result


# --- Local Mode (pytapo, requires LAN access to camera) ---


def get_tapo(camera_ip: str):
    from pytapo import Tapo

    if camera_ip in tapo_instances:
        return tapo_instances[camera_ip]
    password = cloud_state["password"]
    if not password:
        raise HTTPException(401, "Not logged in")
    tapo = Tapo(camera_ip, "admin", password, password)
    tapo_instances[camera_ip] = tapo
    return tapo


@app.post("/api/local/stream/start")
async def local_start_stream(request: Request):
    from pytapo.media_stream.streamer import Streamer

    body = await request.json()
    camera_ip = body.get("camera_ip")
    resolution = body.get("resolution", "HD")

    if not camera_ip:
        raise HTTPException(400, "camera_ip required")

    stream_id = camera_ip.replace(".", "_")

    if stream_id in streamers:
        return {"status": "already_streaming", "stream_id": stream_id}

    stream_dir = HLS_DIR / stream_id
    stream_dir.mkdir(parents=True, exist_ok=True)

    tapo = get_tapo(camera_ip)
    streamer = Streamer(
        tapo,
        outputDirectory=str(stream_dir) + "/",
        fileName="index.m3u8",
        quality=resolution,
        mode="hls",
        includeAudio=True,
    )
    await streamer.start()
    streamers[stream_id] = streamer

    return {"status": "started", "stream_id": stream_id}


@app.post("/api/local/stream/stop")
async def local_stop_stream(request: Request):
    body = await request.json()
    stream_id = body.get("stream_id")
    if not stream_id:
        raise HTTPException(400, "stream_id required")

    streamer = streamers.pop(stream_id, None)
    if streamer:
        await streamer.stop()
    return {"status": "stopped"}


@app.get("/api/local/stream/{stream_id}/index.m3u8")
async def local_get_playlist(stream_id: str):
    playlist = HLS_DIR / stream_id / "index.m3u8"
    if not playlist.exists():
        raise HTTPException(404, "Stream not found or not ready yet")
    return FileResponse(playlist, media_type="application/vnd.apple.mpegurl")


@app.get("/api/local/stream/{stream_id}/{segment}")
async def local_get_segment(stream_id: str, segment: str):
    seg_path = HLS_DIR / stream_id / segment
    if not seg_path.exists():
        raise HTTPException(404, "Segment not found")
    return FileResponse(seg_path, media_type="video/mp2t")


@app.post("/api/local/recordings/dates")
async def local_get_recording_dates(request: Request):
    body = await request.json()
    camera_ip = body.get("camera_ip")
    if not camera_ip:
        raise HTTPException(400, "camera_ip required")

    tapo = get_tapo(camera_ip)
    loop = asyncio.get_event_loop()
    try:
        dates = await loop.run_in_executor(None, tapo.getRecordingsList)
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"dates": dates}


@app.post("/api/local/recordings/list")
async def local_get_recordings(request: Request):
    body = await request.json()
    camera_ip = body.get("camera_ip")
    date = body.get("date")

    if not camera_ip or not date:
        raise HTTPException(400, "camera_ip and date required")

    tapo = get_tapo(camera_ip)
    loop = asyncio.get_event_loop()
    try:
        recordings = await loop.run_in_executor(None, tapo.getRecordings, date)
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"recordings": recordings}


@app.post("/api/local/recordings/download")
async def local_download_recording(request: Request):
    from pytapo.media_stream.downloader import Downloader

    body = await request.json()
    camera_ip = body.get("camera_ip")
    start_time = body.get("start_time")
    end_time = body.get("end_time")

    if not camera_ip or not start_time or not end_time:
        raise HTTPException(400, "camera_ip, start_time, and end_time required")

    download_id = f"{camera_ip}_{start_time}_{end_time}"
    output_dir = DOWNLOADS_DIR / download_id
    output_dir.mkdir(parents=True, exist_ok=True)

    tapo = get_tapo(camera_ip)
    time_correction = await asyncio.get_event_loop().run_in_executor(
        None, tapo.getTimeCorrection
    )

    downloader = Downloader(
        tapo,
        startTime=int(start_time),
        endTime=int(end_time),
        timeCorrection=time_correction,
        outputDirectory=str(output_dir) + "/",
    )

    task = asyncio.create_task(downloader.downloadFile())
    download_tasks[download_id] = task
    return {"status": "started", "download_id": download_id}


@app.get("/api/local/recordings/status/{download_id}")
async def local_download_status(download_id: str):
    task = download_tasks.get(download_id)
    if not task:
        raise HTTPException(404, "Download not found")
    if not task.done():
        return {"status": "downloading"}
    try:
        result = task.result()
        file_name = result.get("fileName", "")
        if file_name and os.path.exists(file_name):
            return {
                "status": "ready",
                "file_url": f"/api/local/recordings/serve/{download_id}/{os.path.basename(file_name)}",
            }
        return {"status": "error", "error": "File not found after download"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/local/recordings/serve/{download_id}/{filename}")
async def local_serve_recording(download_id: str, filename: str):
    file_path = DOWNLOADS_DIR / download_id / filename
    if not file_path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(file_path, media_type="video/mp4", filename=filename)


@app.post("/api/local/events")
async def local_get_events(request: Request):
    body = await request.json()
    camera_ip = body.get("camera_ip")
    if not camera_ip:
        raise HTTPException(400, "camera_ip required")

    tapo = get_tapo(camera_ip)
    loop = asyncio.get_event_loop()
    try:
        events = await loop.run_in_executor(None, tapo.getEvents)
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"events": events}


# --- Live Stream (Cloud Relay) ---

RELAY_CLIENT_BOUNDARY = b"--client-stream-boundary--"
RELAY_HEARTBEAT_INTERVAL = 15

audio_subscribers: dict[str, list[asyncio.Queue]] = {}  # stream_id -> list of queues


def _extract_audio_from_ts(ts_data: bytes, audio_pid: int) -> bytes:
    """Extract raw audio payload bytes from MPEG-TS packets matching audio_pid."""
    out = bytearray()
    offset = 0
    while offset + 188 <= len(ts_data):
        if ts_data[offset] != 0x47:
            offset += 1
            continue
        pid = ((ts_data[offset + 1] & 0x1F) << 8) | ts_data[offset + 2]
        if pid == audio_pid:
            adaptation = (ts_data[offset + 3] >> 4) & 0x03
            payload_start = offset + 4
            if adaptation in (2, 3):
                adapt_len = ts_data[offset + 4]
                payload_start = offset + 5 + adapt_len
            if adaptation in (1, 3) and payload_start < offset + 188:
                pusi = ts_data[offset + 1] & 0x40
                p = payload_start
                if pusi:
                    if p + 9 <= offset + 188:
                        pes_header_len = ts_data[p + 8]
                        p = p + 9 + pes_header_len
                out.extend(ts_data[p:offset + 188])
        offset += 188
    return bytes(out)


def _find_audio_pid_from_ts(ts_data: bytes) -> int | None:
    """Scan PMT in MPEG-TS to find PID of stream type 0x91 (Tapo G.711 mulaw)."""
    offset = 0
    pmt_pid = None
    while offset + 188 <= len(ts_data):
        if ts_data[offset] != 0x47:
            offset += 1
            continue
        pid = ((ts_data[offset + 1] & 0x1F) << 8) | ts_data[offset + 2]
        if pid == 0 and pmt_pid is None:
            # PAT — find PMT PID
            p = offset + 4
            adaptation = (ts_data[offset + 3] >> 4) & 0x03
            if adaptation in (2, 3):
                p = offset + 5 + ts_data[offset + 4]
            if ts_data[offset + 1] & 0x40:
                p += 1 + ts_data[p]  # pointer field
            p += 8  # skip PAT header
            if p + 4 <= offset + 188:
                pmt_pid = ((ts_data[p + 2] & 0x1F) << 8) | ts_data[p + 3]
        elif pmt_pid is not None and pid == pmt_pid:
            p = offset + 4
            adaptation = (ts_data[offset + 3] >> 4) & 0x03
            if adaptation in (2, 3):
                p = offset + 5 + ts_data[offset + 4]
            if ts_data[offset + 1] & 0x40:
                p += 1 + ts_data[p]
            p += 10  # skip PMT header
            prog_info_len = ((ts_data[p - 2] & 0x0F) << 8) | ts_data[p - 1]
            p += prog_info_len
            while p + 5 <= offset + 188:
                stream_type = ts_data[p]
                elem_pid = ((ts_data[p + 1] & 0x1F) << 8) | ts_data[p + 2]
                es_info_len = ((ts_data[p + 3] & 0x0F) << 8) | ts_data[p + 4]
                if stream_type == 0x91:
                    return elem_pid
                p += 5 + es_info_len
            break
        offset += 188
    return None


def _get_cipc_url():
    return cloud_state.get("cipc_url") or "https://aps1-cipc-api.i.tplinkcloud.com"


class RelayQuicProtocol(QuicConnectionProtocol):
    def __init__(self, *args, stream_tag: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._h3_stream_id = 0
        self._data_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._response_headers: dict = {}
        self._response_status: int = 0
        self._got_response = asyncio.Event()
        self._tag = stream_tag

    def quic_event_received(self, event: QuicEvent):
        from aioquic.quic.events import ConnectionTerminated
        if isinstance(event, ConnectionTerminated):
            print(f"[QUIC-{self._tag}] Connection terminated err={event.error_code} reason={event.reason_phrase}")
            self._data_queue.put_nowait(None)
            return
        if self._http is None:
            return
        for h3_event in self._http.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                hdrs = dict(h3_event.headers)
                status = int(hdrs.get(b":status", b"0"))
                self._response_status = status
                self._response_headers = {
                    k.decode(): v.decode()
                    for k, v in h3_event.headers
                    if not k.startswith(b":")
                }
                print(f"[QUIC-{self._tag}] HTTP/3 response status={status} headers={self._response_headers}")
                self._got_response.set()
            elif isinstance(h3_event, DataReceived):
                self._data_queue.put_nowait(h3_event.data)


async def _relay_connect(relay_url: str, relay_token: str, relay_ip: str, stream_dir: Path, stop_event: asyncio.Event, stream_id: str, resolution: str = "VGA", p2p_session_id: str = "", cdn_url: str = "", relay_business_url: str = ""):
    use_cdn = bool(cdn_url and relay_business_url)

    if use_cdn:
        # CDN mode: connect to CDN URL, use business URL path
        cdn_parsed = urlparse(cdn_url)
        biz_parsed = urlparse(relay_business_url)
        host = cdn_parsed.hostname
        port = cdn_parsed.port or 443
        path = biz_parsed.path
        if biz_parsed.query:
            path += f"?{biz_parsed.query}"
        # Extract CDN origin from business URL (hostname only)
        biz_host_stripped = biz_parsed.hostname or ""
        print(f"[QUIC] CDN mode: host={host} cdn_origin={biz_host_stripped}")
    else:
        parsed = urlparse(relay_url)
        host = parsed.hostname
        port = parsed.port or 443
        path = parsed.path
        if parsed.query:
            path += f"?{parsed.query}"
    full_path = f"{path}&retryTime=0"

    playlist_path = stream_dir / "index.m3u8"
    ffmpeg_proc = None
    quic_conn = None

    try:
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=["h3"],
            max_datagram_frame_size=65536,
            idle_timeout=60,
        )
        configuration.verify_mode = ssl.CERT_NONE

        print(f"[QUIC] Connecting to {host}:{port} via HTTP/3...")

        async with quic_connect(
            host,
            port,
            configuration=configuration,
            create_protocol=lambda *args, **kwargs: RelayQuicProtocol(*args, stream_tag=stream_id, **kwargs),
        ) as protocol:
            quic_conn = protocol
            h3 = protocol._http

            # Build HTTP/3 request headers matching XQuicRelayClient.java
            request_headers = [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", f"{host}:443".encode()),
                (b":path", full_path.encode()),
                (b"user-agent", b"Client=TP-Link_Tapo_Android/3.18.116/1.3"),
                (b"keep-relay", b"300"),
                (b"accept", b"*/*"),
                (b"content-type", f"multipart/mixed;boundary={RELAY_CLIENT_BOUNDARY.decode()}".encode()),
                (b"x-token", relay_token.encode()),
                (b"x-client-model", b"Android"),
                (b"x-client-uuid", cloud_state["terminal_uuid"].encode()),
                (b"x-track-id", str(uuid.uuid4()).encode()),
                (b"x-redirect-times", b"0"),
                (b"x-pull-mode", b"0"),
                (b"x-version", b"2.0"),
                (b"x-compete", b"0"),
                (b"x-arrive-latency", b"0"),
            ]
            if use_cdn:
                request_headers.append((b"x-cdn-origin", biz_host_stripped.encode()))
            if p2p_session_id:
                request_headers.append((b"x-client-sessionid", p2p_session_id.encode()))

            stream_req_id = protocol._quic.get_next_available_stream_id()
            h3.send_headers(
                stream_id=stream_req_id,
                headers=request_headers,
                end_stream=False,
            )
            protocol.transmit()
            protocol._h3_stream_id = stream_req_id
            print(f"[QUIC] Sent HTTP/3 POST on stream {stream_req_id}, path={full_path[:100]}")

            # Wait for initial HTTP response
            try:
                await asyncio.wait_for(protocol._got_response.wait(), timeout=30)
            except asyncio.TimeoutError:
                print(f"[QUIC] Timeout waiting for HTTP/3 response")
                return

            status = protocol._response_status
            print(f"[QUIC] Response status: {status}")

            if status == 304:
                print(f"[QUIC] Got redirect (304), would need to reconnect")
                return
            if status != 200:
                print(f"[QUIC] Error status {status}")
                return

            resp_headers = protocol._response_headers
            device_boundary = b"--device-stream-boundary--"
            ct = resp_headers.get("content-type", "")
            if "boundary=" in ct:
                device_boundary = ct.split("boundary=")[1].strip().encode()
            print(f"[QUIC] Device boundary: {device_boundary}")

            # Send preview request
            preview_req = json.dumps({
                "type": "request",
                "seq": 1,
                "params": {
                    "preview": {
                        "channels": [0],
                        "resolutions": [resolution],
                        "audio": ["default"],
                    },
                    "method": "get",
                },
            }, separators=(",", ":")).encode()

            preview_msg = b"--" + RELAY_CLIENT_BOUNDARY + b"\r\n"
            preview_msg += b"Content-Type: application/json\r\n"
            preview_msg += f"Content-Length: {len(preview_req)}\r\n".encode()
            preview_msg += b"\r\n"
            preview_msg += preview_req + b"\r\n"

            h3.send_data(stream_req_id, preview_msg, end_stream=False)
            protocol.transmit()
            print(f"[QUIC] Sent preview request: {preview_req.decode()}")

            def _start_ffmpeg(seg_offset=0):
                proc = subprocess.Popen(
                    ["ffmpeg", "-y", "-loglevel", "warning",
                     "-probesize", "32768",
                     "-analyzeduration", "500000",
                     "-fflags", "+genpts+discardcorrupt",
                     "-f", "mpegts",
                     "-i", "pipe:0",
                     "-map", "0:v:0?",
                     "-c:v", "copy",
                     "-f", "hls",
                     "-hls_time", "1",
                     "-hls_init_time", "0.5",
                     "-hls_list_size", "10",
                     "-hls_flags", "delete_segments+append_list",
                     "-start_number", str(seg_offset),
                     "-hls_segment_filename", str(stream_dir / "seg_%05d.ts"),
                     str(playlist_path)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=open(str(stream_dir / "ffmpeg.log"), "a"),
                )
                print(f"[QUIC] ffmpeg started, pid={proc.pid} seg_offset={seg_offset}")
                if stream_id in relay_sessions:
                    relay_sessions[stream_id]["ffmpeg_proc"] = proc
                return proc

            ffmpeg_proc = _start_ffmpeg()
            ffmpeg_restarts = 0
            max_ffmpeg_restarts = 5
            seg_counter = 0
            audio_pid = None
            audio_subscribers[stream_id] = []

            if stream_id in relay_sessions:
                relay_sessions[stream_id]["quic_protocol"] = protocol
                relay_sessions[stream_id]["quic_stream_id"] = stream_req_id

            heartbeat_task = asyncio.create_task(
                _relay_heartbeat_quic(protocol, stream_req_id, stop_event)
            )

            chunk_count = 0
            bytes_total = 0
            buf = b""
            reads = 0

            while not stop_event.is_set():
                try:
                    data = await asyncio.wait_for(protocol._data_queue.get(), timeout=30)
                except asyncio.TimeoutError:
                    print(f"[QUIC] Data timeout after {reads} reads, {len(buf)} bytes in buffer")
                    continue
                if data is None:
                    print(f"[QUIC] Connection closed, {reads} reads, {len(buf)} buf remaining")
                    break

                reads += 1
                buf += data

                while True:
                    boundary_pos = buf.find(device_boundary)
                    if boundary_pos == -1:
                        if len(buf) > 1024 * 1024:
                            buf = buf[-len(device_boundary) - 100:]
                        break

                    after_boundary = boundary_pos + len(device_boundary)
                    header_end = buf.find(b"\r\n\r\n", after_boundary)
                    if header_end == -1:
                        break

                    header_block = buf[after_boundary:header_end].decode("utf-8", errors="replace")
                    chunk_headers = {}
                    for line in header_block.strip().split("\r\n"):
                        if ":" in line:
                            k, v = line.split(":", 1)
                            chunk_headers[k.strip().lower()] = v.strip()

                    content_length = int(chunk_headers.get("content-length", "0"))
                    body_start = header_end + 4
                    body_end = body_start + content_length

                    if len(buf) < body_end:
                        break

                    chunk_body = buf[body_start:body_end]
                    buf = buf[body_end:]

                    content_type = chunk_headers.get("content-type", "")
                    encrypted = chunk_headers.get("x-if-encrypt", "0") == "1"

                    if "video/mp2t" in content_type:
                        if encrypted:
                            chunk_count += 1
                            continue

                        if ffmpeg_proc.poll() is not None:
                            rc = ffmpeg_proc.returncode
                            print(f"[QUIC] ffmpeg exited with code {rc} after {chunk_count} chunks")
                            if ffmpeg_restarts < max_ffmpeg_restarts:
                                ffmpeg_restarts += 1
                                seg_counter += chunk_count
                                ffmpeg_proc = _start_ffmpeg(seg_counter)
                                print(f"[QUIC] ffmpeg restart #{ffmpeg_restarts}")
                            else:
                                print(f"[QUIC] ffmpeg max restarts reached, giving up")
                                break

                        try:
                            ffmpeg_proc.stdin.write(chunk_body)
                            ffmpeg_proc.stdin.flush()
                        except BrokenPipeError:
                            print(f"[QUIC] ffmpeg stdin broken pipe")
                            break

                        if audio_pid is None:
                            audio_pid = _find_audio_pid_from_ts(chunk_body)
                            if audio_pid is not None:
                                print(f"[QUIC] Detected audio PID: 0x{audio_pid:04x}")

                        subs = audio_subscribers.get(stream_id, [])
                        if audio_pid is not None and subs:
                            raw_audio = _extract_audio_from_ts(chunk_body, audio_pid)
                            if raw_audio:
                                for q in subs:
                                    try:
                                        q.put_nowait(raw_audio)
                                    except asyncio.QueueFull:
                                        try:
                                            q.get_nowait()
                                        except asyncio.QueueEmpty:
                                            pass
                                        try:
                                            q.put_nowait(raw_audio)
                                        except asyncio.QueueFull:
                                            pass

                        bytes_total += len(chunk_body)
                        chunk_count += 1
                        if chunk_count % 50 == 0:
                            print(f"[QUIC] {chunk_count} chunks, {bytes_total / 1024:.0f} KB piped to ffmpeg")

                    elif "application/json" in content_type:
                        try:
                            msg = json.loads(chunk_body.decode())
                            print(f"[QUIC] JSON message: {json.dumps(msg)[:300]}")
                            if msg.get("type") == "response":
                                talk_sid = msg.get("params", {}).get("session_id")
                                if talk_sid and stream_id in relay_sessions:
                                    relay_sessions[stream_id]["talk_session_id"] = talk_sid
                                    print(f"[QUIC] Talk session_id: {talk_sid}")
                            elif msg.get("type") == "notification" and msg.get("params", {}).get("event_type") == "stream_status":
                                if msg["params"].get("status") == "finished":
                                    print(f"[QUIC] Camera stream finished")
                                    break
                        except Exception:
                            pass

            heartbeat_task.cancel()
            print(f"[QUIC] Stream ended. Total: {chunk_count} chunks, {bytes_total / 1024:.0f} KB, {ffmpeg_restarts} restarts")

    except Exception as e:
        print(f"[QUIC] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        for q in audio_subscribers.pop(stream_id, []):
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                pass
        if ffmpeg_proc:
            try:
                ffmpeg_proc.stdin.close()
                ffmpeg_proc.wait(timeout=5)
            except Exception:
                try:
                    ffmpeg_proc.kill()
                except Exception:
                    pass
        print(f"[QUIC] Cleanup done for {stream_id}")


async def _relay_heartbeat_quic(protocol, stream_id: int, stop_event: asyncio.Event):
    try:
        while not stop_event.is_set():
            await asyncio.sleep(RELAY_HEARTBEAT_INTERVAL)
            if stop_event.is_set():
                break
            heartbeat = json.dumps({"type": "notification", "params": {"event_type": "heartbeat"}}, separators=(",", ":")).encode()
            msg = b"--" + RELAY_CLIENT_BOUNDARY + b"\r\n"
            msg += b"Content-Type: application/json\r\n"
            msg += f"Content-Length: {len(heartbeat)}\r\n".encode()
            msg += b"\r\n"
            msg += heartbeat + b"\r\n"
            try:
                protocol._http.send_data(stream_id, msg, end_stream=False)
                protocol.transmit()
                print(f"[QUIC] Heartbeat sent")
            except Exception:
                break
    except asyncio.CancelledError:
        pass


def _iot_headers(use_jwt: bool = False) -> dict:
    headers = {
        "App-Cid": f"app:TP-Link_Tapo_Android:{cloud_state['terminal_uuid']}",
        "X-App-Name": "TP-Link_Tapo_Android",
        "X-App-Version": "3.18.116",
        "X-Term-Id": cloud_state["terminal_uuid"],
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "TP-Link_Tapo_Android/3.18.116",
    }
    if use_jwt and cloud_state.get("jwt"):
        headers["Authorization"] = cloud_state["jwt"]
    else:
        headers["Authorization"] = f"ut|{cloud_state['token']}"
    return headers


async def _ensure_jwt(client: httpx.AsyncClient):
    if cloud_state.get("jwt") and time.time() < cloud_state.get("jwt_expires", 0) - 300:
        return

    security_url = cloud_state.get("security_url")
    if not security_url:
        security_url = "https://aps1-security.iot.i.tplinknbu.com"

    body = {
        "appType": "TP-Link_Tapo_Android",
        "terminalUUID": cloud_state["terminal_uuid"],
        "token": f"ut|{cloud_state['token']}",
    }
    headers = _iot_headers()
    headers["Authorization-Required"] = "false"

    print(f"[JWT] POST {security_url}/v2/auth/app")
    print(f"[JWT] Body: {json.dumps(body)[:200]}")
    resp = await client.post(f"{security_url}/v2/auth/app", json=body, headers=headers)
    print(f"[JWT] Response: {resp.status_code} {resp.text[:500]}")
    resp.raise_for_status()
    data = resp.json()
    print(f"[JWT] Auth response: {json.dumps(data)[:300]}")

    jwt_token = data.get("jwt", "")
    expires_in = data.get("jwtExpiresIn", 86400)
    cloud_state["jwt"] = jwt_token
    cloud_state["jwt_expires"] = time.time() + expires_in


async def _get_things(client: httpx.AsyncClient) -> list:
    iot_url = cloud_state.get("iot_server_url")
    if not iot_url:
        iot_url = "https://aps1-app-server.iot.i.tplinkcloud.com"

    headers = _iot_headers()
    resp = await client.get(f"{iot_url}/v2/things?page=0&pageSize=100", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    things = data.get("data", [])
    print(f"[THINGS] Got {len(things)} things")

    global iot_things_cache
    for t in things:
        iot_things_cache[t.get("thingName", "")] = t
    return things


def _get_thing(device_id: str) -> dict:
    return iot_things_cache.get(device_id, {})


async def _services_sync(client: httpx.AsyncClient, device_id: str, request_data: dict, use_edge: bool = True) -> dict:
    thing = _get_thing(device_id)

    if use_edge:
        base_url = thing.get("edgeAppServerUrlV2") or thing.get("edgeAppServerUrl")
    else:
        base_url = thing.get("appServerUrlV2") or thing.get("appServerUrl")

    if not base_url:
        base_url = cloud_state.get("iot_server_url", "https://aps1-app-server.iot.i.tplinkcloud.com")

    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"

    body = {
        "inputParams": {
            "requestData": request_data,
        },
        "serviceId": "passthrough",
    }
    headers = _iot_headers(use_jwt=use_edge)
    url = f"{base_url}/v1/things/{device_id}/services-sync"
    print(f"[SYNC] POST {url}")
    print(f"[SYNC] Headers: {json.dumps({k: v[:60] for k, v in headers.items()})}")
    print(f"[SYNC] Body: {json.dumps(body)[:500]}")

    resp = await client.post(url, json=body, headers=headers, timeout=30)
    print(f"[SYNC] Response: {resp.status_code} {resp.text[:500]}")
    if resp.status_code != 200:
        try:
            err = resp.json()
        except Exception:
            err = {"raw": resp.text[:300]}
        raise HTTPException(resp.status_code, f"services-sync failed: {json.dumps(err)[:300]}")
    data = resp.json()
    print(f"[SYNC] Response: {json.dumps(data)[:500]}")

    output = data.get("outputParams", {}).get("responseData", {})
    ec = output.get("error_code", 0)
    if ec and ec < 0:
        raise HTTPException(400, f"Device error {ec}: {json.dumps(output)[:300]}")

    return output.get("result", output)


@app.post("/api/live/start")
async def live_start(request: Request):
    _require_login()
    body = await request.json()
    device_id = body.get("device_id")
    resolution = body.get("resolution", "VGA")

    if not device_id:
        raise HTTPException(400, "device_id required")

    stream_id = device_id[:16]

    # Reuse existing active stream
    existing = relay_sessions.get(stream_id)
    if existing and not existing["task"].done():
        playlist = existing["stream_dir"] / "index.m3u8"
        return {
            "status": "ok",
            "stream_id": stream_id,
            "hls_url": f"/api/live/stream/{stream_id}/index.m3u8",
            "reused": True,
        }

    # Stop stale session if exists
    if stream_id in relay_sessions:
        await _stop_relay_session(stream_id)

    stream_dir = HLS_DIR / f"live_{stream_id}"
    stream_dir.mkdir(parents=True, exist_ok=True)
    for f in stream_dir.iterdir():
        f.unlink()

    async with httpx.AsyncClient(verify=False) as client:
        if device_id not in iot_things_cache:
            await _get_things(client)
        await _ensure_jwt(client)

        # Step 1: Request relay + P2P init in parallel
        cipc_url = _get_cipc_url()
        relay_body = {
            "cloudType": 2,
            "customParams": json.dumps({"audio_config": {"encode_type": "G711ulaw", "sample_rate": "16"}}),
            "dataTimeoutCount": 0,
            "deviceId": device_id,
            "deviceType": "SMART.IPCAMERA",
            "playerId": cloud_state["terminal_uuid"],
            "preConnection": 0,
            "resolution": resolution,
            "rootCaVer": "1",
            "streamType": 0,
            "trackId": str(uuid.uuid4()),
        }
        relay_headers = {
            "Authorization": cloud_state["token"],
            "Content-Type": "application/json; charset=UTF-8",
            "User-Agent": "Tapo_APP/Phone/3.18.116_Android/Android 15",
            "Accept": "*/*",
            "X-Client-Id": cloud_state["terminal_uuid"],
            "X-Source": "tapo-app",
            "X-Brand": "TPLINK",
            "X-Ca-Type": "cloud-self",
        }

        nonce = ''.join(__import__('random').choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
        p2p_request = {
            "p2p": {
                "request_p2p": {
                    "version": "1.1",
                    "app_imp_version": 4,
                    "pub_ip": "0.0.0.0",
                    "pub_port": 0,
                    "pri_ip": "0.0.0.0",
                    "pri_port": 0,
                    "nat_type": 6,
                    "stun_url": "stun.tplinkcloud.com",
                    "punch_version": 3,
                    "punch_maxfds": 128,
                    "punch_timeout": 30,
                    "cone2symm_interval": 10,
                    "symm2cone_interval": 80,
                    "app_nonce": nonce,
                },
            },
            "method": "do",
        }

        print(f"[LIVE] Requesting relay + P2P in parallel for {device_id}...")
        relay_coro = client.post(
            f"{cipc_url}/v2/relay/request",
            json=relay_body,
            headers=relay_headers,
            timeout=15,
        )
        p2p_coro = _services_sync(client, device_id, p2p_request, use_edge=True)
        relay_resp, p2p_result = await asyncio.gather(relay_coro, p2p_coro)

        relay_data = relay_resp.json()
        print(f"[LIVE] Relay response: {json.dumps(relay_data)[:2000]}")

        relay_ec = relay_data.get("errorCode", 0)
        if relay_ec != 0:
            raise HTTPException(400, f"Relay error {relay_ec}: {relay_data.get('message', '')}")

        relay_result = relay_data.get("result", {})
        relay_url = relay_result.get("relayUrl", "")
        relay_token = relay_result.get("relayToken", "")
        relay_ip = relay_result.get("relayIp", "")
        cdn_url = relay_result.get("cdnUrl", "")
        relay_business_url = relay_result.get("relayBusinessUrl", "")
        concurrent_type = relay_result.get("concurrentType", [])

        sid = p2p_result.get("sid", "")
        is_ready = p2p_result.get("is_ready", 0)
        print(f"[LIVE] P2P init: sid={sid} is_ready={is_ready}")

        # Step 2: Poll is_p2p_ready (fast polling)
        camera_info = {}
        for attempt in range(15):
            if is_ready == 1:
                camera_info = p2p_result
                break

            await asyncio.sleep(0.5)
            ready_request = {
                "p2p": {
                    "is_p2p_ready": {
                        "sid": sid,
                    },
                },
                "method": "do",
            }
            p2p_result = await _services_sync(client, device_id, ready_request, use_edge=True)
            is_ready = p2p_result.get("is_ready", 0)
            print(f"[LIVE] P2P ready check #{attempt + 1}: is_ready={is_ready}")
            if is_ready == 1:
                camera_info = p2p_result
                break

        if is_ready != 1:
            raise HTTPException(504, "Camera P2P not ready after timeout")

    # Step 4: Start relay connection in background
    stop_event = asyncio.Event()
    use_cdn = "cdn_quic" in concurrent_type and cdn_url and relay_business_url
    task = asyncio.create_task(
        _relay_connect(
            relay_url, relay_token, relay_ip, stream_dir, stop_event, stream_id,
            resolution, sid, cdn_url if use_cdn else "", relay_business_url if use_cdn else "",
        )
    )
    relay_sessions[stream_id] = {
        "task": task,
        "ffmpeg_proc": None,
        "stop_event": stop_event,
        "stream_dir": stream_dir,
        "device_id": device_id,
    }

    return {
        "status": "ok",
        "stream_id": stream_id,
        "hls_url": f"/api/live/stream/{stream_id}/index.m3u8",
        "relay": {
            "ip": relay_ip,
            "quicEnable": relay_result.get("quicEnable", 0),
        },
        "camera": {
            "sid": sid,
            "pub_ip": camera_info.get("pub_ip", ""),
            "pub_port": camera_info.get("pub_port", 0),
        },
    }


async def _stop_relay_session(stream_id: str):
    session = relay_sessions.pop(stream_id, None)
    if not session:
        return
    session["stop_event"].set()
    proc = session.get("ffmpeg_proc")
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass
    task = session.get("task")
    if task and not task.done():
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    # Clean up HLS files
    stream_dir = session.get("stream_dir")
    if stream_dir and stream_dir.exists():
        for f in stream_dir.iterdir():
            try:
                f.unlink()
            except Exception:
                pass
    print(f"[LIVE] Session {stream_id} stopped")


@app.post("/api/live/stop")
async def live_stop(request: Request):
    _require_login()
    body = await request.json()
    stream_id = body.get("stream_id", "")
    if stream_id:
        await _stop_relay_session(stream_id)
    else:
        for sid in list(relay_sessions.keys()):
            await _stop_relay_session(sid)
    return {"status": "ok"}


@app.get("/api/live/stream/{stream_id}/index.m3u8")
async def live_hls_playlist(stream_id: str):
    playlist = HLS_DIR / f"live_{stream_id}" / "index.m3u8"
    if not playlist.exists():
        raise HTTPException(404, "Stream not ready yet")
    return FileResponse(playlist, media_type="application/vnd.apple.mpegurl",
                        headers={"Cache-Control": "no-cache, no-store"})


@app.get("/api/live/stream/{stream_id}/{segment}")
async def live_hls_segment(stream_id: str, segment: str):
    seg_path = HLS_DIR / f"live_{stream_id}" / segment
    if not seg_path.exists():
        raise HTTPException(404, "Segment not found")
    return FileResponse(seg_path, media_type="video/mp2t")


@app.get("/api/live/status/{stream_id}")
async def live_status(stream_id: str):
    session = relay_sessions.get(stream_id)
    if not session:
        return {"active": False}
    playlist = session["stream_dir"] / "index.m3u8"
    return {
        "active": not session["task"].done(),
        "hls_ready": playlist.exists() and playlist.stat().st_size > 100,
        "device_id": session["device_id"],
    }


@app.post("/api/live/talk/start")
async def talk_start(request: Request):
    _require_login()
    body = await request.json()
    stream_id = body.get("stream_id", "")
    session = relay_sessions.get(stream_id)
    if not session:
        raise HTTPException(404, "Stream not found")
    protocol = session.get("quic_protocol")
    quic_sid = session.get("quic_stream_id")
    if not protocol or quic_sid is None:
        raise HTTPException(400, "QUIC connection not ready")

    device_id = session.get("device_id", "")
    seq = session.get("talk_seq", 3)

    talk_req = json.dumps({
        "type": "request",
        "seq": seq,
        "params": {
            "talk": {
                "channel": 0,
                "deviceId": device_id,
                "mode": "half_duplex",
            },
            "method": "get",
        },
    }, separators=(",", ":")).encode()

    msg = b"--" + RELAY_CLIENT_BOUNDARY + b"\r\n"
    msg += b"Content-Type: application/json\r\n"
    msg += f"Content-Length: {len(talk_req)}\r\n".encode()
    msg += b"\r\n"
    msg += talk_req

    try:
        protocol._http.send_data(quic_sid, msg, end_stream=False)
        protocol.transmit()
        session["talk_seq"] = seq + 1
        session["talk_session_id"] = None
        print(f"[TALK] Sent talk start for {device_id} on stream {stream_id}, seq={seq}")
    except Exception as e:
        raise HTTPException(500, f"Failed to start talk: {e}")

    return {"status": "ok"}


@app.post("/api/live/talk/send")
async def talk_send(request: Request):
    _require_login()
    stream_id = request.query_params.get("stream_id", "")
    session = relay_sessions.get(stream_id)
    if not session:
        raise HTTPException(404, "Stream not found")
    protocol = session.get("quic_protocol")
    quic_sid = session.get("quic_stream_id")
    if not protocol or quic_sid is None:
        raise HTTPException(400, "QUIC connection not ready")

    audio_data = await request.body()
    if not audio_data:
        return {"status": "ok"}

    talk_sid = session.get("talk_session_id", "")
    talk_chunks = session.get("talk_chunks_sent", 0)

    msg = b"--" + RELAY_CLIENT_BOUNDARY + b"\r\n"
    msg += b"X-If-Encrypt: 0\r\n"
    if talk_sid:
        msg += f"X-Session-Id: {talk_sid}\r\n".encode()
    msg += b"Content-Type: audio/mp2t\r\n"
    msg += f"Content-Length: {len(audio_data)}\r\n".encode()
    msg += b"\r\n"
    msg += audio_data

    try:
        protocol._http.send_data(quic_sid, msg, end_stream=False)
        protocol.transmit()
        talk_chunks += 1
        session["talk_chunks_sent"] = talk_chunks
        if talk_chunks <= 3 or talk_chunks % 20 == 0:
            print(f"[TALK] Sent audio frame #{talk_chunks}: {len(audio_data)} bytes, session_id={talk_sid}")
    except Exception as e:
        raise HTTPException(500, f"Failed to send audio: {e}")

    return {"status": "ok"}


@app.post("/api/live/talk/stop")
async def talk_stop(request: Request):
    _require_login()
    body = await request.json()
    stream_id = body.get("stream_id", "")
    session = relay_sessions.get(stream_id)
    if not session:
        raise HTTPException(404, "Stream not found")
    protocol = session.get("quic_protocol")
    quic_sid = session.get("quic_stream_id")
    if not protocol or quic_sid is None:
        return {"status": "ok"}

    seq = session.get("talk_seq", 4)
    talk_sid = session.get("talk_session_id", "")

    stop_req = json.dumps({
        "type": "request",
        "seq": seq,
        "params": {
            "stop": "null",
            "method": "do",
        },
    }, separators=(",", ":")).encode()

    msg = b"--" + RELAY_CLIENT_BOUNDARY + b"\r\n"
    if talk_sid:
        msg += f"X-Session-Id: {talk_sid}\r\n".encode()
    msg += b"Content-Type: application/json\r\n"
    msg += f"Content-Length: {len(stop_req)}\r\n".encode()
    msg += b"\r\n"
    msg += stop_req

    try:
        protocol._http.send_data(quic_sid, msg, end_stream=False)
        protocol.transmit()
        session["talk_seq"] = seq + 1
        session["talk_session_id"] = None
        print(f"[TALK] Stopped talk session on stream {stream_id}")
    except Exception as e:
        print(f"[TALK] Error stopping: {e}")

    return {"status": "ok"}


@app.websocket("/api/live/audio/{stream_id}")
async def live_audio_ws(ws: WebSocket, stream_id: str):
    await ws.accept()
    q: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=50)
    subs = audio_subscribers.get(stream_id)
    if subs is None:
        await ws.close(code=1008, reason="Stream not found")
        return
    subs.append(q)
    print(f"[AUDIO-WS] Client connected for {stream_id}")
    try:
        while True:
            data = await q.get()
            if data is None:
                break
            await ws.send_bytes(data)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            subs.remove(q)
        except ValueError:
            pass
        print(f"[AUDIO-WS] Client disconnected for {stream_id}")


# --- Static ---


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def main():
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    main()
