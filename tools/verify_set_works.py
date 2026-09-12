"""Aggressive probe: send actual state changes and verify they apply.

Unlike probe_set_endpoints.py which sends idempotent SETs, this script
toggles a reversible setting (holidayMode) so we can definitively tell
whether the SET command actually reaches the device (not just whether
the cloud returns a todoId).

Probes each candidate Info-family SET endpoint with multiple request
shapes:
- Different request id (0, 1, 2)
- Minimal bean vs full bean
- With/without xtoken header
- Holiday mode toggle (0 -> 1 -> 0) so the device ends in the same state

Usage:
    PMS_USER='phone' PMS_PASS='password' python tools/verify_set_works.py
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import aiohttp

REPO_ROOT = Path(__file__).resolve().parents[1]
TLS_PATH = REPO_ROOT / "custom_components" / "panasonic_smart_china" / "tls.py"

_TLS_SPEC = importlib.util.spec_from_file_location("panasonic_tls", TLS_PATH)
if _TLS_SPEC is None or _TLS_SPEC.loader is None:
    raise RuntimeError(f"Unable to load TLS helper from {TLS_PATH}")
_TLS_MODULE = importlib.util.module_from_spec(_TLS_SPEC)
_TLS_SPEC.loader.exec_module(_TLS_MODULE)
psmartcloud_fingerprint = _TLS_MODULE.psmartcloud_fingerprint

BASE_URL = "https://app.psmartcloud.com/App/"
URL_GET_TOKEN = BASE_URL + "UsrGetToken"
URL_LOGIN = BASE_URL + "UsrLogin"
URL_GET_DEV = BASE_URL + "UsrGetBindDevInfo"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("***" if k.lower() in {"token", "pwd", "ssid", "usrid", "deviceid", "password"} else v)
                for k, v in value.items()}
    return value


async def login(session, username, password):
    async with session.post(
        URL_GET_TOKEN,
        json={"id": 1, "uiVersion": 4.0, "params": {"usrId": username}},
        headers={"User-Agent": "SmartApp", "Content-Type": "application/json"},
        ssl=psmartcloud_fingerprint(),
    ) as r:
        data = await r.json()
    token_start = data.get("results", {}).get("token")
    if not token_start:
        raise RuntimeError("GetToken failed")
    pwd_md5 = hashlib.md5(password.encode()).hexdigest().upper()
    inter = hashlib.md5((pwd_md5 + username).encode()).hexdigest().upper()
    final = hashlib.md5((inter + token_start).encode()).hexdigest().upper()
    async with session.post(
        URL_LOGIN,
        json={"id": 2, "uiVersion": 4.0,
              "params": {"telId": "00:00:00:00:00:00", "checkFailCount": 0,
                         "usrId": username, "pwd": final}},
        headers={"User-Agent": "SmartApp", "Content-Type": "application/json"},
        ssl=psmartcloud_fingerprint(),
    ) as r:
        data = await r.json()
    results = data.get("results", {})
    return results["usrId"], results["ssId"], results.get("familyId"), results.get("realFamilyId")


async def get_device(session, usr_id, ssid, family_id, real_family_id):
    async with session.post(
        URL_GET_DEV,
        json={"id": 3, "uiVersion": 4.0,
              "params": {"realFamilyId": real_family_id, "familyId": family_id, "usrId": usr_id}},
        headers={"User-Agent": "SmartApp", "Content-Type": "application/json",
                 "Cookie": f"SSID={ssid}"},
        ssl=psmartcloud_fingerprint(),
    ) as r:
        data = await r.json()
    for dev in data.get("results", {}).get("devList", []):
        if dev.get("deviceId"):
            return dev
    raise RuntimeError("No device found")


def device_token(device_id):
    parts = str(device_id).split("_")
    if len(parts) != 3:
        return None
    mac, cat, suffix = parts[0].upper(), parts[1].upper(), parts[2]
    if len(mac) < 6:
        return None
    inner = hashlib.sha512(f"{mac[6:]}_{cat}_{mac[:6]}".encode()).hexdigest()
    return hashlib.sha512(f"{inner}_{suffix}".encode()).hexdigest()


async def fetch_status_all_for_device(session, usr_id, ssid, family_id, real_family_id, device_id):
    """Fetch statusAll for a single device via UsrGetBindDevInfo."""
    async with session.post(
        URL_GET_DEV,
        json={"id": 3, "uiVersion": 4.0,
              "params": {"realFamilyId": real_family_id, "familyId": family_id, "usrId": usr_id}},
        headers={"User-Agent": "SmartApp", "Content-Type": "application/json",
                 "Cookie": f"SSID={ssid}"},
        ssl=psmartcloud_fingerprint(),
    ) as r:
        data = await r.json()
    for dev in data.get("results", {}).get("devList", []):
        if dev.get("deviceId") == device_id:
            status_all = dev.get("params", {}).get("statusAll") or {}
            # Convert to int
            return {k: (int(v) if isinstance(v, str) and v.lstrip("-").isdigit() else v)
                    for k, v in status_all.items()}
    return {}


async def send_set(session, url, payload, ssid, with_xtoken=True):
    headers = {
        "User-Agent": "SmartApp",
        "Content-Type": "application/json",
        "Cookie": f"SSID={ssid}",
    }
    if with_xtoken:
        headers["xtoken"] = f"SSID={ssid}"
    try:
        async with session.post(url, json=payload, headers=headers,
                                 ssl=psmartcloud_fingerprint()) as r:
            try:
                body = await r.json(content_type=None)
            except Exception:
                body = {"rawText": (await r.text())[:300]}
            return r.status, body
    except Exception as e:
        return None, {"error": str(e)}


# Full bean with all known long-name fields from statusAll (everything = 255 keep)
FULL_BEAN_255 = {
    "runningStatus": 255,
    "runningMode": 255,
    "airVolume": 255,
    "holidayMode": 255,
    "windPath": 255,
    "pPressureMode": 255,
    "heatingMode": 255,
    "alarmStatus": 255,
    "coldControlStatus": 255,
    "hardVersion": 255,
    "softVersion": 255,
    "panelLockSetting": 255,
    "CO2AutoSensitivity": 255,
    "PM25AutoSensitivity": 255,
    "pm25SensorClTimeLeft": 255,
    "oaFilterClTimeLeft": 255,
    "oaFilterExTimeLeft": 255,
    "saFilterClTimeLeft": 255,
    "saFilterExTimeLeft": 255,
    "oaFilterClCycle": 255,
    "oaFilterExCycle": 255,
    "saFilterClCycle": 255,
    "saFilterExist": 255,
    "oaHumidityCur": 255,
    "oaHumidityMax": 255,
    "oaTempCur": 255,
    "oaTempMax": 255,
    "oaPM25Cur": 255,
    "oaPM25Max": 255,
    "saHumidityCur": 255,
    "saHumidityMax": 255,
    "saTempCur": 255,
    "saTempMax": 255,
    "saPM25Cur": 255,
    "saPM25Max": 255,
    "raHumidityCur": 255,
    "raHumidityMax": 255,
    "raTempCur": 255,
    "raTempMax": 255,
    "raPM25Cur": 255,
    "raPM25Max": 255,
    "raCO2Cur": 255,
    "raCO2Max": 255,
    "purchaseRemindInfoFlg": 255,
    "resetOperationFlg": 255,
    "onTimerSetting": 255,
    "onTimerHour": 127,
    "onTimerMinute": 127,
    "offTimerSetting": 255,
    "offTimerHour": 127,
    "offTimerMinute": 127,
    "awakeTimeHour": 127,
    "awakeTimeMinute": 127,
    "sleepTimeHour": 127,
    "sleepTimeMinute": 127,
}


def make_payload(id_val, usr_id, device_id, token, bean):
    return {
        "id": id_val,
        "usrId": usr_id,
        "deviceId": device_id,
        "token": token,
        "params": dict(bean),
    }


async def try_toggle_holiday(session, ssid, usr_id, family_id, real_family_id,
                              device_id, token, endpoint, request_id, full_bean):
    """Try toggling holidayMode via this endpoint and verify state changed."""
    url = BASE_URL + endpoint
    bean_label = "FULL_BEAN" if full_bean else "MINIMAL_BEAN"

    # Read current holidayMode
    before = await fetch_status_all_for_device(session, usr_id, ssid, family_id, real_family_id, device_id)
    cur = int(before.get("holidayMode", 0))
    target = 1 - cur  # toggle

    # Build payload - either minimal (just holidayMode) or full bean
    if full_bean:
        params = dict(FULL_BEAN_255)
        params["holidayMode"] = target
    else:
        params = {"holidayMode": target}

    payload = make_payload(request_id, usr_id, device_id, token, params)
    http_status, response = await send_set(session, url, payload, ssid, with_xtoken=True)
    todo_id = response.get("results", {}).get("todoId") if isinstance(response, dict) else None
    err = response.get("error") if isinstance(response, dict) else None

    # Wait for cloud to propagate to device
    await asyncio.sleep(4)

    # Read state again
    after = await fetch_status_all_for_device(session, usr_id, ssid, family_id, real_family_id, device_id)
    new = int(after.get("holidayMode", 0))

    changed = (new == target)
    return {
        "endpoint": endpoint,
        "request_id": request_id,
        "bean": bean_label,
        "http": http_status,
        "todoId": todo_id,
        "error": err,
        "before_holidayMode": cur,
        "sent_target": target,
        "after_holidayMode": new,
        "state_changed": changed,
    }


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", default=os.environ.get("PMS_USER"))
    parser.add_argument("--pass", dest="password", default=os.environ.get("PMS_PASS"))
    args = parser.parse_args()
    if not args.user or not args.password:
        print("Set PMS_USER / PMS_PASS", file=sys.stderr)
        sys.exit(1)

    async with aiohttp.ClientSession() as session:
        print("→ Logging in...")
        usr_id, ssid, family_id, real_family_id = await login(session, args.user, args.password)
        print(f"  usrId={usr_id} familyId={family_id} realFamilyId={real_family_id}")

        device = await get_device(session, usr_id, ssid, family_id, real_family_id)
        device_id = device["deviceId"]
        print(f"  deviceId={device_id}")
        print(f"  devSubTypeId={device.get('params', {}).get('devSubTypeId')}")
        print()

        token = device_token(device_id)
        if not token:
            print("ERROR: device token gen failed", file=sys.stderr)
            sys.exit(1)

        print("→ Reading initial holidayMode state...")
        before = await fetch_status_all_for_device(session, usr_id, ssid, family_id, real_family_id, device_id)
        print(f"  holidayMode={before.get('holidayMode')}")
        print()

        endpoints_to_try = [
            "ADevSetStatusInfoFloorPlacedERV",
            "ADevSetStatusInfoERV",
        ]
        request_ids = [0, 1, 2]
        bean_types = [False, True]  # minimal then full

        results = []
        for ep in endpoints_to_try:
            for rid in request_ids:
                for full in bean_types:
                    print(f"→ Testing {ep} id={rid} {'FULL' if full else 'MINIMAL'} bean...")
                    result = await try_toggle_holiday(
                        session, ssid, usr_id, family_id, real_family_id,
                        device_id, token, ep, rid, full
                    )
                    results.append(result)
                    verdict = "✓ CHANGED" if result["state_changed"] else "✗ no change"
                    print(f"  HTTP {result['http']}  todoId={result['todoId']}  "
                          f"holiday {result['before_holidayMode']}→sent {result['sent_target']}→got {result['after_holidayMode']}  {verdict}")
                    print()

                    # Revert if we changed state
                    if result["state_changed"]:
                        print(f"  ↻ Reverting...")
                        bean = dict(FULL_BEAN_255) if full else {}
                        bean["holidayMode"] = result["before_holidayMode"]
                        payload = make_payload(rid, usr_id, device_id, token, bean)
                        await send_set(session, BASE_URL + ep, payload, ssid, with_xtoken=True)
                        await asyncio.sleep(3)
                        print()

        print()
        print("=== 总结 ===")
        print(f"{'Endpoint':42s} {'ID':3s} {'Bean':8s} {'HTTP':4s} {'todoId':10s} {'State':10s}")
        print("-" * 90)
        for r in results:
            verdict = "✓ CHANGED" if r["state_changed"] else "✗ unchanged"
            print(f"{r['endpoint']:42s} {r['request_id']:<3d} {r['bean']:8s} "
                  f"{str(r['http']):4s} {str(r['todoId'])[:10]:10s} {verdict}")


if __name__ == "__main__":
    asyncio.run(main())
