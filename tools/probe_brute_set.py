"""Brute-force Info-family SET endpoint names for FY-50ZR1C.

The endpoint suffix for each device family is hardcoded in mcdona1d's
project (no auto-discovery). Patterns we've seen:
- devSubTypeId == endpoint suffix: LD6C, DCERV, MidERV, SmallERV
- devSubTypeId + 'Info' prefix: LD5C -> InfoLD5C
- Mystery name (bathroom heater): FV54BA1C (not the model name)
- The 'Aircle-XX-XX' suffix appears in deviceId but isn't the endpoint

For FY-50ZR1C (devSubTypeId=CABINET-02), we've tried the obvious
candidates (CABINET, CABINET-02, InfoCABINET, InfoCABINET-02) - all 404.

This script tries a wide range of guesses derived from:
- Model name parts: FY, 50, ZR1, ZR1C, FY-50ZR1C, FY50ZR1C, etc.
- Suffix parts: Aircle, Aircle06, Aircle0601
- Category: ERV, 0800
- Common Panasonic device codes: ERVBOX, CABINET02, etc.

For each candidate, send a real toggle (holidayMode) and verify state.

Usage:
    PMS_USER='phone' PMS_PASS='password' python tools/probe_brute_set.py
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

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


async def login(session, username, password):
    async with session.post(
        BASE_URL + "UsrGetToken",
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
        BASE_URL + "UsrLogin",
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
        BASE_URL + "UsrGetBindDevInfo",
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


async def fetch_status_all(session, usr_id, ssid, family_id, real_family_id, device_id):
    async with session.post(
        BASE_URL + "UsrGetBindDevInfo",
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
            return {k: (int(v) if isinstance(v, str) and v.lstrip("-").isdigit() else v)
                    for k, v in status_all.items()}
    return {}


async def send_set_iPhone_style(session, ssid, endpoint, payload):
    """Send SET using mcdona1d's exact iPhone User-Agent + xtoken + ssl=False style."""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X)",
        "xtoken": f"SSID={ssid}",
        "DNT": "1",
        "Origin": "https://app.psmartcloud.com",
        "X-Requested-With": "XMLHttpRequest",
    }
    try:
        async with session.post(BASE_URL + endpoint, json=payload, headers=headers,
                                 ssl=False) as r:
            try:
                body = await r.json(content_type=None)
            except Exception:
                body = {"rawText": (await r.text())[:200]}
            return r.status, body
    except Exception as e:
        return None, {"error": str(e)}


async def try_toggle(session, ssid, usr_id, family_id, real_family_id, device_id, token,
                     endpoint, target):
    """Try toggling holidayMode via this endpoint. Returns True if state changed."""
    payload = {
        "id": 52,
        "usrId": usr_id,
        "deviceId": device_id,
        "token": token,
        "params": {"holidayMode": target},
    }
    http, body = await send_set_iPhone_style(session, ssid, endpoint, payload)
    await asyncio.sleep(3)
    after = await fetch_status_all(session, usr_id, ssid, family_id, real_family_id, device_id)
    new = int(after.get("holidayMode", 0))
    return http, body, new == target, new


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
        dev_sub_type = device.get("params", {}).get("devSubTypeId")
        print(f"  devSubTypeId={dev_sub_type}")
        # Also dump other potentially useful params
        for key, val in device.get("params", {}).items():
            if key in ("statusAll", "devList", "params"):
                continue
            print(f"  {key}: {val}")
        print()
        token = device_token(device_id)
        if not token:
            print("ERROR: device token gen failed", file=sys.stderr)
            sys.exit(1)

        # Candidate endpoint names derived from various sources
        candidates = [
            # From devSubTypeId
            "CABINET02", "CABINET-02", "CABINET02C", "CABINET-02C",
            "CABINET2", "CABINET-2", "CabinetERV02", "CabinetERV-02",
            # From model FY-50ZR1C
            "FY50ZR1C", "FY-50ZR1C", "FY50ZR1", "FY50ZR", "FY50Z",
            "50ZR1C", "ZR1C", "ZR1", "ZR", "FY",
            # From Aircle-06-01
            "Aircle06-01", "Aircle0601", "Aircle06", "Aircle06_01",
            "Aircle0601C", "Aircle-06", "Aircle06C", "Aircle",
            # From category
            "ERV", "ERV0800", "ERV-0800", "ERV08",
            # From cabinet variant
            "CABINET02ERV", "CabinetERV02",
            # Other Panasonic naming guesses
            "FY50ZR1CERV", "FYZR1C", "AircleERV",
        ]

        # Construct full path candidates (with both Info and non-Info prefixes)
        full_endpoints = []
        for prefix in ["ADevSetStatusInfo", "ADevSetStatus"]:
            for cand in candidates:
                full_endpoints.append(prefix + cand)

        # Also try with our previously successful patterns just for completeness
        # (InfoERV / InfoFloorPlacedERV) - already known not to work but listed
        # for cross-reference

        print(f"→ Will test {len(full_endpoints)} endpoint name candidates...")
        print(f"→ Initial holidayMode = ?")
        before = await fetch_status_all(session, usr_id, ssid, family_id, real_family_id, device_id)
        cur = int(before.get("holidayMode", 0))
        print(f"  holidayMode={cur}")
        print()

        results = []
        for ep in full_endpoints:
            target = 1 - cur
            http, body, changed, new = await try_toggle(
                session, ssid, usr_id, family_id, real_family_id, device_id, token, ep, target
            )
            todo_id = body.get("results", {}).get("todoId") if isinstance(body, dict) else None
            verdict = "✓ CHANGED" if changed else "✗ no change"
            extra = ""
            if isinstance(body, dict) and "error" in body and not todo_id:
                extra = f" err={body['error']}"
            elif http == 404:
                extra = ""
            print(f"  {ep:45s}  HTTP {str(http):4s}  holiday {cur}→{target}→{new}  {verdict}{extra}")
            results.append((ep, http, changed))

            # Revert if changed
            if changed:
                revert_payload = {
                    "id": 52, "usrId": usr_id, "deviceId": device_id,
                    "token": token, "params": {"holidayMode": cur},
                }
                await send_set_iPhone_style(session, ssid, ep, revert_payload)
                await asyncio.sleep(2)
                cur = int((await fetch_status_all(session, usr_id, ssid, family_id, real_family_id, device_id)).get("holidayMode", 0))

        print()
        working = [ep for ep, _, c in results if c]
        if working:
            print(f"=== ✓ 工作端点: {working} ===")
        else:
            print(f"=== ✗ 全部 {len(full_endpoints)} 个候选端点都没反应 ===")
            print()
            print("结论：这个设备的 SET 端点名称不属于以上任何变体。")
            print("可能需要：")
            print("1. 用手机 App + Charles/mitmproxy 抓包，看 SET 实际走的 URL")
            print("2. 联系松下官方技术支持")
            print("3. 看其他社区用户的发现")


if __name__ == "__main__":
    asyncio.run(main())
