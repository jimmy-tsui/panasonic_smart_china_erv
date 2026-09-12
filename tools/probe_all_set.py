"""Extended probe: try Info-family payload on EVERY candidate SET endpoint.

The earlier verify_set_works.py showed that InfoERV / InfoFloorPlacedERV
accept our Info-family payload and return todoId, but the device never
acts on it. Two possibilities:

1. The cloud queues everything as todoId without processing - the device
   only listens for specific endpoints (likely Info-family needs a
   different endpoint for this device category).
2. The Info-family payload format is correct but applied to the WRONG
   endpoint - the device uses an old-protocol endpoint (e.g.
   ADevSetStatusMidERV) but with the Info-family payload shape.

This script tries both Info-family + every possible old-protocol endpoint
with the Info-family payload shape, toggling holidayMode each time to
verify whether the command actually reaches the device.

If ALL 14 combos fail to change device state, the conclusion is:
- Either the device is controlled via a LAN/local protocol (not cloud)
- Or the device is in a state where it doesn't accept cloud commands
  (e.g. needs initial pairing, or account lacks control privilege)

Usage:
    PMS_USER='phone' PMS_PASS='password' python tools/probe_all_set.py
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


async def fetch_status_all(session, usr_id, ssid, family_id, real_family_id, device_id):
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
            return {k: (int(v) if isinstance(v, str) and v.lstrip("-").isdigit() else v)
                    for k, v in status_all.items()}
    return {}


async def fetch_get_endpoint_info_family(session, ssid, endpoint, usr_id, device_id, token):
    """GET an Info-family endpoint with proper payload (identity at top level)."""
    async with session.post(
        BASE_URL + endpoint,
        json={"id": 2, "usrId": usr_id, "deviceId": device_id, "token": token},
        headers={"User-Agent": "SmartApp", "Content-Type": "application/json",
                 "Cookie": f"SSID={ssid}", "xtoken": f"SSID={ssid}"},
        ssl=psmartcloud_fingerprint(),
    ) as r:
        try:
            body = await r.json(content_type=None)
        except Exception:
            body = {"rawText": (await r.text())[:300]}
    return r.status, body


async def send_set(session, ssid, endpoint, payload, info_family_payload=False):
    """Send SET. If info_family_payload=True, use Info format (identity at top + xtoken)."""
    headers = {"User-Agent": "SmartApp", "Content-Type": "application/json",
               "Cookie": f"SSID={ssid}"}
    if info_family_payload:
        headers["xtoken"] = f"SSID={ssid}"
    try:
        async with session.post(BASE_URL + endpoint, json=payload, headers=headers,
                                 ssl=psmartcloud_fingerprint()) as r:
            try:
                body = await r.json(content_type=None)
            except Exception:
                body = {"rawText": (await r.text())[:300]}
            return r.status, body
    except Exception as e:
        return None, {"error": str(e)}


# All candidate SET endpoints
CANDIDATE_SET_ENDPOINTS = [
    # Info-family variants
    "ADevSetStatusInfoERV",
    "ADevSetStatusInfoFloorPlacedERV",
    "ADevSetStatusInfoCABINET",
    "ADevSetStatusInfoCABINET02",
    "ADevSetStatusInfoCABINET-02",
    "ADevSetStatusInfoCABINET2",
    # Old protocol (try with Info payload)
    "ADevSetStatusERV",
    "ADevSetStatusFloorPlacedERV",
    "ADevSetStatusMidERV",
    "ADevSetStatusSmallERV",
    "ADevSetStatusDCERV",
    "ADevSetStatusNewDCERV",
    "ADevSetStatusLD6C",
    "ADevSetStatusNeedsAP",
    "ADevSetStatusJDNeedsAP",
]


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
        print()

        token = device_token(device_id)
        if not token:
            print("ERROR: device token gen failed", file=sys.stderr)
            sys.exit(1)

        print("=== 第一阶段：GET Info 家族端点（用 Info payload） ===")
        for ep in ["ADevGetStatusInfoERV", "ADevGetStatusInfoFloorPlacedERV"]:
            print(f"  GET {ep}...")
            http, body = await fetch_get_endpoint_info_family(session, ssid, ep, usr_id, device_id, token)
            err = body.get("error") if isinstance(body, dict) else None
            results = body.get("results") if isinstance(body, dict) else None
            if results:
                print(f"    HTTP {http}  fields={len(results)}  keys={sorted(results.keys())[:15]}{'...' if len(results) > 15 else ''}")
            elif err:
                print(f"    HTTP {http}  error: {err}")
            else:
                print(f"    HTTP {http}  body: {body}")
        print()

        print("=== 第二阶段：每个候选 SET 端点切换 holidayMode ===")
        before = await fetch_status_all(session, usr_id, ssid, family_id, real_family_id, device_id)
        cur = int(before.get("holidayMode", 0))
        print(f"  当前 holidayMode = {cur}")
        print()

        results_summary = []
        for ep in CANDIDATE_SET_ENDPOINTS:
            target = 1 - cur
            # Use Info-family payload for ALL endpoints (long field names,
            # identity at top, xtoken header). This is the most permissive
            # shape - if the cloud accepts old-protocol endpoints with this
            # format, we'll see the device respond.
            payload = {
                "id": 2,
                "usrId": usr_id,
                "deviceId": device_id,
                "token": token,
                "params": {"holidayMode": target},
            }
            http, body = await send_set(session, ssid, ep, payload, info_family_payload=True)
            todo_id = body.get("results", {}).get("todoId") if isinstance(body, dict) else None
            err = body.get("error") if isinstance(body, dict) else None

            await asyncio.sleep(3)
            after = await fetch_status_all(session, usr_id, ssid, family_id, real_family_id, device_id)
            new = int(after.get("holidayMode", 0))
            changed = (new == target)

            verdict = "✓ CHANGED" if changed else "✗ no change"
            err_str = f" err={err}" if err else ""
            todo_str = f" todo={todo_id}" if todo_id else ""
            print(f"  {ep:40s}  HTTP {str(http):4s}{todo_str}{err_str}  holiday {cur}→sent {target}→got {new}  {verdict}")
            results_summary.append((ep, http, changed))

            # Revert if changed
            if changed:
                revert_payload = {
                    "id": 2,
                    "usrId": usr_id,
                    "deviceId": device_id,
                    "token": token,
                    "params": {"holidayMode": cur},
                }
                await send_set(session, ssid, ep, revert_payload, info_family_payload=True)
                await asyncio.sleep(2)
                cur = int((await fetch_status_all(session, usr_id, ssid, family_id, real_family_id, device_id)).get("holidayMode", 0))

        print()
        print("=== 总结 ===")
        working = [ep for ep, _, changed in results_summary if changed]
        if working:
            print(f"  ✓ 能用的端点: {working}")
        else:
            print(f"  ✗ 全部 15 个候选端点都未触发设备响应")
            print()
            print("可能的原因：")
            print("  1. 设备不接受云端控制（仅 LAN 直连）")
            print("  2. 账号没有控制权限（只读账户）")
            print("  3. 设备未完成 initial pairing")
            print("  4. SET 需要走完全不同的 API（不是 ADevSetStatus* 家族）")


if __name__ == "__main__":
    asyncio.run(main())
