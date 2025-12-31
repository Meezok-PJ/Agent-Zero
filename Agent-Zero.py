#!/usr/bin/env python3
"""
Agent-Zero: Comprehensive Static & Dynamic Malware Analysis Tool
=================================================================

A defensive cybersecurity tool that performs comprehensive static and dynamic
analysis with stage-by-stage LLM validation and reporting.

Features:
- Multi-stage analysis pipeline with LLM confirmation at each stage
- Static analysis: String extraction (with FLOSS de-obfuscation), API categorization, pattern matching
- CAPA integration: MITRE ATT&CK TTP detection and static analysis
- Dynamic analysis: Hybrid Analysis (Falcon Sandbox) integration
- Robust JSON parsing with multiple fallback strategies
- VirusTotal integration with detailed engine analysis
- CSV dataset matching for known malware signatures
- Hard-coded behavioral pattern detection
- Comprehensive API categorization
- Stage-by-stage and final consolidated reporting
- Web interface with real-time progress updates

Requirements:
- requests, rich, python-dotenv, flask

Usage:
  python Agent-Zero.py --file <binary_path> [options]
  python Agent-Zero.py --web                              # Start web server
  python Agent-Zero.py --file <binary_path> --web         # Run analysis with web UI

Options:
  --model mistral          : LLM model to use
  --ollama-url <url>       : Ollama API endpoint
  --web                    : Start Flask web server
  --web-port <port>        : Web server port (default: 5000)
  --vt-only                : Quick VT + pattern check only
  --no-llm                 : Skip LLM, use heuristic analysis
  --no-vt                  : Skip VirusTotal lookup
  --no-dynamic             : Skip dynamic analysis (Hybrid Analysis)
  --no-capa                : Skip CAPA static analysis
  --capa-verbose           : Use CAPA verbose mode
  --no-floss               : Skip FLOSS string de-obfuscation
  --dataset-csv <path>     : CSV file with malware API signatures
  --stage-reports          : Generate individual reports for each stage
"""

import argparse
import csv
import json
import os
import re
import sys
import time
import subprocess
import hashlib
import threading
import uuid
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Flask import (optional for web mode)
FLASK_AVAILABLE = False
try:
    from flask import Flask, request, jsonify, render_template, send_file, Response, stream_with_context
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    pass

try:
    import requests
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    from rich.markdown import Markdown
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install: pip install requests rich")
    sys.exit(1)

# Dynamic analysis imports
load_dotenv_available = False
try:
    from dotenv import load_dotenv
    load_dotenv_available = True
except ImportError:
    pass

# ==================== CONSTANTS ====================
MIN_STRING_LENGTH = 4
MAX_TOP_STRINGS = 200
DEFAULT_MODEL = "mistral"
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_OUTDIR = "out"
DEFAULT_RETRIES = 3

# VirusTotal config
# Load environment variables if dotenv is available
if load_dotenv_available:
    try:
        load_dotenv()
    except:
        pass
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY")
VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/"

# Warn if VirusTotal API key is missing (will be printed after console is initialized)
_vt_key_missing = not VIRUSTOTAL_API_KEY

# Hybrid Analysis API endpoints
HYBRID_ANALYSIS_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
HYBRID_ANALYSIS_SUBMIT_HASH_URL = f"{HYBRID_ANALYSIS_BASE_URL}/submit/hash"
HYBRID_ANALYSIS_OVERVIEW_URL = f"{HYBRID_ANALYSIS_BASE_URL}/overview/{{sha256}}"
HYBRID_ANALYSIS_REPORT_URL = f"{HYBRID_ANALYSIS_BASE_URL}/report"
HYBRID_ANALYSIS_SUMMARY_URL = f"{HYBRID_ANALYSIS_BASE_URL}/report/{{job_id}}/summary"
HYBRID_ANALYSIS_STATE_URL = f"{HYBRID_ANALYSIS_BASE_URL}/report/{{job_id}}/state"

# Polling configuration for dynamic analysis
MAX_POLLING_TIME = 600  # 10 minutes
POLLING_INTERVAL = 10   # Check every 10 seconds
INITIAL_WAIT = 30       # Wait 30 seconds before first check

# Hard-coded sequences (TTPs)
MALICIOUS_API_SEQUENCES = {
    "PROCESS_INJECTION (T1055)": ["openprocess", "virtualallocex", "writeprocessmemory", "createremotethread"],
    "DEFENSE_EVASION (T1497)": ["isdebuggerpresent", "checkremotedebuggerpresent", "virtualalloc", "virtualprotect"],
    "RANSOMWARE_ENCRYPT (T1486)": ["cryptacquirecontext", "cryptencrypt", "createfile"],
    "NETWORK_C2 (T1071)": ["wsastartup", "internetopen", "connect", "httpsendrequest"],
    "CREDENTIAL_DUMPING (T1003)": ["lsass", "samlib", "credui", "wdigest"],
    "PRIVILEGE_ESCALATION (T1068)": ["adjusttokenprivileges", "duplicatetokenex", "impersonateloggedonuser"],
}

# Malicious API categories
MALICIOUS_API_CATEGORIES = {
    # Process/Memory Manipulation
    "openprocess": "Process/Memory Manipulation", "virtualallocex": "Process/Memory Manipulation",
    "virtualprotectex": "Process/Memory Manipulation", "writeprocessmemory": "Process/Memory Manipulation",
    "readprocessmemory": "Process/Memory Manipulation", "createremotethread": "Process/Memory Manipulation",
    "ntcreatethreadex": "Process/Memory Manipulation", "setthreadcontext": "Process/Memory Manipulation",
    "getthreadcontext": "Process/Memory Manipulation", "resumethread": "Process/Memory Manipulation",
    "suspendthread": "Process/Memory Manipulation", "queueuserapc": "Process/Memory Manipulation",
    "zwmapviewofsection": "Process/Memory Manipulation", "ntmapviewofsection": "Process/Memory Manipulation",
    "createtoolehelp32snapshot": "Process/Memory Manipulation", "virtualalloc": "Process/Memory Manipulation",
    "virtualprotect": "Process/Memory Manipulation",

    # Code Loading/API Resolution
    "loadlibrarya": "Code Loading/API Resolution", "loadlibraryw": "Code Loading/API Resolution",
    "loadlibraryex": "Code Loading/API Resolution", "getprocaddress": "Code Loading/API Resolution",
    "ldrloaddll": "Code Loading/API Resolution", "rtlcreateuserthread": "Code Loading/API Resolution",
    "setunhandledexceptionfilter": "Code Loading/API Resolution",

    # Process Creation/Execution
    "createprocessa": "Process Creation/Execution", "createprocessw": "Process Creation/Execution",
    "createprocessasuserw": "Process Creation/Execution", "createprocesswithtokenw": "Process Creation/Execution",
    "shellexecuteexa": "Process Creation/Execution", "shellexecuteexw": "Process Creation/Execution",
    "winexec": "Process Creation/Execution", "ntcreateprocessex": "Process Creation/Execution",

    # Service/Driver Manipulation
    "openscmanager": "Service/Driver Manipulation", "createservice": "Service/Driver Manipulation",
    "startservice": "Service/Driver Manipulation", "changeserviceconfig": "Service/Driver Manipulation",
    "deviceiocontrol": "Service/Driver Manipulation", "ntloaddriver": "Service/Driver Manipulation",

    # Registry/Persistence
    "regcreatekeyexa": "Registry/Persistence", "regcreatekeyexw": "Registry/Persistence",
    "regsetvalueexa": "Registry/Persistence", "regsetvalueexw": "Registry/Persistence",
    "regdeletekey": "Registry/Persistence", "regdeletevalue": "Registry/Persistence",
    "regqueryvalueex": "Registry/Persistence",

    # File System
    "createfilea": "File System", "createfilew": "File System", "writefile": "File System",
    "readfile": "File System", "copyfilea": "File System", "copyfilew": "File System",
    "movefileex": "File System", "deletefile": "File System", "createfilemapping": "File System",
    "mapviewoffile": "File System",

    # Networking
    "socket": "Networking", "connect": "Networking", "send": "Networking", "recv": "Networking",
    "wsastartup": "Networking", "wsasocket": "Networking", "wsarecv": "Networking", "wsasend": "Networking",
    "internetopen": "Networking", "internetconnect": "Networking", "httpopenrequest": "Networking",
    "httpsendrequest": "Networking", "winhttpopen": "Networking", "winhttpconnect": "Networking",
    "winhttpsendrequest": "Networking", "getaddrinfo": "Networking", "dnsquery_a": "Networking",
    "dnsquery_w": "Networking",

    # Lateral Movement/SMB
    "wnetaddconnection2": "Lateral Movement/SMB", "wnetuseconnection": "Lateral Movement/SMB",
    "netuseadd": "Lateral Movement/SMB", "netshareadd": "Lateral Movement/SMB",
    "netshareenum": "Lateral Movement/SMB", "netserverenum": "Lateral Movement/SMB",
    "netservergetinfo": "Lateral Movement/SMB", "netsessionenum": "Lateral Movement/SMB",
    "netfileenum": "Lateral Movement/SMB",

    # Auth/Privilege Escalation
    "openprocesstoken": "Auth/Privilege Escalation", "gettokeninformation": "Auth/Privilege Escalation",
    "adjusttokenprivileges": "Auth/Privilege Escalation", "lookupprivilegevalue": "Auth/Privilege Escalation",
    "duplicatetokenex": "Auth/Privilege Escalation", "impersonateloggedonuser": "Auth/Privilege Escalation",
    "logonusera": "Auth/Privilege Escalation", "logonuserw": "Auth/Privilege Escalation",
    "settokeninformation": "Auth/Privilege Escalation",

    # Anti-Analysis/Sandbox Check
    "isdebuggerpresent": "Anti-Analysis/Sandbox Check", "checkremotedebuggerpresent": "Anti-Analysis/Sandbox Check",
    "ntqueryinformationprocess": "Anti-Analysis/Sandbox Check", "queryperformancecounter": "Anti-Analysis/Sandbox Check",
    "gettickcount": "Anti-Analysis/Sandbox Check", "getsystemtime": "Anti-Analysis/Sandbox Check",
    "gettickcount64": "Anti-Analysis/Sandbox Check",

    # WMI/COM/Scripting
    "cocreateinstance": "WMI/COM/Scripting", "sysallocstring": "WMI/COM/Scripting",
    "variantinit": "WMI/COM/Scripting",

    # IPC/Named Objects
    "createnamedpipe": "IPC/Named Objects", "connectnamedpipe": "IPC/Named Objects",
    "callnamedpipe": "IPC/Named Objects", "createmutex": "IPC/Named Objects",
    "openmutex": "IPC/Named Objects", "createevent": "IPC/Named Objects",
    "setevent": "IPC/Named Objects", "waitforsingleobject": "IPC/Named Objects",

    # Input Capture/Keylogging
    "setwindowshookexa": "Input Capture/Keylogging", "setwindowshookexw": "Input Capture/Keylogging",
    "getasynckeystate": "Input Capture/Keylogging", "getkeystate": "Input Capture/Keylogging",
    "getforegroundwindow": "Input Capture/Keylogging", "getwindowtext": "Input Capture/Keylogging",
    "bitblt": "Input Capture/Keylogging", "getdc": "Input Capture/Keylogging",
    "printwindow": "Input Capture/Keylogging",

    # Cryptography/Ransomware
    "cryptgenrandom": "Cryptography/Ransomware", "cryptacquirecontext": "Cryptography/Ransomware",
    "cryptencrypt": "Cryptography/Ransomware", "cryptdecrypt": "Cryptography/Ransomware",
    "bcryptencrypt": "Cryptography/Ransomware", "cryptimportkey": "Cryptography/Ransomware",
    "cryptexportkey": "Cryptography/Ransomware",

    # Forensics Tampering/Cleanup
    "cleareventlog": "Forensics Tampering/Cleanup", "backupeventlog": "Forensics Tampering/Cleanup",
}

# Initialize console (must be after imports)
console = Console()

# Warn about missing API keys
if _vt_key_missing:
    console.print("[yellow]Warning: VT_API_KEY not found in environment. VirusTotal lookup will be unavailable.[/yellow]")

# ==================== ASCII LOGO & BRANDING ====================

ZERO_STAT_LOGO = """⢋⣴⠒⡝⣿⣿⣿⣿⣿⡿⢋⣥⣶⣿⣿⣿⣿⣿⣿⣶⣦⣍⠻⣿⣿⣿⣿⣿⣷⣿
⢾⣿⣀⣿⡘⢿⣿⡿⠋⠄⠻⠛⠛⠛⠻⠿⣿⣿⣿⣿⣿⣿⣷⣌⠻⣿⣿⣿⣿⣿
⠄⠄⠈⠙⢿⣦⣉⡁⠄⠄⣴⣶⣿⣿⢷⡶⣾⣿⣿⣿⣿⡛⠛⠻⠃⠙⢿⣿⣿⣿
⠄⠄⠄⠄⠄⠈⠉⣀⣀⣴⡟⢩⠁⠩⣝⢂⢨⣿⣿⣿⣿⢟⡛⣳⣶⣤⡘⠿⢋⣡
⠄⠄⠄⠄⠄⠄⠘⣿⣿⣿⣿⣾⣿⣶⣿⣿⣿⣿⣿⣿⣿⣆⣈⣱⣮⣿⣷⡾⠟⠋
⠄⠄⠄⠄⠄⠄⠄⠈⠿⠛⠛⣻⣿⠉⠛⠋⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠸⣿
⠄⠄⠄⠄⢀⡠⠄⢒⣤⣟⠿⣿⣿⣿⣷⣤⣤⣀⣀⣉⣉⣠⣽⣿⣟⠻⣿⣿⡆⢻
⠄⣀⠄⠄⠄⠄⠈⠋⠉⣿⣿⣶⣿⣟⣛⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣼⣿⡇⣸
⣿⠃⠄⠄⠄⠄⠄⠄⠠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣾⣿⣿⣿⣿⣿⣿⠁⢿
⡋⠄⠄⠄⠄⠄⠄⢰⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⠄"""

def display_banner():
    """Display Zero-HYBRID banner with ASCII logo."""
    console.print()
    console.print(Panel(
        Text(ZERO_STAT_LOGO, style="bold #6A0DAD"),
        title="[bold #C724B1]Agent-Zero[/bold #C724B1]",
        subtitle="[#C724B1]Your Static Analysis LLM Agent[/#C724B1]",
        border_style="#6A0DAD",
        box=box.DOUBLE,
        padding=(1, 2)
    ))
    console.print()

# ==================== SYSTEM PROMPTS ====================

STAGE_1_PROMPT = """You are a cybersecurity analyst. Analyze string extraction and FLOSS de-obfuscation results. Return ONLY valid JSON.

CRITICAL: Return ONLY the JSON object below. No markdown, no explanations, no text before or after.

{{
  "stage": "string_extraction_and_floss",
  "quality_assessment": "excellent|good|fair|poor",
  "total_strings": <number>,
  "extraction_method": "python|strings|python+floss|strings+floss",
  "floss_findings": ["finding1", "finding2"],
  "key_observations": ["observation1", "observation2"],
  "potential_indicators": ["indicator1", "indicator2"],
  "deobfuscated_strings_of_interest": ["string1", "string2"],
  "recommendation": "proceed|retry_with_different_method|manual_review_needed"
}}

DATA:
{data}"""

STAGE_2_PROMPT = """You are a cybersecurity analyst. Analyze categorized strings and CAPA static analysis results. Return ONLY valid JSON.

CRITICAL: Return ONLY the JSON object below. No markdown, no explanations, no text before or after.

{{
  "stage": "categorization_and_capa",
  "categorization_quality": "excellent|good|fair|poor",
  "suspicious_api_count": <number>,
  "network_indicators_count": <number>,
  "key_api_categories": ["category1", "category2"],
  "notable_strings": ["string1", "string2"],
  "capa_attack_techniques_count": <number>,
  "capa_mbc_behaviors_count": <number>,
  "capa_key_findings": ["finding1", "finding2"],
  "capa_top_ttps": ["T1055", "T1071"],
  "initial_risk_level": "low|medium|high|critical",
  "recommendation": "proceed_to_reputation_check"
}}

DATA:
{data}"""

STAGE_3_PROMPT = """You are a cybersecurity analyst. Analyze threat intelligence including VirusTotal, CAPA static analysis, and dynamic analysis results. Return ONLY valid JSON.

CRITICAL: Return ONLY the JSON object below. No markdown, no explanations, no text before or after.

{{
  "stage": "threat_intelligence",
  "vt_detection_count": <number>,
  "vt_total_engines": <number>,
  "capa_attack_techniques_count": <number>,
  "capa_mbc_behaviors_count": <number>,
  "combined_threat_score": 0-100,
  "dataset_matches_count": <number>,
  "behavioral_patterns_matched": ["pattern1", "pattern2"],
  "dynamic_analysis_verdict": "malicious|suspicious|clean|unknown",
  "dynamic_analysis_source": "Hybrid Analysis|None",
  "reputation_summary": "clean|low_risk|suspicious|malicious",
  "confidence": 0.0-1.0,
  "key_evidence": ["evidence1", "evidence2"],
  "unified_ttp_list": ["T1055", "T1071"],
  "recommendation": "proceed_to_final_analysis"
}}

DATA:
{data}"""

FINAL_ANALYSIS_PROMPT_JSON = """Return ONLY this JSON object. No other text. Start with {{ and end with }}.

{{
  "verdict": "benign|suspicious|malicious",
  "confidence": 0.0-1.0,
  "score": 0-100,
  "malware_family": "family_name or unknown",
  "primary_capabilities": ["capability1", "capability2"],
  "ttp_matches": ["T1055", "T1071"],
  "indicators": ["indicator1", "indicator2"],
  "explanation": "Brief analysis",
  "recommended_actions": ["action1", "action2"],
  "artifacts": {{"yara_rule_draft": "", "iocs": []}},
  "stage_synthesis": "Brief summary",
  "evidence_map": {{}}
}}

STAGES: {stage_reports}
EVIDENCE: {full_data}"""

FINAL_ANALYSIS_PROMPT_KV = """Analyze the data and return analysis using KEY: VALUE format. No JSON, no markdown.

VERDICT: benign|suspicious|malicious
CONFIDENCE: 0.0-1.0
SCORE: 0-100
MALWARE_FAMILY: family_name or unknown
PRIMARY_CAPABILITIES: capability1, capability2
TTP_MATCHES: T1055, T1071
INDICATORS: indicator1, indicator2
EXPLANATION: Brief analysis
RECOMMENDED_ACTIONS: action1, action2
STAGE_SYNTHESIS: Brief summary

STAGES: {stage_reports}
EVIDENCE: {full_data}"""

# ==================== UTILITY FUNCTIONS ====================

def parse_detection_ratio(ratio: str) -> Tuple[int, int]:
    """Parse detection_ratio string like '12/70' -> (12, 70)"""
    try:
        parts = ratio.split('/')
        if len(parts) == 2:
            return int(parts[0]), int(parts[1])
    except Exception:
        pass
    return 0, 0

def safe_json_parse(text: str) -> Optional[Dict[str, Any]]:
    """
    Robust JSON parsing with multiple strategies:
    1. Direct JSON parse
    2. Extract JSON from markdown code blocks
    3. Find JSON object in text
    4. Clean and retry
    """
    if not text:
        return None

    # Strategy 1: Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Quick markdown code block extraction (optimized)
    if '```' in text:
        json_block_match = re.search(r'```(?:json)?\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})\s*```', text, re.DOTALL)
        if json_block_match:
            try:
                return json.loads(json_block_match.group(1))
            except json.JSONDecodeError:
                pass

    # Strategy 3: Find first complete JSON object (optimized - stop at first valid match)
    start_idx = text.find('{')
    if start_idx != -1:
        brace_count = 0
        in_string = False
        escape_next = False

        for i in range(start_idx, min(start_idx + 50000, len(text))):  # Limit search to prevent slow parsing
            char = text[i]

            if escape_next:
                escape_next = False
                continue

            if char == '\\':
                escape_next = True
                continue

            if char == '"' and not escape_next:
                in_string = not in_string
                continue

            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        # Found complete JSON object
                        try:
                            return json.loads(text[start_idx:i+1])
                        except json.JSONDecodeError:
                            break

        # Fallback: If we didn't find a complete object, try simple extraction
        # Find last closing brace and try to parse from first { to last }
        end_idx = text.rfind('}')
        if end_idx > start_idx:
            try:
                # Try parsing the section between first { and last }
                candidate = text[start_idx:end_idx+1]
                # Remove any trailing text that might be after the JSON
                if candidate.count('{') == candidate.count('}'):
                    return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    return None

def parse_key_value_output(text: str) -> Optional[Dict[str, Any]]:
    """
    Parse KEY: VALUE format output (more reliable than JSON for some models).
    """
    if not text:
        return None

    # Key mapping for final analysis
    key_mapping = {
        "VERDICT": "verdict",
        "CONFIDENCE": "confidence",
        "SCORE": "score",
        "MALWARE_FAMILY": "malware_family",
        "PRIMARY_CAPABILITIES": "primary_capabilities",
        "TTP_MATCHES": "ttp_matches",
        "INDICATORS": "indicators",
        "EXPLANATION": "explanation",
        "RECOMMENDED_ACTIONS": "recommended_actions",
        "STAGE_SYNTHESIS": "stage_synthesis",
        "ARTIFACTS": "artifacts",
        "EVIDENCE_MAP": "evidence_map"
    }

    parsed = {}
    text = text.strip()

    # Regex to find KEY: VALUE pairs
    pattern = re.compile(r'\s*([A-Z_]+):\s*(.*?)(?=\s*[A-Z_]+:|\Z)', re.DOTALL)
    matches = pattern.findall(text)

    if not matches:
        return None

    for key, value in matches:
        internal_key = key_mapping.get(key.strip())
        if internal_key:
            cleaned_value = value.strip()

            # Handle list fields
            if internal_key in ["primary_capabilities", "ttp_matches", "indicators", "recommended_actions"]:
                cleaned_value = cleaned_value.strip('[]"\'')
                if cleaned_value:
                    parsed[internal_key] = [item.strip() for item in cleaned_value.split(',') if item.strip()]
                else:
                    parsed[internal_key] = []
            # Handle numeric fields
            elif internal_key == "confidence":
                try:
                    parsed[internal_key] = float(cleaned_value)
                except ValueError:
                    parsed[internal_key] = 0.5
            elif internal_key == "score":
                try:
                    parsed[internal_key] = int(float(cleaned_value))
                except ValueError:
                    parsed[internal_key] = 50
            else:
                parsed[internal_key] = cleaned_value

    # Return if we got at least verdict, confidence, and score
    if "verdict" in parsed and "confidence" in parsed and "score" in parsed:
        # Fill in missing fields with defaults
        defaults = {
            "malware_family": "unknown",
            "primary_capabilities": [],
            "ttp_matches": [],
            "indicators": [],
            "explanation": parsed.get("explanation", "Analysis completed"),
            "recommended_actions": parsed.get("recommended_actions", []),
            "artifacts": {},
            "stage_synthesis": parsed.get("stage_synthesis", "Analysis completed"),
            "evidence_map": {}
        }
        for key, default_value in defaults.items():
            if key not in parsed:
                parsed[key] = default_value
        return parsed

    return None

def extract_from_text(text: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract basic information from unstructured text response.
    This is a last resort fallback.
    """
    text_lower = text.lower()

    # Try to extract verdict
    verdict = "suspicious"
    if "malicious" in text_lower:
        verdict = "malicious"
    elif "benign" in text_lower or "clean" in text_lower:
        verdict = "benign"

    # Try to extract confidence/score from text
    confidence = 0.5
    score = 50

    # Look for confidence patterns
    conf_match = re.search(r'confidence[:\s]+([0-9.]+)', text_lower)
    if conf_match:
        try:
            confidence = float(conf_match.group(1))
            if confidence > 1.0:
                confidence = confidence / 100.0
        except ValueError:
            pass

    # Look for score patterns
    score_match = re.search(r'score[:\s]+([0-9]+)', text_lower)
    if score_match:
        try:
            score = int(score_match.group(1))
        except ValueError:
            pass

    # Extract TTPs if mentioned
    ttp_matches = []
    for ttp in ["T1055", "T1071", "T1497", "T1486", "T1003", "T1068"]:
        if ttp in text:
            ttp_matches.append(ttp)

    # Build basic report
    return {
        "verdict": verdict,
        "confidence": confidence,
        "score": score,
        "malware_family": "unknown",
        "primary_capabilities": [],
        "ttp_matches": ttp_matches,
        "indicators": [],
        "explanation": f"Analysis extracted from text response. Original response: {text[:500]}",
        "recommended_actions": ["Review audit logs", "Manual analysis recommended"],
        "artifacts": {},
        "stage_synthesis": "Text-based extraction fallback used",
        "evidence_map": {}
    }

# ==================== MAIN ANALYZER CLASS ====================

class EnhancedBinaryAnalyzer:
    def __init__(self, args):
        self.args = args
        self.timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        self.stage_reports = {}

        # Create directories
        Path(args.outdir).mkdir(exist_ok=True)
        Path("audit").mkdir(exist_ok=True)
        if getattr(args, "stage_reports", False):
            Path(f"{args.outdir}/stages").mkdir(exist_ok=True)

        # Initialize dynamic analysis API keys
        try:
            load_dotenv()
        except:
            pass
        self.hybrid_analysis_api_key = os.environ.get("HYBRID_ANALYSIS_API_KEY")

    # ==================== FILE OPERATIONS ====================

    def calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash for a file."""
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            console.print(f"[yellow]SHA256 error: {e}[/yellow]")
            return ""

    def _save_tool_output_json(self, tool_name: str, data: Dict[str, Any], file_hash: str) -> str:
        """Save tool output to JSON file for later parsing.

        Args:
            tool_name: Name of the tool ('floss' or 'capa')
            data: Tool output data to save
            file_hash: SHA256 hash of the file being analyzed

        Returns:
            Path to the saved JSON file
        """
        hash_short = file_hash[:8] if file_hash else self.timestamp
        json_path = os.path.join(self.args.outdir, f"{tool_name}_output_{hash_short}.json")

        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            if console and not getattr(self.args, '_web_mode', False):
                console.print(f"[green]✓ {tool_name.upper()} output saved to: {json_path}[/green]")

            return json_path
        except Exception as e:
            if console:
                console.print(f"[yellow]Failed to save {tool_name} JSON output: {e}[/yellow]")
            return ""

    def _load_tool_output_json(self, tool_name: str, file_hash: str) -> Optional[Dict[str, Any]]:
        """Load tool output from JSON file if it exists.

        Args:
            tool_name: Name of the tool ('floss' or 'capa')
            file_hash: SHA256 hash of the file being analyzed

        Returns:
            Loaded JSON data or None if file doesn't exist
        """
        hash_short = file_hash[:8] if file_hash else self.timestamp
        json_path = os.path.join(self.args.outdir, f"{tool_name}_output_{hash_short}.json")

        if not os.path.exists(json_path):
            return None

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if console and not getattr(self.args, '_web_mode', False):
                console.print(f"[cyan]Loaded {tool_name.upper()} output from: {json_path}[/cyan]")

            return data
        except Exception as e:
            if console:
                console.print(f"[yellow]Failed to load {tool_name} JSON output: {e}[/yellow]")
            return None

    # ==================== STRING EXTRACTION ====================

    def extract_strings(self, file_path: str) -> Tuple[List[str], str, Dict[str, Any]]:
        """Extract strings using Python scanner, system strings, and FLOSS."""
        # Start with standard extraction
        strings = self._extract_strings_python(file_path)
        method = "python"
        floss_data = {}

        if len(strings) < 10:
            system_strings = self._extract_strings_system(file_path)
            if system_strings:
                strings = system_strings
                method = "strings"

        # Try FLOSS for de-obfuscated strings (unless disabled)
        if not getattr(self.args, "no_floss", False):
            floss_strings, floss_metadata = self._extract_strings_floss(file_path)
            if floss_strings:
                # Merge FLOSS strings with existing strings
                all_strings = list(set(strings + floss_strings))
                strings = all_strings
                if method == "python":
                    method = "python+floss"
                elif method == "strings":
                    method = "strings+floss"
                else:
                    method = f"{method}+floss"
                floss_data = floss_metadata
                if console:
                    console.print(f"[green]FLOSS extracted {len(floss_strings)} de-obfuscated strings[/green]")

        unique_strings = list(set(s.strip() for s in strings if len(s.strip()) >= MIN_STRING_LENGTH))
        return unique_strings, method, floss_data

    def _extract_strings_python(self, file_path: str) -> List[str]:
        """Pure Python string extraction."""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            current_string = []
            for byte in data:
                if 32 <= byte <= 126:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= MIN_STRING_LENGTH:
                        strings.append(''.join(current_string))
                    current_string = []

            if len(current_string) >= MIN_STRING_LENGTH:
                strings.append(''.join(current_string))

        except Exception as e:
            console.print(f"[yellow]Python extraction failed: {e}[/yellow]")

        return strings

    def _extract_strings_system(self, file_path: str) -> List[str]:
        """Use system strings command as fallback."""
        try:
            result = subprocess.run(['strings', file_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout.splitlines()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return []

    def _check_tool_available(self, tool_name: str) -> Optional[str]:
        """Check if a tool is available and working by running -h flag.
        Handles shell aliases (tries shell execution FIRST), then falls back to PATH lookup.
        Provides diagnostic info for debugging.
        """
        import platform

        # ========== STEP 1: Try shell execution FIRST (for aliases) ==========
        # This works for tools defined as aliases in ~/.zshrc or ~/.bashrc
        detected_shell = os.environ.get('SHELL', '')
        home_dir = os.path.expanduser('~')
        shell_cmd = None
        rc_file = None

        # Detect shell and rc file
        zshrc_path = os.path.join(home_dir, '.zshrc')
        if os.path.exists(zshrc_path):
            rc_file = zshrc_path
            if 'zsh' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('zsh'):
                shell_cmd = shutil.which('zsh')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/zsh'
        elif os.path.exists(os.path.join(home_dir, '.bashrc')):
            rc_file = os.path.join(home_dir, '.bashrc')
            if 'bash' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('bash'):
                shell_cmd = shutil.which('bash')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/bash'
        elif os.path.exists(os.path.join(home_dir, '.bash_profile')):
            rc_file = os.path.join(home_dir, '.bash_profile')
            if 'bash' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('bash'):
                shell_cmd = shutil.which('bash')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/bash'

        # Try to resolve alias via shell execution
        if shell_cmd and rc_file:
            if console and not getattr(self.args, '_web_mode', False):
                console.print(f"[dim]Attempting shell alias resolution for '{tool_name}'...[/dim]")

            try:
                # Use 'type' command to resolve aliases and get actual path
                # For zsh: 'whence -p toolname' or 'type -p toolname'
                # For bash: 'type -p toolname'
                if 'zsh' in shell_cmd.lower():
                    resolve_cmd = f"source '{rc_file}' 2>/dev/null; whence -p '{tool_name}' 2>/dev/null || type -p '{tool_name}' 2>/dev/null || command -v '{tool_name}' 2>/dev/null"
                else:
                    resolve_cmd = f"source '{rc_file}' 2>/dev/null; type -p '{tool_name}' 2>/dev/null || command -v '{tool_name}' 2>/dev/null"

                result = subprocess.run(
                    resolve_cmd,
                    shell=True,
                    executable=shell_cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                resolved_path = result.stdout.strip() if result.stdout else None

                # If we got a path, verify it works
                if resolved_path and os.path.exists(resolved_path):
                    # Verify tool works by running -h flag
                    try:
                        verify_result = subprocess.run(
                            [resolved_path, '-h'],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if verify_result.returncode == 0 or verify_result.stdout or verify_result.stderr:
                            if console and not getattr(self.args, '_web_mode', False):
                                console.print(f"[green]✓ {tool_name} found via shell alias at: {resolved_path}[/green]")
                            return resolved_path
                    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
                        pass

                # Try direct shell execution to verify alias works
                test_cmd = f"source '{rc_file}' 2>/dev/null; {tool_name} -h 2>&1"
                test_result = subprocess.run(
                    test_cmd,
                    shell=True,
                    executable=shell_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if test_result.stdout or (test_result.returncode == 0 and test_result.stderr):
                    # Tool works via alias - return special marker that indicates shell execution
                    if console and not getattr(self.args, '_web_mode', False):
                        console.print(f"[green]✓ {tool_name} found via shell alias (will use shell execution)[/green]")
                    # Return a special marker that indicates shell execution should be used
                    return f"SHELL_ALIAS:{tool_name}"

            except Exception as e:
                if console and not getattr(self.args, '_web_mode', False):
                    console.print(f"[dim]Shell alias resolution failed: {e}[/dim]")

        # ========== STEP 2: Fall back to PATH-based lookup ==========
        tool_variations = [tool_name]
        if platform.system() == 'Windows':
            tool_variations.extend([f"{tool_name}.exe", tool_name.replace('.exe', '')])

        for tool_variant in tool_variations:
            tool_path = shutil.which(tool_variant)
            if tool_path:
                # Verify tool works by running -h flag
                try:
                    result = subprocess.run(
                        [tool_path, '-h'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    # If return code is 0 or has output (some tools return non-zero for -h but still output help)
                    if result.returncode == 0 or result.stdout or result.stderr:
                        if console and not getattr(self.args, '_web_mode', False):
                            console.print(f"[green]✓ {tool_name} found and verified in PATH at: {tool_path}[/green]")
                        return tool_path
                except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
                    continue  # Try next variation

        # Tool not found or not working - provide diagnostic info
        if console and not getattr(self.args, '_web_mode', False):
            console.print(f"[yellow]Tool '{tool_name}' not found or not working in PATH[/yellow]")
            console.print(f"[dim]Searched for: {', '.join(tool_variations)}[/dim]")

            # Provide installation suggestions
            if tool_name == 'capa':
                console.print("[yellow]Install CAPA from: https://github.com/mandiant/capa[/yellow]")
                console.print("[yellow]Install command: pip install capa[/yellow]")
                console.print("[yellow]Or download from: https://github.com/mandiant/capa/releases[/yellow]")
            elif tool_name == 'floss':
                console.print("[yellow]Install FLOSS from: https://github.com/mandiant/flare-floss[/yellow]")
                console.print("[yellow]Install command: pip install flare-floss[/yellow]")
                console.print("[yellow]Or download from: https://github.com/mandiant/flare-floss/releases[/yellow]")

        return None

    def _extract_strings_floss(self, file_path: str) -> Tuple[List[str], Dict[str, Any]]:
        """Extract de-obfuscated strings using FLOSS.

        Runs FLOSS twice:
        1. Without --json to get human-readable text output for CLI display
        2. With --json to get structured data for LLM processing

        Returns: (list of strings, metadata dict with text_output and parsed data)
        """
        import platform

        # If disabled, skip
        if getattr(self.args, "no_floss", False):
            return [], {}

        # Detect shell and rc file for alias expansion
        shell_cmd = None
        rc_file = None
        detected_shell = os.environ.get('SHELL', '')
        home_dir = os.path.expanduser('~')

        # Check for zsh first (your setup)
        zshrc_path = os.path.join(home_dir, '.zshrc')
        if os.path.exists(zshrc_path):
            rc_file = zshrc_path
            if 'zsh' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('zsh'):
                shell_cmd = shutil.which('zsh')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/zsh'
        # Check for bash
        elif os.path.exists(os.path.join(home_dir, '.bashrc')):
            rc_file = os.path.join(home_dir, '.bashrc')
            if 'bash' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('bash'):
                shell_cmd = shutil.which('bash')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/bash'
        elif os.path.exists(os.path.join(home_dir, '.bash_profile')):
            rc_file = os.path.join(home_dir, '.bash_profile')
            if 'bash' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('bash'):
                shell_cmd = shutil.which('bash')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/bash'

        # Check tool availability and determine execution strategy
        floss_path = self._check_tool_available('floss')
        use_shell_execution = False

        # If tool is detected as shell alias, prioritize shell execution
        if floss_path and floss_path.startswith("SHELL_ALIAS:"):
            use_shell_execution = True
            floss_path = None  # Clear path marker
        elif not floss_path:
            # If not found, check if we have shell available for fallback
            if not shell_cmd or not rc_file:
                # Re-detect shell if not already detected
                detected_shell = os.environ.get('SHELL', '')
                home_dir = os.path.expanduser('~')
                zshrc_path = os.path.join(home_dir, '.zshrc')
                if os.path.exists(zshrc_path):
                    rc_file = zshrc_path
                    if 'zsh' in detected_shell.lower():
                        shell_cmd = detected_shell
                    elif shutil.which('zsh'):
                        shell_cmd = shutil.which('zsh')
                    elif platform.system() != 'Windows':
                        shell_cmd = '/bin/zsh'

        floss_text_output = ""
        all_strings = []
        metadata = {}

        # Helper function to run FLOSS via shell (for aliases)
        def run_floss_shell(with_json: bool) -> Optional[subprocess.CompletedProcess]:
            if not shell_cmd or not rc_file:
                return None
            try:
                escaped_file_path = file_path.replace("'", "'\"'\"'")
                if with_json:
                    shell_command_str = f"source '{rc_file}' 2>/dev/null; floss --json '{escaped_file_path}'"
                else:
                    shell_command_str = f"source '{rc_file}' 2>/dev/null; floss '{escaped_file_path}'"

                if console and getattr(self.args, 'capa_verbose', False):
                    console.print(f"[dim]Executing FLOSS via shell (interactive mode): {shell_command_str}[/dim]")

                # Use zsh -i (interactive mode) to enable alias expansion
                return subprocess.run(
                    [shell_cmd, '-i', '-c', shell_command_str],
                    capture_output=True,
                    text=True,
                    timeout=180
                )
            except Exception as e:
                if console:
                    console.print(f"[yellow]FLOSS shell execution error: {e}[/yellow]")
                    import traceback
                    console.print(f"[dim]{traceback.format_exc()}[/dim]")
                return None

        # Helper function to run FLOSS directly
        def run_floss_direct(with_json: bool) -> Optional[subprocess.CompletedProcess]:
            commands_to_try = []
            if floss_path and not floss_path.startswith("SHELL_ALIAS:"):
                commands_to_try.append([floss_path])
            if not use_shell_execution:
                commands_to_try.append(['floss'])
            commands_to_try.append([sys.executable, '-m', 'floss'])

            for cmd_base in commands_to_try:
                try:
                    if with_json:
                        cmd = cmd_base + ['--json', file_path]
                    else:
                        cmd = cmd_base + [file_path]

                    return subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            return None

        # ========== STEP 1: Get human-readable text output (for CLI display) ==========
        if console:
            console.print("[dim]Running FLOSS for text output (CLI display)...[/dim]")

        # Try shell execution first if alias detected, then direct
        if use_shell_execution and shell_cmd and rc_file:
            if console:
                console.print("[dim]Using shell execution (alias detected)...[/dim]")
            result_text = run_floss_shell(with_json=False)
            if result_text and result_text.returncode != 0 and not result_text.stdout:
                if console:
                    console.print(f"[yellow]FLOSS shell execution returned: exit code {result_text.returncode}[/yellow]")
                    if result_text.stderr:
                        console.print(f"[yellow]Stderr: {result_text.stderr[:300]}[/yellow]")
        else:
            result_text = None

        if not result_text or (result_text.returncode != 0 and not result_text.stdout):
            result_text = run_floss_direct(with_json=False)

        if result_text and result_text.stdout:
            floss_text_output = result_text.stdout
            if console:
                console.print("[green]✓ FLOSS text output captured[/green]")
        elif result_text and result_text.stderr and console:
            console.print(f"[yellow]FLOSS stderr: {result_text.stderr[:200]}[/yellow]")

        # ========== STEP 2: Get JSON output (for LLM processing) ==========
        if console:
            console.print("[dim]Running FLOSS for JSON output (LLM processing)...[/dim]")

        # Try shell execution first if alias detected, then direct
        if use_shell_execution and shell_cmd and rc_file:
            result_json = run_floss_shell(with_json=True)
            if result_json and result_json.returncode != 0 and not result_json.stdout:
                if console:
                    console.print(f"[yellow]FLOSS JSON shell execution returned: exit code {result_json.returncode}[/yellow]")
                    if result_json.stderr:
                        console.print(f"[yellow]Stderr: {result_json.stderr[:300]}[/yellow]")
        else:
            result_json = None

        if not result_json or (result_json.returncode != 0 and not result_json.stdout):
            result_json = run_floss_direct(with_json=True)

        if result_json and result_json.stdout:
            try:
                floss_data = json.loads(result_json.stdout)

                # Extract strings from different FLOSS extraction methods
                for method in ['strings', 'stack_strings', 'decoded_strings']:
                    strings_list = floss_data.get(method, [])
                    for s in strings_list:
                        if isinstance(s, dict):
                            string_value = s.get('string', s.get('value', ''))
                        else:
                            string_value = str(s)

                        if string_value and len(string_value.strip()) >= MIN_STRING_LENGTH:
                            all_strings.append(string_value.strip())

                # Build metadata with both text output and JSON data
                metadata = {
                    'floss_version': floss_data.get('version', 'unknown'),
                    'extraction_methods': ['strings', 'stack_strings', 'decoded_strings'],
                    'total_extracted': len(all_strings),
                    'text_output': floss_text_output,  # Human-readable for CLI
                    'json_data': floss_data  # Structured for LLM
                }

                if console:
                    console.print(f"[green]✓ FLOSS extracted {len(all_strings)} de-obfuscated strings[/green]")

                return list(set(all_strings)), metadata

            except json.JSONDecodeError:
                # Fallback: use text output only
                if floss_text_output:
                    lines = floss_text_output.splitlines()
                    all_strings = [line.strip() for line in lines if len(line.strip()) >= MIN_STRING_LENGTH]
                    metadata = {
                        'extraction_methods': ['floss_text'],
                        'total_extracted': len(all_strings),
                        'text_output': floss_text_output
                    }
                    return list(set(all_strings)), metadata

        # If JSON failed but we have text output, parse it
        if floss_text_output:
            lines = floss_text_output.splitlines()
            all_strings = [line.strip() for line in lines if len(line.strip()) >= MIN_STRING_LENGTH]
            metadata = {
                'extraction_methods': ['floss_text'],
                'total_extracted': len(all_strings),
                'text_output': floss_text_output
            }
            if console:
                console.print(f"[green]✓ FLOSS (text mode) extracted {len(all_strings)} strings[/green]")
            return list(set(all_strings)), metadata

        # If we got here, all strategies failed
        if console:
            console.print("[yellow]FLOSS tool execution failed or not found.[/yellow]")
            console.print("[yellow]Install FLOSS: pip install flare-floss[/yellow]")
            console.print("[yellow]Or download from: https://github.com/mandiant/flare-floss/releases[/yellow]")

        return [], {}

    # ==================== STRING CATEGORIZATION ====================

    def categorize_strings(self, strings: List[str]) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """Categorize strings into different types and group suspicious APIs."""
        categories = {
            "ips": [], "domains": [], "paths": [], "dlls": [],
            "suspicious_api_calls": [], "others": []
        }
        categorized_apis_summary = {}

        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        domain_pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b')
        path_pattern = re.compile(r'[a-zA-Z]:\\[^<>:"|?*]+\.[a-zA-Z]{2,6}|\\[^<>:"|?*]+\.[a-zA-Z]{2,6}')
        dll_pattern = re.compile(r'.*\.(dll|exe|sys|drv)$', re.IGNORECASE)

        malicious_api_set = MALICIOUS_API_CATEGORIES.keys()

        for string in strings:
            string_lower = string.lower()

            if string_lower in malicious_api_set:
                categories["suspicious_api_calls"].append(string)
                category_name = MALICIOUS_API_CATEGORIES[string_lower]
                categorized_apis_summary.setdefault(category_name, []).append(string)
                continue

            if ip_pattern.search(string):
                categories["ips"].append(string)
                continue

            if domain_pattern.search(string) and len(string) < 255:
                categories["domains"].append(string)
                continue

            if path_pattern.search(string):
                categories["paths"].append(string)
                continue

            if dll_pattern.search(string):
                categories["dlls"].append(string)
                continue

            categories["others"].append(string)

        for category in categories:
            categories[category] = list(set(categories[category]))

        return categories, categorized_apis_summary

    # ==================== VIRUSTOTAL ====================

    def virustotal_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal v3 API with detailed engine results."""
        if not file_hash:
            return {"raw": None, "vt_stats": {"malicious":0,"suspicious":0,"undetected":0},
                    "vt_classifications": [], "error":"empty_hash"}

        if getattr(self.args, "no_vt", False):
            return {"raw": None, "vt_stats": {"malicious":0,"suspicious":0,"undetected":0},
                    "vt_classifications": [], "error":"no_vt_flag"}

        if not VIRUSTOTAL_API_KEY:
            return {"raw": None, "vt_stats": {"malicious":0,"suspicious":0,"undetected":0},
                    "vt_classifications": [], "error":"VT_API_KEY not configured"}

        url = VT_FILE_REPORT_URL + file_hash
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code != 200:
                try:
                    err = resp.json()
                except Exception:
                    err = resp.text
                return {"raw": None, "vt_stats":{"malicious":0,"suspicious":0,"undetected":0},
                        "vt_classifications": [], "error":f"HTTP {resp.status_code}: {err}"}

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            last_stats = attrs.get("last_analysis_stats", {}) or {}

            malicious = int(last_stats.get("malicious", 0))
            suspicious = int(last_stats.get("suspicious", 0))
            undetected = int(last_stats.get("undetected", 0))

            # Parse engine labels
            engine_results = attrs.get("last_analysis_results", {}) or {}
            engine_labels = []
            for engine, ed in engine_results.items():
                label = ed.get("category")
                result = ed.get("result")
                if label in ("malicious","suspicious") or result:
                    engine_labels.append({"engine": engine, "category": label, "result": result})

            vt_stats = {"malicious": malicious, "suspicious": suspicious, "undetected": undetected}
            return {"raw": data, "vt_stats": vt_stats, "vt_classifications": engine_labels, "error": None}

        except Exception as e:
            return {"raw": None, "vt_stats":{"malicious":0,"suspicious":0,"undetected":0},
                    "vt_classifications": [], "error": str(e)}

    # ==================== BEHAVIORAL PATTERNS ====================

    def match_api_sequences(self, strings: List[str]) -> List[str]:
        """Check for high-confidence malicious API sequences."""
        lowered = set(s.lower() for s in strings if isinstance(s, str))
        matches = []
        for name, seq in MALICIOUS_API_SEQUENCES.items():
            if all(api.lower() in lowered for api in seq):
                matches.append(name)
        return matches

    # ==================== CSV DATASET ====================

    def load_dataset_csv(self, csv_path: str) -> List[Dict[str, Any]]:
        """Load CSV dataset with malware API sequences."""
        entries = []
        try:
            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row or len(row) == 0:
                        continue

                    if len(row) >= 3:
                        a = row[0].strip()
                        b = row[1].strip().strip('"')
                        c = row[2].strip()
                        apis = [x.strip() for x in re.split(r'[,\|;]', b) if x.strip()]
                        entries.append({"sha256": a, "apis": apis, "label": c})
                    elif len(row) == 2:
                        c0 = row[0].strip()
                        c1 = row[1].strip().strip('"')
                        if re.fullmatch(r'[A-Fa-f0-9]{64}', c0):
                            entries.append({"sha256": c0, "apis": [x.strip() for x in re.split(r'[,\|;]', c1) if x.strip()], "label": ""})
                        else:
                            entries.append({"sha256": "", "apis": [x.strip() for x in re.split(r'[,\|;]', c1) if x.strip()], "label": c0})
        except Exception as e:
            console.print(f"[yellow]Failed to load CSV dataset: {e}[/yellow]")
        return entries

    def match_dataset(self, dataset_entries: List[Dict[str,Any]], observed_api_calls: List[str]) -> List[Dict[str,Any]]:
        """Match dataset entries against observed API calls."""
        matches = []
        obs_set = set(a.lower() for a in observed_api_calls)

        for entry in dataset_entries:
            apis = [a.lower() for a in entry.get("apis", [])]
            if not apis:
                continue

            matched = [p for p in apis if p in obs_set]
            pct = len(matched) / max(1, len(apis))

            if pct == 1.0:
                confidence = "ALL_APIS_PRESENT"
            elif pct >= 0.6:
                confidence = f"PARTIAL_{int(pct*100)}%"
            else:
                confidence = f"LOW_{int(pct*100)}%"

            if matched:
                matches.append({
                    "label": entry.get("label",""),
                    "apis_detected": matched,
                    "match_confidence": confidence,
                    "dataset_sha256": entry.get("sha256","")
                })
        return matches

    # ==================== DYNAMIC ANALYSIS ====================

    def _lookup_hybrid_analysis_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Check if file was already analyzed by Hybrid Analysis using overview endpoint."""
        if not self.hybrid_analysis_api_key:
            return None

        try:
            url = HYBRID_ANALYSIS_OVERVIEW_URL.format(sha256=sha256)
            headers = {
                "api-key": self.hybrid_analysis_api_key,
                "User-Agent": "Falcon Sandbox"
            }

            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if data.get("verdict") or data.get("job_id"):
                    console.print(f"[green]Found existing Hybrid Analysis report for hash[/green]")
                    return data
            elif response.status_code == 404:
                # File not analyzed yet
                return None
            else:
                error_msg = response.text
                console.print(f"[yellow]Hybrid Analysis hash lookup returned: {response.status_code} - {error_msg}[/yellow]")
                return None

        except Exception as e:
            console.print(f"[yellow]Hybrid Analysis hash lookup error: {e}[/yellow]")
            return None

    def submit_to_hybrid_analysis(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Submit file hash to Hybrid Analysis (Falcon Sandbox) and wait for results."""
        if not self.hybrid_analysis_api_key:
            console.print("[red]Hybrid Analysis API key not configured[/red]")
            return None

        # Calculate SHA256 hash
        sha256 = self.calculate_sha256(file_path)
        if not sha256:
            console.print("[red]Failed to calculate SHA256 hash[/red]")
            return None

        # Check if file already analyzed
        existing_report = self._lookup_hybrid_analysis_hash(sha256)
        if existing_report:
            # If we have a job_id, try to fetch the summary report
            job_id = existing_report.get("job_id")
            if job_id:
                # Try to get summary directly first (analysis might be complete)
                try:
                    summary_url = HYBRID_ANALYSIS_SUMMARY_URL.format(job_id=job_id)
                    headers = {
                        "api-key": self.hybrid_analysis_api_key,
                        "User-Agent": "Falcon Sandbox"
                    }
                    summary_response = requests.get(summary_url, headers=headers, timeout=30)
                    if summary_response.status_code == 200:
                        summary = summary_response.json()
                        return self._extract_hybrid_analysis_data(summary)
                except:
                    # If direct fetch fails, wait for completion
                    pass
                # Wait for analysis to complete if needed
                summary = self._wait_for_hybrid_analysis_completion(job_id)
                if summary:
                    return self._extract_hybrid_analysis_data(summary)
            # If we have verdict data directly, use it
            if existing_report.get("verdict") or existing_report.get("threat_score") is not None:
                return self._extract_hybrid_analysis_data(existing_report)

        console.print("[cyan]Submitting hash to Hybrid Analysis for analysis...[/cyan]")

        try:
            # Submit hash for analysis
            headers = {
                "api-key": self.hybrid_analysis_api_key,
                "User-Agent": "Falcon Sandbox",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            # Prepare form data with hash and required parameters
            data = {
                "hash": sha256,
                "environment_id": "100",  # Windows 10 environment
                "analysis_type": "run"    # Full analysis
            }

            response = requests.post(
                HYBRID_ANALYSIS_SUBMIT_HASH_URL,
                headers=headers,
                data=data,
                timeout=60
            )

            if response.status_code != 200:
                error_msg = response.text
                try:
                    error_json = response.json()
                    error_msg = json.dumps(error_json, indent=2)
                except:
                    pass
                console.print(f"[red]Hybrid Analysis submission failed: {response.status_code}[/red]")
                console.print(f"[red]Error details: {error_msg}[/red]")
                return None

            result = response.json()
            job_id = result.get("job_id")

            if not job_id:
                console.print("[red]No job_id returned from Hybrid Analysis[/red]")
                console.print(f"[yellow]Response: {json.dumps(result, indent=2)}[/yellow]")
                return None

            console.print(f"[green]Hash submitted successfully. Job ID: {job_id}[/green]")
            console.print("[cyan]Waiting for analysis to complete...[/cyan]")

            summary = self._wait_for_hybrid_analysis_completion(job_id)

            if summary:
                return self._extract_hybrid_analysis_data(summary)
            else:
                console.print("[yellow]Hybrid Analysis did not complete within timeout[/yellow]")
                return None

        except requests.exceptions.Timeout:
            console.print("[red]Hybrid Analysis request timed out[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Hybrid Analysis error: {e}[/red]")
            import traceback
            console.print(f"[yellow]Traceback: {traceback.format_exc()}[/yellow]")
            return None

    def _wait_for_hybrid_analysis_completion(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Poll Hybrid Analysis API until analysis completes or timeout."""
        start_time = time.time()
        time.sleep(INITIAL_WAIT)

        headers = {
            "api-key": self.hybrid_analysis_api_key,
            "User-Agent": "Falcon Sandbox"
        }

        with Progress(SpinnerColumn(), TextColumn("[magenta]Waiting for Hybrid Analysis..."), console=console) as progress:
            task = progress.add_task("Analysis in progress", total=None)

            while time.time() - start_time < MAX_POLLING_TIME:
                try:
                    state_url = HYBRID_ANALYSIS_STATE_URL.format(job_id=job_id)
                    state_response = requests.get(state_url, headers=headers, timeout=30)

                    if state_response.status_code == 200:
                        state_data = state_response.json()
                        state = state_data.get("state", "").upper()

                        if state == "SUCCESS":
                            summary_url = HYBRID_ANALYSIS_SUMMARY_URL.format(job_id=job_id)
                            summary_response = requests.get(summary_url, headers=headers, timeout=30)

                            if summary_response.status_code == 200:
                                console.print("[green]Hybrid Analysis completed successfully[/green]")
                                return summary_response.json()
                            else:
                                console.print(f"[yellow]Failed to fetch summary: {summary_response.status_code}[/yellow]")
                                return None

                        elif state in ["ERROR", "FAILED"]:
                            console.print(f"[red]Hybrid Analysis failed with state: {state}[/red]")
                            return None

                        time.sleep(POLLING_INTERVAL)
                    else:
                        console.print(f"[yellow]State check failed: {state_response.status_code}[/yellow]")
                        time.sleep(POLLING_INTERVAL)

                except Exception as e:
                    console.print(f"[yellow]Polling error: {e}[/yellow]")
                    time.sleep(POLLING_INTERVAL)

        console.print("[yellow]Hybrid Analysis polling timeout exceeded[/yellow]")
        return None

    def _extract_hybrid_analysis_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract simplified data from Hybrid Analysis response for LLM consumption."""
        verdict = raw_data.get("verdict", "unknown").lower()
        threat_score = raw_data.get("threat_score", 0)

        if threat_score >= 80:
            confidence = 100
        elif threat_score >= 50:
            confidence = 75
        elif threat_score >= 20:
            confidence = 50
        else:
            confidence = 25

        network_iocs = []
        domains = raw_data.get("domains", [])
        hosts = raw_data.get("hosts", [])
        network_iocs.extend(domains)
        network_iocs.extend(hosts)

        mitre_ttps = []
        mitre_data = raw_data.get("mitre_attcks", [])
        for ttp in mitre_data:
            attck_id = ttp.get("attck_id", "")
            technique = ttp.get("technique", "")
            if attck_id:
                mitre_ttps.append(f"{attck_id} - {technique}")

        behavioral_flags = []
        signatures = raw_data.get("signatures", [])
        for sig in signatures:
            name = sig.get("name", "")
            threat_level = sig.get("threat_level", 0)
            if threat_level >= 2 and name:
                flag_name = name.lower().replace(" ", "_")
                behavioral_flags.append(flag_name)

        family = "unknown"
        classification_tags = raw_data.get("classification_tags", [])
        if classification_tags:
            family = classification_tags[0]

        return {
            "source": "Hybrid Analysis",
            "verdict": verdict,
            "confidence": confidence,
            "family": family,
            "threat_score": threat_score,
            "network_iocs": network_iocs,
            "mitre_ttps": mitre_ttps,
            "behavioral_flags": behavioral_flags,
            "classification_tags": classification_tags
        }

    def orchestrate_dynamic_analysis(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Main entry point for dynamic analysis using Hybrid Analysis."""
        if getattr(self.args, "no_dynamic", False):
            console.print("[yellow]Skipping dynamic analysis (--no-dynamic set)[/yellow]")
            return None

        if not os.path.exists(file_path):
            console.print(f"[red]File not found: {file_path}[/red]")
            return None

        console.print(Panel(
            "[bold #C724B1]Dynamic Analysis: Hybrid Analysis (Falcon Sandbox)[/bold #C724B1]",
            border_style="#6A0DAD",
            box=box.DOUBLE
        ))

        # Use Hybrid Analysis
        if self.hybrid_analysis_api_key:
            console.print("[cyan]Attempting Hybrid Analysis...[/cyan]")
            hybrid_result = self.submit_to_hybrid_analysis(file_path)

            if hybrid_result:
                console.print("[green]Hybrid Analysis completed successfully[/green]")
                return hybrid_result
            else:
                console.print("[yellow]Hybrid Analysis failed or unavailable[/yellow]")
        else:
            console.print("[yellow]Hybrid Analysis API key not configured[/yellow]")

        return None

    def _combine_vt_capa_indicators(self, vt_info: Dict[str, Any], capa_result: Optional[Dict[str, Any]]) -> List[str]:
        """Combine VirusTotal and CAPA indicators into unified list."""
        indicators = []

        # Add VT indicators
        vt_stats = vt_info.get("vt_stats", {})
        malicious = vt_stats.get("malicious", 0)
        if malicious > 0:
            indicators.append(f"VirusTotal: {malicious} engines detected as malicious")

        vt_classifications = vt_info.get("vt_classifications", [])
        for classification in vt_classifications[:5]:
            engine = classification.get("engine", "")
            result = classification.get("result", "")
            if result:
                indicators.append(f"VT-{engine}: {result}")

        # Add CAPA indicators
        if capa_result and not capa_result.get('error'):
            attack_techniques = capa_result.get('attack_techniques', [])
            if attack_techniques:
                indicators.append(f"CAPA: {len(attack_techniques)} ATT&CK techniques detected")
                # Add top techniques
                for tech in attack_techniques[:5]:
                    tech_id = tech.get('technique_id', '')
                    tactic = tech.get('tactic', '')
                    if tech_id:
                        indicators.append(f"CAPA-{tactic}: {tech_id}")

        return indicators

    # ==================== CAPA STATIC ANALYSIS ====================

    def run_capa_analysis(self, file_path: str, verbose: bool = False) -> Optional[Dict[str, Any]]:
        """Run CAPA static analysis tool with MITRE ATT&CK TTP detection.
        Captures both formatted text output (for display/saving) and JSON (for parsing).
        Uses multiple execution strategies including shell aliases.
        """
        import platform

        # Determine shell and rc file for alias expansion
        shell_cmd = None
        rc_file = None

        # Try to detect shell from environment
        detected_shell = os.environ.get('SHELL', '')
        home_dir = os.path.expanduser('~')

        # Check for zsh
        zshrc_path = os.path.join(home_dir, '.zshrc')
        if os.path.exists(zshrc_path):
            rc_file = zshrc_path
            # Try to find zsh in common locations or use detected shell
            if 'zsh' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('zsh'):
                shell_cmd = shutil.which('zsh')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/zsh'
            else:
                # On Windows, try common zsh locations (Git Bash, WSL)
                for path in ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Windows\\System32\\bash.exe']:
                    if os.path.exists(path):
                        shell_cmd = path
                        break
        # Check for bash
        elif os.path.exists(os.path.join(home_dir, '.bashrc')):
            rc_file = os.path.join(home_dir, '.bashrc')
            if 'bash' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('bash'):
                shell_cmd = shutil.which('bash')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/bash'
            else:
                # On Windows, try common bash locations
                for path in ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Windows\\System32\\bash.exe']:
                    if os.path.exists(path):
                        shell_cmd = path
                        break
        elif os.path.exists(os.path.join(home_dir, '.bash_profile')):
            rc_file = os.path.join(home_dir, '.bash_profile')
            if 'bash' in detected_shell.lower():
                shell_cmd = detected_shell
            elif shutil.which('bash'):
                shell_cmd = shutil.which('bash')
            elif platform.system() != 'Windows':
                shell_cmd = '/bin/bash'
            else:
                # On Windows, try common bash locations
                for path in ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Windows\\System32\\bash.exe']:
                    if os.path.exists(path):
                        shell_cmd = path
                        break

        # Check tool availability and determine execution strategy
        capa_path = self._check_tool_available('capa')
        use_shell_execution = False

        # If tool is detected as shell alias, prioritize shell execution
        if capa_path and capa_path.startswith("SHELL_ALIAS:"):
            use_shell_execution = True
            capa_path = None  # Clear path marker
        elif capa_path:
            # Valid path found
            pass
        else:
            # Try to detect shell for fallback
            if not shell_cmd or not rc_file:
                # Re-detect shell if not already detected
                detected_shell = os.environ.get('SHELL', '')
                home_dir = os.path.expanduser('~')
                zshrc_path = os.path.join(home_dir, '.zshrc')
                if os.path.exists(zshrc_path):
                    rc_file = zshrc_path
                    if 'zsh' in detected_shell.lower():
                        shell_cmd = detected_shell
                    elif shutil.which('zsh'):
                        shell_cmd = shutil.which('zsh')
                    elif platform.system() != 'Windows':
                        shell_cmd = '/bin/zsh'

        # Define execution strategies
        commands_to_try = []

        # 1. Try resolved path if available (not a shell alias)
        if capa_path and not use_shell_execution:
            commands_to_try.append([capa_path])

        # 2. Try 'capa' directly (system path)
        if not use_shell_execution:
            commands_to_try.append(['capa'])

        # 3. Try python module
        commands_to_try.append([sys.executable, '-m', 'capa'])

        capa_text_output = ""
        capa_json_output = None
        working_cmd_base = None

        # ========== STEP 1: Run CAPA without --json to get formatted text output ==========
        if console:
            console.print("[dim]Running CAPA for formatted text output...[/dim]")

        # If shell execution is needed, try that first
        if use_shell_execution and shell_cmd and rc_file:
            if console:
                console.print("[dim]Using shell execution (alias detected)...[/dim]")

            try:
                escaped_file_path = file_path.replace("'", "'\"'\"'")
                if verbose:
                    shell_command_str = f"source '{rc_file}' 2>/dev/null; capa -vv '{escaped_file_path}'"
                else:
                    shell_command_str = f"source '{rc_file}' 2>/dev/null; capa '{escaped_file_path}'"

                if console and getattr(self.args, 'capa_verbose', False):
                    console.print(f"[dim]Executing via shell (interactive mode): {shell_command_str}[/dim]")

                # Use zsh -i (interactive mode) to enable alias expansion
                result_text = subprocess.run(
                    [shell_cmd, '-i', '-c', shell_command_str],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result_text.returncode == 0 or result_text.stdout:
                    if result_text.stdout:
                        capa_text_output = result_text.stdout
                        if result_text.returncode != 0 and console:
                            error_msg = result_text.stderr.strip() if result_text.stderr else f"exit code {result_text.returncode}"
                            console.print(f"[yellow]CAPA text output had warnings: {error_msg}[/yellow]")
                        if console:
                            console.print("[green]✓ CAPA executed successfully via shell alias[/green]")
                    elif result_text.stderr and console:
                        console.print(f"[yellow]CAPA stderr: {result_text.stderr[:200]}[/yellow]")
                else:
                    if console:
                        console.print(f"[yellow]CAPA shell execution returned: exit code {result_text.returncode}[/yellow]")
                        if result_text.stderr:
                            console.print(f"[yellow]Stderr: {result_text.stderr[:300]}[/yellow]")
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                if console:
                    console.print(f"[yellow]Shell execution failed: {e}[/yellow]")
                use_shell_execution = False  # Fall back to direct execution
            except Exception as e:
                if console:
                    console.print(f"[yellow]Shell execution error: {e}[/yellow]")
                    import traceback
                    console.print(f"[dim]{traceback.format_exc()}[/dim]")
                use_shell_execution = False  # Fall back to direct execution

        # Try direct execution if shell execution didn't work or wasn't needed
        if not capa_text_output:
            for cmd_base in commands_to_try:
                # Skip duplicates
                if len(commands_to_try) > 1 and cmd_base == ['capa'] and capa_path and capa_path == 'capa':
                    continue

                try:
                    # Determine CAPA command for text output
                    if verbose:
                        cmd_text = cmd_base + ['-vv', file_path]
                    else:
                        cmd_text = cmd_base + [file_path]

                    if console and getattr(self.args, 'capa_verbose', False):
                        console.print(f"[dim]Trying direct execution: {' '.join(cmd_text)}[/dim]")

                    result_text = subprocess.run(
                        cmd_text,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )

                    # Check if successful or has output
                    if result_text.returncode == 0 or result_text.stdout:
                        if result_text.stdout:
                            capa_text_output = result_text.stdout
                            working_cmd_base = cmd_base
                            if result_text.returncode != 0 and console:
                                error_msg = result_text.stderr.strip() if result_text.stderr else f"exit code {result_text.returncode}"
                                console.print(f"[yellow]CAPA text output had warnings: {error_msg}[/yellow]")
                            break
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue

        # Determine strategy for JSON execution
        if working_cmd_base:
            strategies_for_json = [working_cmd_base]
            use_shell_for_json = False
        elif use_shell_execution:
            strategies_for_json = []
            use_shell_for_json = True
        else:
            strategies_for_json = commands_to_try
            use_shell_for_json = False

        # ========== STEP 2: Run CAPA with --json for structured parsing ==========
        if console:
            console.print("[dim]Running CAPA for JSON structured output...[/dim]")

        if use_shell_for_json and shell_cmd and rc_file:
            # Use shell execution for JSON
            try:
                escaped_file_path = file_path.replace("'", "'\"'\"'")
                if verbose:
                    json_shell_command_str = f"source '{rc_file}' 2>/dev/null; capa --json -vv '{escaped_file_path}'"
                else:
                    json_shell_command_str = f"source '{rc_file}' 2>/dev/null; capa --json '{escaped_file_path}'"

                if console and getattr(self.args, 'capa_verbose', False):
                    console.print(f"[dim]Executing JSON via shell (interactive mode): {json_shell_command_str}[/dim]")

                # Use zsh -i (interactive mode) to enable alias expansion
                result_json = subprocess.run(
                    [shell_cmd, '-i', '-c', json_shell_command_str],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result_json.returncode == 0 or result_json.stdout:
                    if result_json.stdout:
                        try:
                            capa_json = json.loads(result_json.stdout)
                            capa_json_output = self._parse_capa_output(capa_json, verbose)
                        except json.JSONDecodeError as e:
                            if console:
                                console.print(f"[yellow]CAPA JSON parsing failed: {e}[/yellow]")
                            capa_json_output = {'error': 'JSON parsing failed', 'raw_output': result_json.stdout[:500]}
                else:
                    if console:
                        console.print(f"[yellow]CAPA JSON shell execution returned: exit code {result_json.returncode}[/yellow]")
                        if result_json.stderr:
                            console.print(f"[yellow]Stderr: {result_json.stderr[:300]}[/yellow]")
            except Exception as e:
                if console:
                    console.print(f"[yellow]Shell JSON execution failed: {e}[/yellow]")
                    import traceback
                    console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            # Use direct execution for JSON
            for cmd_base in strategies_for_json:
                try:
                    if verbose:
                        cmd_json = cmd_base + ['--json', '-vv', file_path]
                    else:
                        cmd_json = cmd_base + ['--json', file_path]

                    result_json = subprocess.run(
                        cmd_json,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )

                    if result_json.returncode == 0 or result_json.stdout:
                        if result_json.stdout:
                            try:
                                capa_json = json.loads(result_json.stdout)
                                capa_json_output = self._parse_capa_output(capa_json, verbose)
                                break
                            except json.JSONDecodeError as e:
                                if console:
                                    console.print(f"[yellow]CAPA JSON parsing failed: {e}[/yellow]")
                                capa_json_output = {'error': 'JSON parsing failed', 'raw_output': result_json.stdout[:500]}
                                break
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue

        if not capa_json_output and not capa_text_output:
            if console:
                console.print("[yellow]CAPA analysis produced no output from any execution strategy[/yellow]")
            return None

        # ========== STEP 3: Display text output in CLI mode with rich borders ==========
        if capa_text_output and console and not getattr(self.args, '_web_mode', False):
            # Calculate hash for file naming
            sha256 = self.calculate_sha256(file_path)
            hash_short = sha256[:8] if sha256 else "unknown"

            # Display with rich Panel
            console.print("")
            console.print(Panel(
                capa_text_output,
                title="[bold #C724B1]CAPA Static Analysis Report[/bold #C724B1]",
                border_style="#6A0DAD",
                box=box.DOUBLE,
                padding=(0, 1)
            ))
            console.print("")

        # ========== STEP 4: Save text output to file ==========
        # Default to True (save enabled) unless explicitly disabled
        save_text = getattr(self.args, 'save_capa_text', True)
        if save_text is None:
            save_text = True

        # Always include text_output in the return value, even if not saving to file
        if capa_json_output and capa_text_output:
            capa_json_output['text_output'] = capa_text_output

        if capa_text_output and save_text:
            try:
                sha256 = self.calculate_sha256(file_path)
                hash_short = sha256[:8] if sha256 else self.timestamp
                text_file_path = os.path.join(self.args.outdir, f"capa_report_{hash_short}.txt")

                with open(text_file_path, 'w', encoding='utf-8') as f:
                    f.write(capa_text_output)

                if console:
                    console.print(f"[green]CAPA text report saved: {text_file_path}[/green]")

                # Store file path in JSON output
                if capa_json_output:
                    capa_json_output['text_report_path'] = text_file_path
            except Exception as e:
                if console:
                    console.print(f"[yellow]Failed to save CAPA text report: {e}[/yellow]")

        # Return parsed JSON output (which now includes text output reference)
        return capa_json_output

    def _parse_capa_output(self, capa_json: Dict[str, Any], verbose: bool) -> Dict[str, Any]:
        """Parse CAPA JSON output into structured format."""
        try:
            # Extract metadata
            metadata = capa_json.get('meta', {})

            # Extract ATT&CK tactics and techniques
            attack_tactics = {}
            attack_techniques = []

            # Extract MBC behaviors
            mbc_objectives = {}

            # Extract capabilities
            capabilities = []

            # Parse rules/results
            rules = capa_json.get('rules', {})
            for rule_name, rule_data in rules.items():
                rule_meta = rule_data.get('meta', {})

                # Extract ATT&CK mappings
                attack_attrs = rule_meta.get('attack', [])
                if not attack_attrs:
                    attack_attrs = rule_meta.get('mitre-attack', [])

                for attack in attack_attrs:
                    tactic = attack.get('tactic', '') or attack.get('tactic-id', '')
                    technique = attack.get('technique', '') or attack.get('technique-id', '')
                    subtechnique = attack.get('subtechnique', '') or attack.get('subtechnique-id', '')

                    if tactic:
                        if tactic not in attack_tactics:
                            attack_tactics[tactic] = []
                        tech_str = technique
                        if subtechnique:
                            tech_str = f"{technique}.{subtechnique}"
                        attack_techniques.append({
                            'tactic': tactic,
                            'technique': tech_str,
                            'technique_id': technique,
                            'subtechnique': subtechnique,
                            'rule': rule_name
                        })

                # Extract MBC mappings
                mbc_attrs = rule_meta.get('mbc', [])
                for mbc in mbc_attrs:
                    objective = mbc.get('objective', '') or mbc.get('objective-id', '')
                    behavior = mbc.get('behavior', '') or mbc.get('behavior-id', '')

                    if objective:
                        if objective not in mbc_objectives:
                            mbc_objectives[objective] = []
                        mbc_objectives[objective].append({
                            'behavior': behavior,
                            'rule': rule_name
                        })

                # Extract capabilities
                namespace = rule_meta.get('namespace', '')
                if namespace:
                    capabilities.append({
                        'namespace': namespace,
                        'rule': rule_name,
                        'description': rule_meta.get('description', '')
                    })

            # Build structured output
            parsed = {
                'metadata': {
                    'capa_version': metadata.get('capa_version', 'unknown'),
                    'file_md5': metadata.get('file.md5', ''),
                    'file_sha1': metadata.get('file.sha1', ''),
                    'file_sha256': metadata.get('file.sha256', ''),
                    'os': metadata.get('os', ''),
                    'format': metadata.get('format', ''),
                    'arch': metadata.get('arch', ''),
                    'analysis': metadata.get('analysis', 'static')
                },
                'attack_tactics': attack_tactics,
                'attack_techniques': attack_techniques,
                'mbc_objectives': mbc_objectives,
                'capabilities': capabilities,
                'total_rules_matched': len(rules),
                'verbose_mode': verbose
            }

            return parsed

        except Exception as e:
            if console:
                console.print(f"[yellow]CAPA parsing error: {e}[/yellow]")
            return {'error': str(e)}

    def _parse_capa_text_output(self, text_output: str) -> Dict[str, Any]:
        """Fallback: Parse CAPA text output (less structured)."""
        # Basic text parsing as fallback
        return {
            'raw_output': text_output[:5000],  # Limit size
            'parsed': False,
            'error': 'JSON parsing failed, raw text available'
        }

    # ==================== LLM INTERACTION ====================

    def _truncate_data_for_llm(self, data: Dict[str, Any], max_items: int = 20) -> Dict[str, Any]:
        """Truncate large arrays in data to reduce LLM processing time."""
        truncated = {}
        for key, value in data.items():
            if isinstance(value, list) and len(value) > max_items:
                truncated[key] = value[:max_items]
                if key not in truncated:
                    truncated[f"{key}_truncated"] = True
                    truncated[f"{key}_total_count"] = len(value)
            elif isinstance(value, dict):
                truncated[key] = self._truncate_data_for_llm(value, max_items)
            else:
                truncated[key] = value
        return truncated

    def call_llm(self, prompt: str, data: Dict[str, Any], stage_name: str) -> Dict[str, Any]:
        """Call LLM with optimized JSON parsing and reduced payload size."""
        # Truncate large arrays to speed up processing
        truncated_data = self._truncate_data_for_llm(data, max_items=15)

        payload = {
            "model": self.args.model,
            "prompt": prompt.format(data=json.dumps(truncated_data, indent=2)),
            "stream": False,
            "options": {
                "temperature": 0,
                "num_predict": 1024,  # Reduced from 2048 for faster responses
                "top_p": 0.9,
                "repeat_penalty": 1.1
            }
        }

        console.print(f"[cyan]→ Stage: {stage_name} | Model: {self.args.model}[/cyan]")

        for attempt in range(self.args.retries):
            try:
                start_time = time.time()
                response = requests.post(self.args.ollama_url, json=payload, timeout=60)  # Reduced timeout
                response.raise_for_status()

                elapsed = time.time() - start_time
                result = response.json()
                response_text = result.get('response', '').strip()

                if not response_text:
                    # Try alternative response fields
                    response_text = result.get('text', result.get('output', '')).strip()

                # Save audit
                self._save_audit_log(stage_name, truncated_data, response_text)

                # Parse JSON with optimized parser
                parsed = safe_json_parse(response_text)

                if parsed:
                    console.print(f"[green]✓ Stage {stage_name} complete ({elapsed:.1f}s)[/green]")
                    return parsed

                # Show first 200 chars of response for debugging
                preview = response_text[:200].replace('\n', ' ')
                console.print(f"[yellow]Attempt {attempt + 1} failed to parse JSON. Response preview: {preview}...[/yellow]")

            except requests.Timeout:
                console.print(f"[yellow]Attempt {attempt + 1} timed out (>60s)[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Attempt {attempt + 1} failed: {e}[/yellow]")

            if attempt < self.args.retries - 1:
                time.sleep(min(2, 1.5 ** attempt))  # Cap sleep time

        console.print(f"[red]Stage {stage_name} failed after {self.args.retries} attempts, using fallback[/red]")
        return {"stage": stage_name, "error": "All attempts failed", "recommendation": "manual_review"}

    def _save_audit_log(self, stage: str, payload: Dict, response: Any):
        """Save audit log for each stage."""
        audit = {"timestamp": self.timestamp, "stage": stage, "payload": payload, "response": response}
        f = f"audit/{self.timestamp}_{stage}_audit.json"
        with open(f, 'w') as fh:
            json.dump(audit, fh, indent=2)

    # ==================== MULTI-STAGE ANALYSIS ====================

    def _display_stage_table(self, stage_name: str, data: Dict[str, Any], stage_num: int):
        """Display stage results in a formatted table."""
        table = Table(
            title=f"[bold #C724B1]Stage {stage_num}: {stage_name}[/bold #C724B1]",
            box=box.ROUNDED,
            border_style="#6A0DAD",
            header_style="bold #C724B1",
            show_header=True
        )
        table.add_column("Field", style="#C724B1", no_wrap=True, width=25)
        table.add_column("Value", style="white", overflow="fold")

        for key, value in data.items():
            if key == "stage":
                continue
            if isinstance(value, (list, dict)):
                if isinstance(value, list) and len(value) > 0:
                    display_value = ", ".join(str(v) for v in value[:5])
                    if len(value) > 5:
                        display_value += f" ... (+{len(value)-5} more)"
                elif isinstance(value, dict):
                    display_value = json.dumps(value, indent=2)[:200]
                    if len(json.dumps(value)) > 200:
                        display_value += "..."
                else:
                    display_value = "N/A"
            else:
                display_value = str(value)

            table.add_row(key.replace("_", " ").title(), display_value)

        console.print()
        console.print(table)
        console.print()

    def stage_1_extraction(self, strings: List[str], method: str, floss_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Stage 1: String extraction validation (includes FLOSS de-obfuscation results)."""
        console.print(Panel(
            "[bold #C724B1]Stage 1: String Extraction & FLOSS Analysis[/bold #C724B1]",
            border_style="#6A0DAD",
            box=box.DOUBLE
        ))

        # Build data for LLM including FLOSS results
        data = {
            "total_strings": len(strings),
            "extraction_method": method,
            "sample_strings": strings[:50],
            "string_length_distribution": {
                "short_4_10": len([s for s in strings if 4 <= len(s) <= 10]),
                "medium_11_50": len([s for s in strings if 11 <= len(s) <= 50]),
                "long_50plus": len([s for s in strings if len(s) > 50])
            },
            "floss_analysis": {
                "floss_used": "floss" in method.lower(),
                "floss_version": floss_data.get("floss_version", "N/A") if floss_data else "N/A",
                "floss_total_extracted": floss_data.get("total_extracted", 0) if floss_data else 0,
                "floss_extraction_methods": floss_data.get("extraction_methods", []) if floss_data else [],
                "floss_text_output": floss_data.get("text_output", "")[:2000] if floss_data and floss_data.get("text_output") else ""
            } if floss_data else None
        }

        if getattr(self.args, "no_llm", False):
            floss_observations = []
            if floss_data:
                floss_observations.append(f"FLOSS extracted {floss_data.get('total_extracted', 0)} de-obfuscated strings")
                if floss_data.get("extraction_methods"):
                    floss_observations.append(f"FLOSS methods: {', '.join(floss_data.get('extraction_methods', []))}")

            return {
                "stage": "string_extraction",
                "quality_assessment": "good",
                "total_strings": len(strings),
                "extraction_method": method,
                "key_observations": ["Extraction completed", f"Method: {method}"] + floss_observations,
                "potential_indicators": [],
                "recommendation": "proceed"
            }

        report = self.call_llm(STAGE_1_PROMPT, data, "stage_1_extraction")
        self.stage_reports["stage_1"] = report

        # Display stage results in table
        if report and not report.get("error"):
            self._display_stage_table("String Extraction & FLOSS", report, 1)

        if getattr(self.args, "stage_reports", False):
            self._save_stage_report("stage_1", report)

        return report

    def stage_2_categorization(self, categories: Dict[str, List[str]],
                               categorized_apis: Dict[str, List[str]],
                               capa_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Stage 2: Categorization validation with CAPA static analysis results."""
        console.print(Panel(
            "[bold #C724B1]Stage 2: Categorization & CAPA Static Analysis[/bold #C724B1]",
            border_style="#6A0DAD",
            box=box.DOUBLE
        ))

        # Build data including CAPA results for LLM analysis
        data = {
            "categorization": categories,
            "categorized_suspicious_apis": categorized_apis,
            "suspicious_api_count": len(categories.get("suspicious_api_calls", [])),
            "network_indicators": {
                "ips": len(categories.get("ips", [])),
                "domains": len(categories.get("domains", []))
            },
            "file_system_indicators": {
                "paths": len(categories.get("paths", [])),
                "dlls": len(categories.get("dlls", []))
            },
            "capa_static_analysis": None
        }

        # Add CAPA analysis results for LLM processing
        if capa_result and not capa_result.get('error'):
            attack_techniques = capa_result.get('attack_techniques', [])
            mbc_objectives = capa_result.get('mbc_objectives', {})
            capabilities = capa_result.get('capabilities', [])

            data["capa_static_analysis"] = {
                "attack_techniques_count": len(attack_techniques),
                "attack_techniques": [
                    {
                        "tactic": tech.get("tactic", ""),
                        "technique_id": tech.get("technique_id", ""),
                        "technique": tech.get("technique", ""),
                        "rule": tech.get("rule", "")
                    }
                    for tech in attack_techniques[:20]  # Limit for LLM context
                ],
                "mbc_behaviors_count": sum(len(behaviors) for behaviors in mbc_objectives.values()),
                "mbc_objectives": {
                    obj: [b.get("behavior", "") for b in behaviors[:5]]
                    for obj, behaviors in list(mbc_objectives.items())[:10]
                },
                "capabilities_count": len(capabilities),
                "top_capabilities": [
                    {
                        "namespace": cap.get("namespace", ""),
                        "rule": cap.get("rule", "")
                    }
                    for cap in capabilities[:15]
                ],
                "top_attack_tactics": list(capa_result.get('attack_tactics', {}).keys())[:10]
            }

        if getattr(self.args, "no_llm", False):
            capa_observations = []
            if capa_result and not capa_result.get('error'):
                attack_count = len(capa_result.get('attack_techniques', []))
                mbc_count = sum(len(behaviors) for behaviors in capa_result.get('mbc_objectives', {}).values())
                capa_observations = [
                    f"CAPA detected {attack_count} ATT&CK techniques",
                    f"CAPA detected {mbc_count} MBC behaviors"
                ]

            return {
                "stage": "categorization",
                "categorization_quality": "good",
                "suspicious_api_count": len(categories.get("suspicious_api_calls", [])),
                "network_indicators_count": len(categories.get("ips", [])) + len(categories.get("domains", [])),
                "key_api_categories": list(categorized_apis.keys())[:5],
                "notable_strings": categories.get("suspicious_api_calls", [])[:10],
                "capa_observations": capa_observations,
                "initial_risk_level": "high" if (capa_result and len(capa_result.get('attack_techniques', [])) > 5) else "medium",
                "recommendation": "proceed_to_reputation_check"
            }

        report = self.call_llm(STAGE_2_PROMPT, data, "stage_2_categorization")
        self.stage_reports["stage_2"] = report

        # Display stage results in table
        if report and not report.get("error"):
            self._display_stage_table("Categorization & CAPA", report, 2)

        if getattr(self.args, "stage_reports", False):
            self._save_stage_report("stage_2", report)

        return report

    def stage_3_threat_intelligence(self, vt_info: Dict[str, Any],
                                    dataset_matches: List[Dict[str, Any]],
                                    matched_patterns: List[str],
                                    dynamic_result: Optional[Dict[str, Any]] = None,
                                    capa_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Stage 3: Threat intelligence synthesis including VirusTotal, CAPA, and dynamic analysis."""
        console.print(Panel(
            "[bold #C724B1]Stage 3: Threat Intelligence Analysis (VirusTotal + CAPA + Dynamic)[/bold #C724B1]",
            border_style="#6A0DAD",
            box=box.DOUBLE
        ))

        vt_stats = vt_info.get("vt_stats", {})
        # Limit dataset matches to top 10 to reduce payload size
        limited_matches = dataset_matches[:10] if len(dataset_matches) > 10 else dataset_matches

        # Extract CAPA ATT&CK techniques and combine with VT
        capa_attack_techniques = []
        capa_technique_ids = []
        if capa_result and not capa_result.get('error'):
            capa_attack_techniques = capa_result.get('attack_techniques', [])
            capa_technique_ids = [tech.get('technique_id', '') for tech in capa_attack_techniques if tech.get('technique_id')]
            capa_technique_ids = list(set(capa_technique_ids))  # Remove duplicates

        # Combine VT engine labels with CAPA findings
        vt_engine_labels = vt_info.get("vt_classifications", [])[:5]

        # Build unified threat intelligence data
        data = {
            "vt_analysis": {
                "malicious": vt_stats.get("malicious", 0),
                "suspicious": vt_stats.get("suspicious", 0),
                "undetected": vt_stats.get("undetected", 0),
                "top_engine_labels": vt_engine_labels,
                "detection_ratio": f"{vt_stats.get('malicious', 0)}/{sum(vt_stats.values())}" if sum(vt_stats.values()) > 0 else "0/0"
            },
            "capa_analysis": {
                "attack_techniques_count": len(capa_attack_techniques),
                "attack_technique_ids": capa_technique_ids[:20],  # Limit to 20
                "mbc_behaviors_count": sum(len(behaviors) for behaviors in capa_result.get('mbc_objectives', {}).values()) if capa_result and not capa_result.get('error') else 0,
                "capabilities_count": len(capa_result.get('capabilities', [])) if capa_result and not capa_result.get('error') else 0,
                "top_attack_tactics": list(capa_result.get('attack_tactics', {}).keys())[:10] if capa_result and not capa_result.get('error') else []
            } if capa_result and not capa_result.get('error') else None,
            "combined_threat_intelligence": {
                "vt_detection_rate": (vt_stats.get("malicious", 0) / max(1, sum(vt_stats.values()))) * 100 if sum(vt_stats.values()) > 0 else 0,
                "capa_ttp_count": len(capa_technique_ids),
                "unified_risk_indicators": self._combine_vt_capa_indicators(vt_info, capa_result)
            },
            "dataset_matches": limited_matches,
            "dataset_matches_total": len(dataset_matches),
            "behavioral_patterns": matched_patterns,
            "dynamic_analysis": dynamic_result if dynamic_result else None
        }

        if getattr(self.args, "no_llm", False):
            dynamic_verdict = dynamic_result.get("verdict", "unknown") if dynamic_result else "unknown"
            dynamic_source = dynamic_result.get("source", "None") if dynamic_result else "None"

            # Combine VT and CAPA for heuristic analysis
            capa_tech_count = len(capa_technique_ids) if capa_result and not capa_result.get('error') else 0
            combined_indicators = self._combine_vt_capa_indicators(vt_info, capa_result)

            # Calculate combined threat score
            vt_score = (vt_stats.get("malicious", 0) / max(1, sum(vt_stats.values()))) * 100 if sum(vt_stats.values()) > 0 else 0
            capa_score = min(100, capa_tech_count * 10)  # 10 points per technique, capped at 100
            combined_threat_score = max(vt_score, capa_score) if (vt_score > 0 or capa_score > 0) else 0

            return {
                "stage": "threat_intelligence",
                "vt_detection_count": vt_stats.get("malicious", 0),
                "vt_total_engines": sum(vt_stats.values()),
                "capa_attack_techniques_count": capa_tech_count,
                "capa_mbc_behaviors_count": sum(len(behaviors) for behaviors in capa_result.get('mbc_objectives', {}).values()) if capa_result and not capa_result.get('error') else 0,
                "combined_threat_score": int(combined_threat_score),
                "dataset_matches_count": len(dataset_matches),
                "behavioral_patterns_matched": matched_patterns,
                "dynamic_analysis_verdict": dynamic_verdict,
                "dynamic_analysis_source": dynamic_source,
                "reputation_summary": "suspicious" if (vt_stats.get("malicious", 0) > 0 or capa_tech_count > 0 or (dynamic_result and dynamic_verdict in ["malicious", "suspicious"])) else "clean",
                "confidence": 0.9 if (vt_stats.get("malicious", 0) >= 10 or capa_tech_count >= 5 or matched_patterns) else (0.7 if (vt_stats.get("malicious", 0) > 0 or capa_tech_count > 0) else 0.5),
                "key_evidence": combined_indicators[:10],
                "unified_ttp_list": capa_technique_ids[:10],
                "recommendation": "proceed_to_final_analysis"
            }

        report = self.call_llm(STAGE_3_PROMPT, data, "stage_3_threat_intelligence")
        self.stage_reports["stage_3"] = report

        # Display stage results in table
        if report and not report.get("error"):
            self._display_stage_table("Threat Intelligence", report, 3)

        if getattr(self.args, "stage_reports", False):
            self._save_stage_report("stage_3", report)

        return report

    def _display_final_analysis_table(self, analysis: Dict[str, Any]):
        """Display final analysis results in a comprehensive table."""
        table = Table(
            title="[bold #C724B1]Final Analysis Results[/bold #C724B1]",
            box=box.DOUBLE,
            border_style="#6A0DAD",
            header_style="bold #C724B1",
            show_header=True
        )
        table.add_column("Field", style="#C724B1", no_wrap=True, width=25)
        table.add_column("Value", style="white", overflow="fold")

        # Verdict with color coding
        verdict = analysis.get("verdict", "unknown")
        verdict_color = {
            "malicious": "bold red",
            "suspicious": "bold yellow",
            "benign": "bold green"
        }.get(verdict.lower(), "white")
        table.add_row("Verdict", f"[{verdict_color}]{verdict.upper()}[/{verdict_color}]")

        # Confidence and Score
        confidence = analysis.get("confidence", 0)
        score = analysis.get("score", 0)
        table.add_row("Confidence", f"{confidence:.2f}")
        table.add_row("Risk Score", f"{score}/100")

        # Malware family
        if analysis.get("malware_family"):
            table.add_row("Malware Family", analysis.get("malware_family", "unknown"))

        # TTP Matches
        ttp_matches = analysis.get("ttp_matches", [])
        if ttp_matches:
            table.add_row("TTP Matches", ", ".join(ttp_matches))

        # Primary Capabilities
        capabilities = analysis.get("primary_capabilities", [])
        if capabilities:
            table.add_row("Primary Capabilities", ", ".join(capabilities[:5]))

        # Indicators
        indicators = analysis.get("indicators", [])
        if indicators:
            ind_display = ", ".join(indicators[:5])
            if len(indicators) > 5:
                ind_display += f" ... (+{len(indicators)-5} more)"
            table.add_row("Indicators", ind_display)

        # Recommended Actions
        actions = analysis.get("recommended_actions", [])
        if actions:
            table.add_row("Recommended Actions", ", ".join(actions))

        # Explanation
        explanation = analysis.get("explanation", "")
        if explanation:
            # Truncate long explanations
            if len(explanation) > 300:
                explanation = explanation[:300] + "..."
            table.add_row("Explanation", explanation)

        console.print()
        console.print(table)
        console.print()

    def stage_4_final_analysis(self, full_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 4: Final comprehensive analysis."""
        console.print(Panel(
            "[bold #C724B1]Stage 4: Final Comprehensive Analysis[/bold #C724B1]",
            border_style="#6A0DAD",
            box=box.DOUBLE
        ))

        if getattr(self.args, "no_llm", False):
            heuristic_result = self._heuristic_final_analysis(full_payload)
            # Display heuristic analysis table
            self._display_final_analysis_table(heuristic_result)
            return heuristic_result

        # Truncate full payload for final analysis - be more aggressive
        truncated_payload = self._truncate_data_for_llm(full_payload, max_items=10)

        # Prepare stage summary for prompts
        stage_reports_summary = {
            "stage_1": self.stage_reports.get("stage_1", {}),
            "stage_2": self.stage_reports.get("stage_2", {}),
            "stage_3": self.stage_reports.get("stage_3", {})
        }

        # Try JSON format first
        compact_prompt_json = f"""Return ONLY valid JSON starting with {{ and ending with }}. No explanations.

{{
  "verdict": "benign|suspicious|malicious",
  "confidence": 0.0-1.0,
  "score": 0-100,
  "malware_family": "unknown",
  "primary_capabilities": [],
  "ttp_matches": [],
  "indicators": [],
  "explanation": "Analysis",
  "recommended_actions": [],
  "artifacts": {{"yara_rule_draft": "", "iocs": []}},
  "stage_synthesis": "Summary",
  "evidence_map": {{}}
}}

Stages: {json.dumps(stage_reports_summary, indent=1)[:1000]}
Data: {json.dumps(truncated_payload, indent=1)[:1500]}"""

        # Fallback: KEY: VALUE format (more reliable)
        compact_prompt_kv = f"""Analyze and return using KEY: VALUE format. No JSON, no markdown.

VERDICT: benign|suspicious|malicious
CONFIDENCE: 0.0-1.0
SCORE: 0-100
MALWARE_FAMILY: unknown
PRIMARY_CAPABILITIES: item1, item2
TTP_MATCHES: T1055, T1071
INDICATORS: indicator1, indicator2
EXPLANATION: Brief analysis
RECOMMENDED_ACTIONS: action1, action2
STAGE_SYNTHESIS: Summary

Stages: {json.dumps(stage_reports_summary, indent=1)[:1000]}
Data: {json.dumps(truncated_payload, indent=1)[:1500]}"""

        console.print(f"[cyan]→ Stage: Final Analysis | Model: {self.args.model}[/cyan]")

        # Initialize response_text before loops
        response_text = None

        # Try JSON format first
        for attempt in range(self.args.retries):
            try:
                start_time = time.time()
                payload_json = {
                    "model": self.args.model,
                    "prompt": compact_prompt_json,
                    "stream": False,
                    "options": {
                        "temperature": 0,
                        "num_predict": 800,
                        "top_p": 0.9,
                        "repeat_penalty": 1.2,
                        "stop": ["\n\n", "```"]
                    }
                }

                response = requests.post(self.args.ollama_url, json=payload_json, timeout=45)
                response.raise_for_status()

                elapsed = time.time() - start_time
                result = response.json()
                response_text = result.get('response', '').strip()

                if not response_text:
                    response_text = result.get('text', result.get('output', '')).strip()

                self._save_audit_log("stage_4_final", truncated_payload, response_text)

                # Try JSON parsing
                parsed = safe_json_parse(response_text)

                if parsed:
                    console.print(f"[green]✓ Final analysis complete (JSON, {elapsed:.1f}s)[/green]")
                    self.stage_reports["stage_4"] = parsed
                    # Display final analysis table
                    self._display_final_analysis_table(parsed)
                    if getattr(self.args, "stage_reports", False):
                        self._save_stage_report("stage_4", parsed)
                    return parsed

            except requests.Timeout:
                console.print(f"[yellow]JSON attempt {attempt + 1} timed out[/yellow]")
            except Exception as e:
                console.print(f"[yellow]JSON attempt {attempt + 1} failed: {e}[/yellow]")

            if attempt < self.args.retries - 1:
                time.sleep(min(2, 1.5 ** attempt))

        # Fallback to KEY: VALUE format (more reliable)
        console.print("[cyan]Trying KEY:VALUE format (more reliable)...[/cyan]")
        for attempt in range(self.args.retries):
            try:
                start_time = time.time()
                payload_kv = {
                    "model": self.args.model,
                    "prompt": compact_prompt_kv,
                    "stream": False,
                    "options": {
                        "temperature": 0,
                        "num_predict": 600,  # Even smaller for KV format
                        "top_p": 0.9,
                        "repeat_penalty": 1.2
                    }
                }

                response = requests.post(self.args.ollama_url, json=payload_kv, timeout=45)
                response.raise_for_status()

                elapsed = time.time() - start_time
                result = response.json()
                response_text = result.get('response', '').strip()

                if not response_text:
                    response_text = result.get('text', result.get('output', '')).strip()

                # Try KEY:VALUE parsing
                parsed = parse_key_value_output(response_text)

                if parsed:
                    console.print(f"[green]✓ Final analysis complete (KEY:VALUE, {elapsed:.1f}s)[/green]")
                    self.stage_reports["stage_4"] = parsed
                    # Display final analysis table
                    self._display_final_analysis_table(parsed)
                    if getattr(self.args, "stage_reports", False):
                        self._save_stage_report("stage_4", parsed)
                    return parsed

            except requests.Timeout:
                console.print(f"[yellow]KEY:VALUE attempt {attempt + 1} timed out[/yellow]")
            except Exception as e:
                console.print(f"[yellow]KEY:VALUE attempt {attempt + 1} failed: {e}[/yellow]")

            if attempt < self.args.retries - 1:
                time.sleep(min(2, 1.5 ** attempt))

        # Last resort: Extract from text
        console.print("[yellow]Attempting text extraction fallback...[/yellow]")
        if response_text:
            parsed = extract_from_text(response_text, truncated_payload)
            if parsed:
                console.print(f"[green]✓ Final analysis complete (text extraction)[/green]")
                self.stage_reports["stage_4"] = parsed
                # Display final analysis table
                self._display_final_analysis_table(parsed)
                if getattr(self.args, "stage_reports", False):
                    self._save_stage_report("stage_4", parsed)
                return parsed

        console.print(f"[red]All parsing methods failed, using heuristic[/red]")
        heuristic_result = self._heuristic_final_analysis(full_payload)
        # Display heuristic analysis table
        self._display_final_analysis_table(heuristic_result)
        return heuristic_result

    def _heuristic_final_analysis(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Heuristic final analysis when LLM is disabled."""
        vt_info = payload.get("vt_analysis", {})
        matched_patterns = payload.get("hardcoded_behavioral_matches", [])
        dataset_matches = payload.get("dataset_sequence_matches", [])

        vt_stats = vt_info.get("vt_stats", {})
        malicious = vt_stats.get("malicious", 0)

        if matched_patterns:
            verdict = "malicious"
            confidence = 0.95
            score = 95
        elif malicious >= 10:
            verdict = "suspicious"
            confidence = 0.85
            score = 85
        elif malicious > 0:
            verdict = "suspicious"
            confidence = 0.6
            score = 60
        else:
            verdict = "benign"
            confidence = 0.1
            score = 10

        return {
            "verdict": verdict,
            "confidence": confidence,
            "score": score,
            "malware_family": "unknown",
            "primary_capabilities": [],
            "ttp_matches": [p.split('(')[-1].strip(')') for p in matched_patterns if '(' in p],
            "indicators": payload.get("strings_summary", {}).get("api_calls_observed", [])[:10],
            "explanation": f"Heuristic analysis: {verdict} with confidence {confidence}",
            "recommended_actions": ["Isolate host", "Review logs"],
            "artifacts": {},
            "stage_synthesis": "Heuristic analysis based on patterns and VT",
            "evidence_map": {}
        }

    def _save_stage_report(self, stage_name: str, report: Dict[str, Any]):
        """Save individual stage report."""
        report_path = f"{self.args.outdir}/stages/{stage_name}_{self.timestamp}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

    # ==================== REPORTING ====================

    def display_quick_report(self, payload: Dict[str,Any], vt_info: Dict[str,Any],
                            dataset_matches: List[Dict[str,Any]], matched_patterns: List[str]):
        """Display quick report table."""
        t = Table(title="Quick Report", box=box.MINIMAL_DOUBLE_HEAD)
        t.add_column("Field", style="bold cyan", no_wrap=True)
        t.add_column("Value", style="white")
        t.add_row("File", Path(payload.get("file_metadata",{}).get("file_name","N/A")).name or "N/A")
        t.add_row("SHA256", payload.get("file_metadata",{}).get("sha256","N/A"))
        t.add_row("Total Strings", str(payload.get("strings_summary",{}).get("total_strings",0)))
        t.add_row("Suspicious API count", str(len(payload.get("strings_summary",{}).get("api_calls_observed",[]))))
        vt_stats = vt_info.get("vt_stats",{})
        t.add_row("VT (mal/susp/undetected)", f"{vt_stats.get('malicious',0)}/{vt_stats.get('suspicious',0)}/{vt_stats.get('undetected',0)}")
        t.add_row("Dataset matches", str(len(dataset_matches)))
        t.add_row("Matched patterns", ", ".join(matched_patterns) if matched_patterns else "None")
        console.print(Panel(t, title="🔎 Quick Intelligence", border_style="bright_blue"))

    def write_reports(self, payload: Dict, analysis: Dict) -> Tuple[str,str]:
        """Write JSON and Markdown reports."""
        base = f"analysis_{Path(self.args.file).stem}_{self.timestamp}"
        json_path = f"{self.args.outdir}/{base}.json"

        report_data = {
            "metadata": {
                "file": self.args.file,
                "timestamp": self.timestamp,
                "tool_version": "3.0-hybrid"
            },
            "stage_reports": self.stage_reports,
            "full_payload": payload,
            "final_analysis": analysis
        }

        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        md_path = f"{self.args.outdir}/{base}.md"
        md_content = self._generate_markdown(payload, analysis)
        with open(md_path, 'w') as f:
            f.write(md_content)

        return json_path, md_path

    def _generate_markdown(self, payload: Dict, analysis: Dict) -> str:
        """Generate Markdown report."""
        md = f"""# Binary Analysis Report

## File Information
- **File**: `{self.args.file}`
- **Analysis Time**: {self.timestamp}
- **SHA256**: {payload.get("file_metadata",{}).get("sha256","N/A")}

## Stage Reports

"""
        for stage_name, stage_report in self.stage_reports.items():
            md += f"### {stage_name.replace('_', ' ').title()}\n\n"
            md += f"```json\n{json.dumps(stage_report, indent=2)}\n```\n\n"

        # Get combined threat intelligence
        vt_info = payload.get("vt_analysis", {})
        capa_info = payload.get("capa_analysis", {})

        md += f"""## Final Security Assessment
- **Verdict**: `{analysis.get("verdict","unknown")}`
- **Confidence**: {analysis.get("confidence",0):.2f}
- **Risk Score**: {analysis.get("score",0)}/100
- **Malware Family**: {analysis.get("malware_family","unknown")}

## Combined Threat Intelligence (VirusTotal + CAPA)

### VirusTotal Results
- **Malicious Detections**: {vt_info.get("malicious",0)}
- **Suspicious Detections**: {vt_info.get("suspicious",0)}
- **Detection Ratio**: {vt_info.get("detection_ratio","N/A")}
"""

        if vt_info.get("top_engine_labels"):
            md += "\n**Top Engine Classifications:**\n"
            for label in vt_info.get("top_engine_labels", [])[:10]:
                engine = label.get("engine", "Unknown")
                result = label.get("result", "N/A")
                md += f"- {engine}: {result}\n"

        if capa_info:
            md += f"""
### CAPA Static Analysis Results
- **ATT&CK Techniques Detected**: {capa_info.get("attack_techniques_count", 0)}
- **MBC Behaviors Detected**: {capa_info.get("mbc_behaviors_count", 0)}
- **Capabilities Identified**: {capa_info.get("capabilities_count", 0)}
"""
            if capa_info.get("attack_technique_ids"):
                md += "\n**ATT&CK Technique IDs:**\n"
                for tech_id in capa_info.get("attack_technique_ids", [])[:20]:
                    md += f"- {tech_id}\n"

            if capa_info.get("top_attack_tactics"):
                md += "\n**Top Attack Tactics:**\n"
                for tactic in capa_info.get("top_attack_tactics", [])[:10]:
                    md += f"- {tactic}\n"

            # Include CAPA text output if available
            if capa_info.get("text_output"):
                text_report_path = capa_info.get("text_report_path", "N/A")
                md += f"\n### CAPA Static Analysis Report (Full Text Output)\n"
                if text_report_path != "N/A":
                    md += f"**Report File**: `{text_report_path}`\n\n"
                md += "```\n"
                # Limit text output to avoid huge markdown files (first 5000 chars)
                text_output = capa_info.get("text_output", "")
                if len(text_output) > 5000:
                    md += text_output[:5000]
                    md += f"\n\n... (truncated, full report saved to {text_report_path}) ..."
                else:
                    md += text_output
                md += "\n```\n"

        md += f"""

## Explanation
{analysis.get("explanation","N/A")}

## Primary Capabilities
{chr(10).join(f"- {cap}" for cap in analysis.get("primary_capabilities",[]))}

## MITRE ATT&CK TTPs (Unified)
{chr(10).join(f"- {ttp}" for ttp in analysis.get("ttp_matches",[]))}

## Indicators
{chr(10).join(f"- {ind}" for ind in analysis.get("indicators",[]))}

## Recommended Actions
{chr(10).join(f"- {action}" for action in analysis.get("recommended_actions",[]))}

## Stage Synthesis
{analysis.get("stage_synthesis","N/A")}
"""
        return md

    # ==================== PRE-STAGE TOOL EXECUTION ====================

    def _execute_floss_and_save(self, file_path: str, json_path: str, file_hash: str) -> Tuple[List[str], Dict[str, Any]]:
        """Execute FLOSS tool, save output to JSON file, and return parsed results.

        This runs FLOSS FIRST (pre-stage), waits for completion, saves to JSON,
        then returns parsed data for use in stages.

        Args:
            file_path: Path to binary file to analyze
            json_path: Path where FLOSS JSON output should be saved
            file_hash: SHA256 hash of the file (for metadata)

        Returns:
            Tuple of (list of strings, metadata dict)
        """
        # Check if JSON file already exists
        if os.path.exists(json_path):
            if console:
                console.print(f"[cyan]Loading FLOSS output from existing file: {json_path}[/cyan]")

            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    saved_data = json.load(f)

                # Extract data from saved JSON structure
                all_strings = saved_data.get('strings', [])
                metadata = saved_data.get('metadata', {})

                if console:
                    console.print(f"[green]✓ Loaded {len(all_strings)} strings from saved FLOSS output[/green]")

                return all_strings, metadata
            except Exception as e:
                if console:
                    console.print(f"[yellow]Failed to load saved FLOSS output: {e}[/yellow]")

        # Execute FLOSS and get results
        if console:
            console.print("[bold cyan]Executing FLOSS (this may take a while)...[/bold cyan]")

        strings, metadata = self._extract_strings_floss(file_path)

        # Save complete output to JSON file using the provided path
        output_data = {
            'file_hash': file_hash,
            'file_path': file_path,
            'timestamp': self.timestamp,
            'strings': strings,
            'metadata': metadata
        }

        # Ensure output directory exists
        os.makedirs(os.path.dirname(json_path), exist_ok=True)

        # Save to the specified JSON path
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)

            if console and not getattr(self.args, '_web_mode', False):
                console.print(f"[green]✓ FLOSS output saved to: {json_path}[/green]")
        except Exception as e:
            if console:
                console.print(f"[yellow]Failed to save FLOSS JSON output: {e}[/yellow]")

        return strings, metadata

    def _execute_capa_and_save(self, file_path: str, json_path: str, file_hash: str, verbose: bool = False) -> Optional[Dict[str, Any]]:
        """Execute CAPA tool, save output to JSON file, and return parsed results.

        This runs CAPA FIRST (pre-stage), waits for completion, saves to JSON,
        then returns parsed data for use in stages.

        Args:
            file_path: Path to binary file to analyze
            json_path: Path where CAPA JSON output should be saved
            file_hash: SHA256 hash of the file (for metadata)
            verbose: Whether to use CAPA verbose mode

        Returns:
            Parsed CAPA results dict or None if failed
        """
        # Check if JSON file already exists
        if os.path.exists(json_path):
            if console:
                console.print(f"[cyan]Loading CAPA output from existing file: {json_path}[/cyan]")

            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    saved_data = json.load(f)

                # Return saved CAPA results
                if console:
                    console.print("[green]✓ Loaded CAPA results from saved output[/green]")

                return saved_data.get('parsed_result', saved_data)
            except Exception as e:
                if console:
                    console.print(f"[yellow]Failed to load saved CAPA output: {e}[/yellow]")

        # Execute CAPA and get results
        if console:
            console.print("[bold cyan]Executing CAPA (this may take a while)...[/bold cyan]")

        capa_result = self.run_capa_analysis(file_path, verbose=verbose)

        # Save complete output to JSON file using the provided path
        output_data = {
            'file_hash': file_hash,
            'file_path': file_path,
            'timestamp': self.timestamp,
            'verbose_mode': verbose,
            'parsed_result': capa_result
        }

        # Also include text output and file path if available
        if capa_result:
            if 'text_output' in capa_result:
                output_data['text_output'] = capa_result.get('text_output', '')
            if 'text_report_path' in capa_result:
                output_data['text_report_path'] = capa_result.get('text_report_path', '')

        # Ensure output directory exists
        os.makedirs(os.path.dirname(json_path), exist_ok=True)

        # Save to the specified JSON path
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)

            if console and not getattr(self.args, '_web_mode', False):
                console.print(f"[green]✓ CAPA output saved to: {json_path}[/green]")
        except Exception as e:
            if console:
                console.print(f"[yellow]Failed to save CAPA JSON output: {e}[/yellow]")

        return capa_result

    # ==================== MAIN PIPELINE ====================

    def run_analysis(self):
        """Main analysis workflow with multi-stage LLM reporting."""
        if not os.path.exists(self.args.file):
            error_msg = f"File not found: {self.args.file}"
            if console:
                console.print(f"[red]{error_msg}[/red]")
            # Don't sys.exit in web mode - raise exception instead
            if not getattr(self.args, "_web_mode", False):
                sys.exit(1)
            else:
                raise FileNotFoundError(error_msg)

        # Calculate SHA256 first (needed for various operations)
        sha256 = self.calculate_sha256(self.args.file)
        console.print(f"[cyan]SHA256: {sha256}[/cyan]" if sha256 else "[yellow]SHA256 failed[/yellow]")

        # ==================== PRE-STAGE: Execute FLOSS and CAPA Tools First ====================
        # Define JSON file paths for tool outputs
        floss_json_path = os.path.join(self.args.outdir, f"floss_output_{sha256[:8]}.json")
        capa_json_path = os.path.join(self.args.outdir, f"capa_output_{sha256[:8]}.json")

        # Initialize tool results
        floss_strings = []
        floss_metadata = {}
        capa_result = None

        # Pre-Stage 1: Execute FLOSS (if not disabled)
        if not getattr(self.args, "no_floss", False):
            console.print(Panel(
                "[bold #C724B1]Pre-Stage: Running FLOSS String De-obfuscation[/bold #C724B1]",
                border_style="#6A0DAD",
                box=box.DOUBLE
            ))

            with Progress(SpinnerColumn(), TextColumn("[magenta]Running FLOSS (this may take a while)..."), console=console) as p:
                p.add_task("floss", total=None)
                try:
                    floss_strings, floss_metadata = self._execute_floss_and_save(
                        self.args.file, floss_json_path, sha256
                    )

                    if floss_strings:
                        console.print(f"[green]✓ FLOSS completed: Extracted {len(floss_strings)} de-obfuscated strings[/green]")

                        # Display FLOSS text output if available (human-readable for CLI)
                        if floss_metadata.get("text_output"):
                            console.print(Panel(
                                floss_metadata.get("text_output", "")[:3000] + ("..." if len(floss_metadata.get("text_output", "")) > 3000 else ""),
                                title="[bold #C724B1]FLOSS De-obfuscation Output[/bold #C724B1]",
                                border_style="#6A0DAD",
                                box=box.DOUBLE,
                                padding=(0, 1)
                            ))
                    else:
                        console.print("[yellow]FLOSS completed but no strings extracted[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]FLOSS execution failed: {e}[/yellow]")
                    floss_strings, floss_metadata = [], {}
        else:
            console.print("[yellow]Skipping FLOSS (--no-floss set)[/yellow]")

        # Pre-Stage 2: Execute CAPA (if not disabled)
        if not getattr(self.args, "no_capa", False):
            console.print(Panel(
                "[bold #C724B1]Pre-Stage: Running CAPA Static Analysis: MITRE ATT&CK TTP Detection[/bold #C724B1]",
                border_style="#6A0DAD",
                box=box.DOUBLE
            ))

            verbose_mode = getattr(self.args, "capa_verbose", False)
            try:
                # Execute CAPA (output will be displayed inside run_capa_analysis)
                capa_result = self._execute_capa_and_save(
                    self.args.file, capa_json_path, sha256, verbose_mode
                )

                if capa_result and not capa_result.get('error'):
                    attack_count = len(capa_result.get('attack_techniques', []))
                    mbc_count = sum(len(behaviors) for behaviors in capa_result.get('mbc_objectives', {}).values())
                    console.print(f"[green]✓ CAPA completed: {attack_count} ATT&CK techniques, {mbc_count} MBC behaviors detected[/green]")

                    # Display CAPA text output in pre-stage
                    if capa_result.get('text_output') and console and not getattr(self.args, '_web_mode', False):
                        console.print("")
                        console.print(Panel(
                            capa_result.get('text_output', ''),
                            title="[bold #C724B1]CAPA Static Analysis Report (Pre-Stage)[/bold #C724B1]",
                            border_style="#6A0DAD",
                            box=box.DOUBLE,
                            padding=(0, 1)
                        ))
                        console.print("")
                    
                    # Also display saved text file if available
                    if capa_result.get('text_report_path') and os.path.exists(capa_result.get('text_report_path')):
                        try:
                            with open(capa_result.get('text_report_path'), 'r', encoding='utf-8') as f:
                                file_content = f.read()
                            if file_content and console and not getattr(self.args, '_web_mode', False):
                                console.print(f"[cyan]CAPA text report saved to: {capa_result.get('text_report_path')}[/cyan]")
                        except Exception as e:
                            if console:
                                console.print(f"[yellow]Could not read CAPA text file: {e}[/yellow]")
                else:
                    console.print("[yellow]CAPA completed but produced no results[/yellow]")
            except Exception as e:
                console.print(f"[yellow]CAPA execution failed: {e}[/yellow]")
                capa_result = None
        else:
            console.print("[yellow]Skipping CAPA (--no-capa set)[/yellow]")

        # ==================== STAGE 1: String Extraction + FLOSS ====================
        console.print(Panel(
            "[bold #C724B1]Stage 1: String Extraction & Analysis[/bold #C724B1]",
            border_style="#6A0DAD",
            box=box.DOUBLE
        ))

        # Extract strings (will use FLOSS results if available)
        with Progress(SpinnerColumn(), TextColumn("[magenta]Extracting strings..."), console=console) as p:
            p.add_task("s", total=None)
            strings, method, floss_data = self.extract_strings(self.args.file)

            # If FLOSS was run in pre-stage, merge its results
            if floss_strings:
                # Merge FLOSS strings with extracted strings
                all_strings = list(set(strings + floss_strings))
                strings = all_strings

                # Update floss_data with pre-stage results
                if not floss_data:
                    floss_data = {}
                floss_data.update({
                    'pre_stage_floss': True,
                    'floss_strings_count': len(floss_strings),
                    'floss_metadata': floss_metadata,
                    'text_output': floss_metadata.get('text_output', ''),
                    'json_data': floss_metadata.get('json_data', {})
                })
                console.print(f"[cyan]Merged {len(floss_strings)} FLOSS strings with extracted strings[/cyan]")

        if not strings:
            error_msg = "No strings extracted"
            if console:
                console.print(f"[red]{error_msg}[/red]")
            # Don't sys.exit in web mode
            if not getattr(self.args, "_web_mode", False):
                sys.exit(1)
            else:
                raise ValueError(error_msg)

        console.print(f"[green]Extracted {len(strings)} total strings (method={method})[/green]")

        # Stage 1 LLM Report (includes FLOSS analysis)
        stage1_report = self.stage_1_extraction(strings, method, floss_data)

        # Categorize strings
        categorized, categorized_apis_summary = self.categorize_strings(strings)
        extracted_api_calls = categorized.get("suspicious_api_calls", [])

        # ==================== STAGE 2: Categorization + CAPA Analysis ====================
        # Stage 2 LLM Report now includes CAPA results from pre-stage
        stage2_report = self.stage_2_categorization(categorized, categorized_apis_summary, capa_result)

        # VirusTotal lookup
        if getattr(self.args, "no_vt", False):
            vt_info = {"raw": None, "vt_stats":{"malicious":0,"suspicious":0,"undetected":0},
                      "vt_classifications": [], "error":"no_vt_flag"}
            console.print("[yellow]Skipping VirusTotal lookup (--no-vt set)[/yellow]")
        else:
            with Progress(SpinnerColumn(), TextColumn("[magenta]Querying VirusTotal..."), console=console) as p:
                p.add_task("vt", total=None)
                vt_info = self.virustotal_lookup(sha256)
            if vt_info.get("error"):
                console.print(f"[yellow]VT: {vt_info.get('error')}[/yellow]")
            else:
                s = vt_info.get("vt_stats",{})
                console.print(f"[green]VT stats: mal={s.get('malicious',0)} suspicious={s.get('suspicious',0)} undetected={s.get('undetected',0)}[/green]")

        # Match behavioral patterns
        matched_patterns = self.match_api_sequences(strings)
        console.print(f"[red]Matched patterns: {matched_patterns}[/red]" if matched_patterns else "[cyan]No hard-coded behavioral patterns matched[/cyan]")

        # CSV dataset matching
        dataset_matches = []
        if getattr(self.args, "dataset_csv", None):
            ds_entries = self.load_dataset_csv(self.args.dataset_csv)
            dataset_matches = self.match_dataset(ds_entries, extracted_api_calls)
            console.print(f"[cyan]Dataset matches: {len(dataset_matches)}[/cyan]" if dataset_matches else "[cyan]No dataset matches[/cyan]")

        # Dynamic analysis (Hybrid Analysis)
        dynamic_result = None
        if not getattr(self.args, "no_dynamic", False):
            dynamic_result = self.orchestrate_dynamic_analysis(self.args.file)
            if dynamic_result:
                console.print(f"[green]Dynamic analysis completed: {dynamic_result.get('source', 'Unknown')} - {dynamic_result.get('verdict', 'unknown')}[/green]")
            else:
                console.print("[yellow]Dynamic analysis unavailable or failed[/yellow]")

        # Stage 3 LLM Report (includes dynamic analysis and CAPA)
        stage3_report = self.stage_3_threat_intelligence(vt_info, dataset_matches, matched_patterns, dynamic_result, capa_result)

        # Build unified payload
        filename = Path(self.args.file).name
        vt_stats = vt_info.get("vt_stats", {"malicious":0,"suspicious":0,"undetected":0})
        total_engines = vt_stats.get("malicious",0) + vt_stats.get("suspicious",0) + vt_stats.get("undetected",0) or 0
        detection_ratio = f"{vt_stats.get('malicious',0)}/{total_engines}" if total_engines else "0/0"

        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_pattern = re.compile(r'https?://[^\s,\'"]+')
        extracted_ips = [s for s in strings if ip_pattern.search(s)]
        extracted_urls = [s for s in strings if url_pattern.search(s)]

        full_payload = {
            "file_metadata": {
                "file_name": filename,
                "sha256": sha256,
                "file_type": (vt_info.get("raw", {}).get("data", {}).get("attributes", {}).get("type_description")) if vt_info.get("raw") else "",
                "size": (vt_info.get("raw", {}).get("data", {}).get("attributes", {}).get("size")) if vt_info.get("raw") else None
            },
            "vt_analysis": {
                "malicious": vt_stats.get("malicious",0),
                "suspicious": vt_stats.get("suspicious",0),
                "undetected": vt_stats.get("undetected",0),
                "detection_ratio": detection_ratio,
                "top_engine_labels": vt_info.get("vt_classifications", [])
            },
            "dataset_sequence_matches": dataset_matches,
            "hardcoded_behavioral_matches": matched_patterns,
            "strings_summary": {
                "total_strings": len(strings),
                "network_indicators": {"ips": extracted_ips, "urls": extracted_urls},
                "suspicious_strings": categorized.get("suspicious_api_calls", [])[:50],
                "api_calls_observed": extracted_api_calls,
                "categorized_apis": categorized_apis_summary,
                "floss_metadata": floss_data
            },
            "capa_analysis": capa_result if capa_result else None,
            "categorization": categorized,
            "dynamic_analysis": dynamic_result if dynamic_result else None,
            "metadata": {
                "extraction_method": method,
                "timestamp": self.timestamp
            }
        }

        # If vt-only: quick report and exit
        if getattr(self.args, "vt_only", False):
            self.display_quick_report(full_payload, vt_info, dataset_matches, matched_patterns)
            out_json = f"{self.args.outdir}/vt_only_{Path(self.args.file).stem}_{self.timestamp}.json"
            with open(out_json, 'w') as f:
                json.dump({"sha256": sha256, "vt": vt_info, "dataset_matches": dataset_matches,
                          "matched_patterns": matched_patterns, "stage_reports": self.stage_reports}, f, indent=2)
            console.print(Panel(f"[green]VT-only run saved: {out_json}[/green]"))
            return

        # Stage 4: Final analysis
        final_analysis = self.stage_4_final_analysis(full_payload)

        # Save reports
        json_path, md_path = self.write_reports(full_payload, final_analysis)

        # Display summary
        console.print(Panel(
            f"[green]Analysis complete![/green]\n\n"
            f"JSON: [cyan]{json_path}[/cyan]\n"
            f"Markdown: [cyan]{md_path}[/cyan]\n"
            f"Verdict: [bold]{final_analysis.get('verdict','unknown')}[/bold] "
            f"(Confidence: {final_analysis.get('confidence',0):.2f}, Score: {final_analysis.get('score',0)}/100)",
            title="📁 Reports",
            border_style="green"
        ))

# ==================== MAIN ====================

def main():
    parser = argparse.ArgumentParser(description="Agent-Zero: Comprehensive Static & Dynamic Malware Analysis Tool")
    parser.add_argument("--file", help="Path to binary file (required unless --web)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL})")
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL, help="Ollama API URL")
    parser.add_argument("--outdir", default=DEFAULT_OUTDIR, help="Output directory")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retry attempts")
    parser.add_argument("--web", action="store_true", help="Start Flask web server")
    parser.add_argument("--web-port", type=int, default=5000, help="Web server port (default: 5000)")
    parser.add_argument("--vt-only", action="store_true", help="Quick VT + pattern check only")
    parser.add_argument("--no-llm", dest="no_llm", action="store_true", help="Skip LLM, use heuristic analysis")
    parser.add_argument("--no-vt", dest="no_vt", action="store_true", help="Skip VirusTotal lookup")
    parser.add_argument("--no-dynamic", dest="no_dynamic", action="store_true", help="Skip dynamic analysis (Hybrid Analysis)")
    parser.add_argument("--no-capa", dest="no_capa", action="store_true", help="Skip CAPA static analysis")
    parser.add_argument("--capa-verbose", dest="capa_verbose", action="store_true", help="Use CAPA verbose mode (-vv)")
    parser.add_argument("--no-save-capa-text", dest="save_capa_text", action="store_false", default=True, help="Don't save CAPA text output to file (default: save enabled)")
    parser.add_argument("--no-floss", dest="no_floss", action="store_true", help="Skip FLOSS string de-obfuscation")
    parser.add_argument("--dataset-csv", dest="dataset_csv", help="Path to CSV of malware API sequences")
    parser.add_argument("--stage-reports", dest="stage_reports", action="store_true", help="Generate individual stage reports")
    args = parser.parse_args()

    # Validate arguments
    if args.web:
        # Web mode - will be handled by web server
        if not FLASK_AVAILABLE:
            console.print("[red]Flask not installed. Install with: pip install flask flask-cors[/red]")
            sys.exit(1)
        # Import and start web server
        try:
            import sys
            from pathlib import Path
            web_app_path = Path(__file__).parent / "web" / "app.py"
            if not web_app_path.exists():
                console.print(f"[red]Web app not found at {web_app_path}[/red]")
                sys.exit(1)

            # Import web app
            import importlib.util
            spec = importlib.util.spec_from_file_location("web_app", str(web_app_path))
            web_app = importlib.util.module_from_spec(spec)
            sys.modules['web_app'] = web_app
            spec.loader.exec_module(web_app)

            app = web_app.create_app()
            console.print(f"[green]Starting Agent-Zero web server on port {args.web_port}[/green]")
            console.print(f"[cyan]Open your browser to: http://localhost:{args.web_port}[/cyan]")
            app.run(host='0.0.0.0', port=args.web_port, debug=False)
            return
        except Exception as e:
            console.print(f"[red]Failed to start web server: {e}[/red]")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    if not args.file:
        parser.error("--file is required unless --web is specified")

    # Display banner
    display_banner()

    try:
        analyzer = EnhancedBinaryAnalyzer(args)
        analyzer.run_analysis()
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()


