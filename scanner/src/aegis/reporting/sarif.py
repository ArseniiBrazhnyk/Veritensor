# Copyright 2025 Aegis Security
#
# This module generates SARIF v2.1.0 reports.
# It allows Aegis to integrate natively with GitHub Advanced Security
# and other CI/CD dashboards.

import json
from typing import List, Dict, Any
from pathlib import Path

# --- Constants ---
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Aegis Security Scanner"
TOOL_DRIVER_NAME = "aegis"

# --- Rule Definitions ---
# We map internal Aegis threats to stable Rule IDs.
AEGIS_RULES = [
    {
        "id": "AEGIS-001",
        "name": "RemoteCodeExecution",
        "shortDescription": {"text": "Critical RCE Risk Detected"},
        "fullDescription": {"text": "The model contains code that executes arbitrary system commands (e.g., os.system, subprocess)."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "rce", "critical"]}
    },
    {
        "id": "AEGIS-002",
        "name": "UnsafeDeserialization",
        "shortDescription": {"text": "Unsafe Pickle Import"},
        "fullDescription": {"text": "The model imports modules that are not in the allowlist. This poses a security risk during deserialization."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "pickle", "deserialization"]}
    },
    {
        "id": "AEGIS-003",
        "name": "KerasLambdaLayer",
        "shortDescription": {"text": "Malicious Keras Lambda Layer"},
        "fullDescription": {"text": "A Keras Lambda layer was detected. These layers can contain arbitrary Python bytecode."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "keras", "rce"]}
    },
    {
        "id": "AEGIS-004",
        "name": "IntegrityMismatch",
        "shortDescription": {"text": "Model Hash Mismatch"},
        "fullDescription": {"text": "The file hash does not match the official registry (Hugging Face). The file may be corrupted or tampered with."},
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "integrity", "supply-chain"]}
    }
]


def generate_sarif_report(scan_results: List[Dict[str, Any]], tool_version: str = "4.1.0") -> str:
    """
    Converts internal Aegis scan results into a SARIF JSON string.

    Args:
        scan_results: List of dicts from main.py (file, status, threats, hash).
        tool_version: Current version of Aegis.

    Returns:
        JSON string formatted as SARIF.
    """
    
    sarif_results = []

    for file_res in scan_results:
        # We only report issues, not clean files (PASS)
        if file_res["status"] == "PASS":
            continue

        file_path = file_res.get("file", "unknown")
        threats = file_res.get("threats", [])

        for threat_msg in threats:
            rule_id = _map_threat_to_rule_id(threat_msg)
            
            result = {
                "ruleId": rule_id,
                "level": "error",  # Default to error for now
                "message": {
                    "text": threat_msg
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            }
                        }
                    }
                ]
            }
            sarif_results.append(result)

    # Construct the full SARIF object
    report = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_DRIVER_NAME,
                        "fullName": TOOL_NAME,
                        "version": tool_version,
                        "rules": AEGIS_RULES
                    }
                },
                "results": sarif_results
            }
        ]
    }

    return json.dumps(report, indent=2)


def _map_threat_to_rule_id(threat_msg: str) -> str:
    """
    Heuristic to map a raw threat string to a SARIF Rule ID.
    """
    msg_lower = threat_msg.lower()

    if "lambda" in msg_lower and "keras" in msg_lower:
        return "AEGIS-003"  # Keras Lambda
    
    if "os." in msg_lower or "subprocess" in msg_lower or "eval" in msg_lower or "exec" in msg_lower:
        return "AEGIS-001"  # RCE
    
    if "unsafe_import" in msg_lower or "critical" in msg_lower:
        return "AEGIS-002"  # General Unsafe Import
        
    if "hash" in msg_lower or "mismatch" in msg_lower:
        return "AEGIS-004"  # Integrity

    # Fallback for unknown threats
    return "AEGIS-002"
