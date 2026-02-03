# Copyright 2025 Veritensor Security
#
# This module handles configuration loading.
# Priority:
# 1. Environment Variables (CI/CD overrides)
# 2. veritensor.yaml (Local configuration)
# 3. Defaults (Hardcoded safety nets)

import os
import logging
import yaml # Now a hard dependency
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Set

logger = logging.getLogger(__name__)
DEFAULT_CONFIG_PATH = Path("veritensor.yaml")

@dataclass
class VeritensorConfig:
    allowed_modules: List[str] = field(default_factory=list)
    ignored_rules: List[str] = field(default_factory=list)
    fail_on_severity: str = "CRITICAL"
    hf_token: Optional[str] = None
    private_key_path: Optional[str] = None
    output_format: str = "table"
    fail_on_missing_license: bool = False
    custom_restricted_licenses: List[str] = field(default_factory=list)
    allowed_models: List[str] = field(default_factory=list)
    # --- Telemetry Fields ---
    report_url: Optional[str] = None
    api_key: Optional[str] = None
    
class ConfigLoader:
    _instance: Optional[VeritensorConfig] = None

    @classmethod
    def load(cls, config_path: Path = DEFAULT_CONFIG_PATH) -> VeritensorConfig:
        if cls._instance:
            return cls._instance

        config_data = {}
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    file_data = yaml.safe_load(f)
                    if file_data:
                        config_data.update(file_data)
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.error(f"Failed to parse {config_path}: {e}")

        # ENV overrides
        if "VERITENSOR_HF_TOKEN" in os.environ:
            config_data["hf_token"] = os.environ["VERITENSOR_HF_TOKEN"]
        elif "HF_TOKEN" in os.environ:
            config_data["hf_token"] = os.environ["HF_TOKEN"]

        if "VERITENSOR_PRIVATE_KEY_PATH" in os.environ:
            config_data["private_key_path"] = os.environ["VERITENSOR_PRIVATE_KEY_PATH"]

        if "VERITENSOR_FAIL_ON" in os.environ:
            config_data["fail_on_severity"] = os.environ["VERITENSOR_FAIL_ON"]

        if "VERITENSOR_REPORT_URL" in os.environ:
            config_data["report_url"] = os.environ["VERITENSOR_REPORT_URL"]
        
        if "VERITENSOR_API_KEY" in os.environ:
            config_data["api_key"] = os.environ["VERITENSOR_API_KEY"]
            
        cls._instance = VeritensorConfig(
            allowed_modules=config_data.get("allowed_modules", []),
            ignored_rules=config_data.get("ignored_rules", []),
            fail_on_severity=config_data.get("fail_on_severity", "CRITICAL"),
            hf_token=config_data.get("hf_token"),
            private_key_path=config_data.get("private_key_path"),
            output_format=config_data.get("output_format", "table"),
            fail_on_missing_license=config_data.get("fail_on_missing_license", False),
            custom_restricted_licenses=config_data.get("restricted_licenses", []),
            allowed_models=config_data.get("allowed_models", []),
            report_url=config_data.get("report_url"),
            api_key=config_data.get("api_key")
        )
        return cls._instance

    @classmethod
    def get_safe_modules(cls) -> Set[str]:
        from veritensor.engines.static.pickle_engine import SAFE_MODULES as DEFAULT_SAFE
        config = cls.load()
        return DEFAULT_SAFE.union(set(config.allowed_modules))

settings = ConfigLoader()
