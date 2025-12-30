# Copyright 2025 Aegis Security
#
# This module handles configuration loading.
# Priority:
# 1. Environment Variables (CI/CD overrides)
# 2. aegis.yaml (Local configuration)
# 3. Defaults (Hardcoded safety nets)

import os
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Set

# Try to import PyYAML, handle if missing (though it should be in pyproject.toml)
try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger(__name__)

# Default path for the configuration file
DEFAULT_CONFIG_PATH = Path("aegis.yaml")


@dataclass
class AegisConfig:
    """
    Runtime configuration for Aegis.
    """
    # --- Security Policies ---
    # Additional modules to trust in Pickle (extends SAFE_MODULES)
    # Example: ["my_company.internal_lib", "sklearn"]
    allowed_modules: List[str] = field(default_factory=list)
    
    # Specific rules to ignore (False Positives)
    # Example: ["CRITICAL: os.path.exists"] - be careful!
    ignored_rules: List[str] = field(default_factory=list)

    # Minimum severity to trigger a failure (exit code 1)
    # Options: "CRITICAL", "HIGH", "MEDIUM", "LOW"
    fail_on_severity: str = "CRITICAL"

    # --- Identity & Registry ---
    # Hugging Face Token for accessing private gated models
    hf_token: Optional[str] = None

    # --- Signing (Sigstore) ---
    # Path to the private key for signing (or content via ENV)
    private_key_path: Optional[str] = None
    
    # --- Output ---
    # Format: "table", "json", "sarif"
    output_format: str = "table"


class ConfigLoader:
    """
    Singleton-like loader that merges YAML and ENV variables.
    """
    _instance: Optional[AegisConfig] = None

    @classmethod
    def load(cls, config_path: Path = DEFAULT_CONFIG_PATH) -> AegisConfig:
        """
        Loads configuration with the following precedence:
        ENV > YAML > Defaults.
        """
        if cls._instance:
            return cls._instance

        # 1. Start with defaults
        config_data = {}

        # 2. Load YAML if exists
        if config_path.exists():
            if yaml is None:
                logger.warning("aegis.yaml found but PyYAML not installed. Skipping config file.")
            else:
                try:
                    with open(config_path, "r") as f:
                        file_data = yaml.safe_load(f)
                        if file_data:
                            config_data.update(file_data)
                    logger.info(f"Loaded configuration from {config_path}")
                except Exception as e:
                    logger.error(f"Failed to parse {config_path}: {e}")

        # 3. Override with Environment Variables (CI/CD friendly)
        # AEGIS_HF_TOKEN -> hf_token
        if "AEGIS_HF_TOKEN" in os.environ:
            config_data["hf_token"] = os.environ["AEGIS_HF_TOKEN"]
        elif "HF_TOKEN" in os.environ: # Fallback to standard HF env
            config_data["hf_token"] = os.environ["HF_TOKEN"]

        # AEGIS_PRIVATE_KEY_PATH -> private_key_path
        if "AEGIS_PRIVATE_KEY_PATH" in os.environ:
            config_data["private_key_path"] = os.environ["AEGIS_PRIVATE_KEY_PATH"]

        # AEGIS_FAIL_ON -> fail_on_severity
        if "AEGIS_FAIL_ON" in os.environ:
            config_data["fail_on_severity"] = os.environ["AEGIS_FAIL_ON"]

        # 4. Construct Object
        cls._instance = AegisConfig(
            allowed_modules=config_data.get("allowed_modules", []),
            ignored_rules=config_data.get("ignored_rules", []),
            fail_on_severity=config_data.get("fail_on_severity", "CRITICAL"),
            hf_token=config_data.get("hf_token"),
            private_key_path=config_data.get("private_key_path"),
            output_format=config_data.get("output_format", "table")
        )

        return cls._instance

    @classmethod
    def get_safe_modules(cls) -> Set[str]:
        """
        Returns the merged set of safe modules:
        Default Rules + User Config Allowed Modules.
        """
        # Import here to avoid circular dependency
        from aegis.engines.static.pickle_engine import SAFE_MODULES as DEFAULT_SAFE
        
        config = cls.load()
        user_allowed = set(config.allowed_modules)
        
        # Merge
        return DEFAULT_SAFE.union(user_allowed)

# Global accessor
settings = ConfigLoader()
