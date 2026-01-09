# 🛡️ Veritensor: AI Supply Chain Security

[![PyPI version](https://img.shields.io/pypi/v/veritensor?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/veritensor/)
[![Docker Image](https://img.shields.io/docker/v/arseniibrazhnyk/veritensor?label=docker&color=blue&logo=docker&logoColor=white)](https://hub.docker.com/r/arseniibrazhnyk/veritensor)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/ArseniiBrazhnyk/Veritensor/actions/workflows/scanner-ci.yaml/badge.svg)](https://github.com/ArseniiBrazhnyk/Veritensor/actions/workflows/scanner-ci.yaml)
[![Security](https://github.com/ArseniiBrazhnyk/Veritensor/actions/workflows/security.yaml/badge.svg)](https://github.com/ArseniiBrazhnyk/Veritensor/actions/workflows/security.yaml)


**Veritensor** is the Zero-Trust security platform for the AI Supply Chain. We replace naive scanning with deep AST analysis and cryptographic verification.

Unlike standard antiviruses, Veritensor understands AI formats (**Pickle, PyTorch, Keras, GGUF**) and ensures that your models:
1.  **Are Safe:** Do not contain malicious code (RCE, Reverse Shells, Lambda injections).
2.  **Are Authentic:** Have not been tampered with (Hash-to-API verification against Hugging Face).
3.  **Are Compliant:** Do not violate commercial license terms (e.g., CC-BY-NC, AGPL).
4.  **Are Trusted:** Can be cryptographically signed before deployment.

---

## 🚀 Features

*   **Deep Static Analysis:** Decompiles Pickle bytecode and Keras Lambda layers to find obfuscated attacks (e.g., `STACK_GLOBAL` exploits).
*   **Identity Verification:** Automatically verifies model hashes against the official Hugging Face registry to detect Man-in-the-Middle attacks.
*   **License Firewall:** Blocks models with restrictive licenses (Non-Commercial, Research-Only) from entering your production pipeline.
*   **Supply Chain Security:** Integrates with **Sigstore Cosign** to sign Docker containers. Includes **timestamps** to prevent replay attacks.
*   **CI/CD Native:** Ready for GitHub Actions, GitLab, and Pre-commit pipelines.

---

## 📦 Installation

### Via PyPI (Recommended for local use)
Lightweight installation (no heavy ML libraries required).
```bash
pip install veritensor
```
### Via Docker (Recommended for CI/CD)
```bash
docker pull arseniibrazhnyk/veritensor:latest
```

---

## ⚡ Quick Start

### 1. Scan a local model
Check a file or directory for malware:
```bash
veritensor scan ./models/bert-base.pt
```
**Example Output:**
```Text
╭────────────────────────────────╮
│ 🛡️  Veritensor Security Scanner │
╰────────────────────────────────╯
                                    Scan Results
┏━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ File         ┃ Status ┃ Threats / Details                    ┃ SHA256 (Short) ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ model.pt     │  FAIL  │ CRITICAL: os.system (RCE Detected)   │ a1b2c3d4...    │
└──────────────┴────────┴──────────────────────────────────────┴────────────────┘
❌ BLOCKING DEPLOYMENT
```
### 2. Verify against Hugging Face
Ensure the file on your disk matches the official version from the registry (detects tampering):
```bash
veritensor scan ./pytorch_model.bin --repo meta-llama/Llama-2-7b
```

### 3. License Compliance Check
Veritensor automatically reads metadata from safetensors and GGUF files.
If a model has a Non-Commercial license (e.g., cc-by-nc-4.0), it will raise a HIGH severity alert.
To override this (Break-glass mode), use:
```bash
veritensor scan ./model.safetensors --force
```
---

## 🔐 Supply Chain Security (Container Signing)

Veritensor integrates with Sigstore Cosign to cryptographically sign your Docker images only if they pass the security scan.

### 1. Generate Keys
Generate a key pair for signing:
```bash
veritensor keygen
# Output: veritensor.key (Private) and veritensor.pub (Public)
```
### 2. Scan & Sign
Pass the --image flag and the path to your private key (via env var).
```bash
# Set path to your private key
export VERITENSOR_PRIVATE_KEY_PATH=veritensor.key

# If scan passes -> Sign the image
veritensor scan ./models/my_model.pkl --image my-org/my-app:v1.0.0
```
### 3. Verify (In Kubernetes / Production)
Before deploying, verify the signature to ensure the model was scanned:
```bash
cosign verify --key veritensor.pub my-org/my-app:v1.0.0
```

---

## 🛠️ Integrations

### GitHub Actions
Add this to your .github/workflows/security.yml to block malicious models in Pull Requests:
```yaml
name: AI Security Scan
on: [pull_request]

jobs:
  veritensor-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Scan Models
        uses: ArseniiBrazhnyk/Veritensor@v1.1.2
        with:
          path: './models'
          repo: 'meta-llama/Llama-2-7b' # Optional: Verify integrity
          force: 'false' # Set to true to not fail build on threats
```
### Pre-commit Hook

Prevent committing malicious models to your repository. Add this to .pre-commit-config.yaml:
```yaml
repos:
  - repo: https://github.com/ArseniiBrazhnyk/Veritensor
    rev: v1.1.2
    hooks:
      - id: veritensor-scan
```

---

## 📂 Supported Formats

| Format | Extension | Analysis Method |
| :--- | :--- | :--- |
| **PyTorch** | `.pt`, `.pth`, `.bin` | Zip extraction + Pickle VM Bytecode Analysis |
| **Pickle** | `.pkl`, `.joblib` | Deep AST Analysis (Stack Emulation) |
| **Keras** | `.h5`, `.keras` | Lambda Layer Detection & Config Analysis |
| **Safetensors** | `.safetensors` | Header Parsing & Metadata Validation |
| **GGUF** | `.gguf` | Binary Parsing & Metadata Validation |

---

## ⚙️ Configuration

You can customize security policies by creating a `veritensor.yaml` file in your project root.
Pro Tip: You can use `regex:` prefix for flexible matching.

```yaml
# veritensor.yaml

# 1. Security Threshold
# Fail the build if threats of this severity (or higher) are found.
# Options: CRITICAL, HIGH, MEDIUM, LOW.
fail_on_severity: CRITICAL

# 2. License Firewall Policy
# If true, blocks models that have no license metadata.
fail_on_missing_license: false

# List of license keywords to block (case-insensitive).
custom_restricted_licenses:
  - "cc-by-nc"       # Non-Commercial
  - "agpl"           # Viral licenses
  - "research-only"

# 3. Static Analysis Exceptions (Pickle)
# Allow specific Python modules that are usually blocked by the strict scanner.
allowed_modules:
  - "my_company.internal_layer"
  - "sklearn.tree"

# 4. Model Whitelist (License Bypass)
# List of Repo IDs that are trusted. Veritensor will SKIP license checks for these.
# Supports Regex!
allowed_models:
  - "meta-llama/Meta-Llama-3-70B-Instruct"  # Exact match
  - "regex:^google-bert/.*"                 # Allow all BERT models from Google
  - "internal/my-private-model"
```

---

## 🧠 Threat Intelligence (Signatures)

Veritensor uses a decoupled signature database (`signatures.yaml`) to detect malicious patterns. This ensures that detection logic is separated from the core engine.

*   **Automatic Updates:** To get the latest threat definitions, simply upgrade the package:
    ```bash
    pip install --upgrade veritensor
    ```
*   **Transparent Rules:** You can inspect the default signatures in `src/veritensor/engines/static/signatures.yaml`.
*   **Custom Policies:** If the default rules are too strict for your use case (false positives), use `veritensor.yaml` to whitelist specific modules or models.

  ---

## 📜 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](https://github.com/ArseniiBrazhnyk/Veritensor?tab=Apache-2.0-1-ov-file#readme) file for details.
