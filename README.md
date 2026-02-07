# 🛡️ Veritensor: AI Supply Chain Security

[![Hugging Face Spaces](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Spaces-blue)](https://huggingface.co/spaces/ArseniiBrazhnyk/veritensor-ai-model-security-scanner)
[![PyPI version](https://img.shields.io/pypi/v/veritensor?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/veritensor/)
[![Docker Image](https://img.shields.io/docker/v/arseniibrazhnyk/veritensor?label=docker&color=blue&logo=docker&logoColor=white)](https://hub.docker.com/r/arseniibrazhnyk/veritensor)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/ArseniiBrazhnyk/Veritensor/actions/workflows/scanner-ci.yaml/badge.svg)](https://github.com/ArseniiBrazhnyk/Veritensor/actions/workflows/scanner-ci.yaml)
[![Security](https://github.com/ArseniiBrazhnyk/Veritensor/actions/workflows/security.yaml/badge.svg)](https://github.com/ArseniiBrazhnyk/Veritensor/actions/workflows/security.yaml)

**Veritensor** is an end-to-end security platform for the entire AI Life Cycle. It replaces traditional black-box scanning with deep semantic analysis, data supply chain protection, and cryptographic trust verification.

Unlike standard security tools, Veritensor provides a unified defense layer for every asset in your AI stack:
1.  **Models:** Deep AST and Bytecode analysis of **Pickle, PyTorch, Keras, Safetensors, and GGUF** to block RCE, backdoors, and weight-tampering.
2.  **Datasets:** High-speed streaming protection for **Parquet, CSV, and JSONL** to detect Data Poisoning, Malicious URLs, and PII.
3.  **Notebooks:** Hardening of **Jupyter (.ipynb)** files by scanning code execution, markdown phishing, and identifying secrets leaked in cell outputs.
4.  **RAG Knowledge Base:** Zero-trust extraction for **PDF, DOCX, and PPTX** to neutralize prompt injections before they reach your Vector Database.
5.  **Supply Chain Trust:** Cryptographic signing of models and containers via **Sigstore**, ensuring that only verified assets reach your production environment.

---

## 🚀 Features

*   **Deep Static Analysis:** Decompiles Pickle bytecode and Keras Lambda layers to find obfuscated attacks (e.g., `STACK_GLOBAL` exploits). Now supports deep scanning of **Zip archives** (PyTorch) and **Python Wheels**.
*   **Identity Verification:** Automatically verifies model hashes against the official Hugging Face registry to detect Man-in-the-Middle attacks.
*   **Dataset Poisoning Guard:** Scans massive datasets (100GB+) using **Streaming Analysis**. Detects "Ignore previous instructions" patterns and malicious URLs in Parquet, CSV, TSV, and JSONL.
*   **Notebook Inspector:** Scans Jupyter `.ipynb` files for execution threats, malicious markdown (XSS/Phishing), and **leaked secrets in output cells**.
*   **RAG Document Security:** Protects your knowledge base by scanning **PDF, DOCX, and PPTX** for prompt injections and PII before vectorization.
*   **License Firewall:** Blocks models with restrictive licenses (e.g., Non-Commercial, AGPL). Veritensor performs a **hybrid check**: it inspects embedded file metadata first, and automatically falls back to the Hugging Face API if metadata is missing (requires `--repo`).
*   **Supply Chain Security:** Integrates with **Sigstore Cosign** to sign Docker containers. Includes **timestamps** to prevent replay attacks.
*   **CI/CD Native:** Supports direct scanning from **Amazon S3** and integrates with GitHub Actions, GitLab, and Pre-commit pipelines.

---

## 📦 Installation

### Via PyPI (Recommended for local use)
Veritensor is modular. Install only what you need to keep your environment lightweight:

| Option | Command | Use Case |
| :--- | :--- | :--- |
| **Core** | `pip install veritensor` | Base model scanning (Pickle, Keras, Safetensors) |
| **Data** | `pip install veritensor[data]` | Datasets (Parquet, TSV, Pandas support) |
| **RAG** | `pip install veritensor[rag]` | Documents (PDF, DOCX, PPTX) |
| **PII** | `pip install veritensor[pii]` | PII detection |
| **AWS** | `pip install veritensor[aws]` | Direct scanning from S3 buckets |
| **All** | `pip install veritensor[all]` | Full suite for enterprise security |

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

### 4. Scan AI Datasets
Veritensor uses streaming to handle huge files. It samples 10k rows by default for speed.
```bash
veritensor scan ./data/train.parquet --full-scan
```

### 5. Scan Jupyter Notebooks
Check code cells, markdown, and saved outputs for threats:
```bash
veritensor scan ./research/experiment.ipynb
```

### 6. Scan from Amazon S3
Scan remote assets without manual downloading:
```bash
veritensor scan s3://my-ml-bucket/models/llama-3.pkl
```
---

## 📊 Reporting & Compliance

Veritensor supports industry-standard formats for integration with security dashboards and audit tools.

### 1. GitHub Security (SARIF)
Generate a report compatible with GitHub Code Scanning:
```bash
veritensor scan ./models --sarif > veritensor-report.sarif
```
### 2. Software Bill of Materials (SBOM)
Generate a CycloneDX v1.5 SBOM to inventory your AI assets:
```bash
veritensor scan ./models --sbom > sbom.json
```
### 3. Raw JSON
For custom parsers and SOAR automation:
```bash
veritensor scan ./models --json
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
      - uses: actions/checkout@v4 # Recommended to use latest checkout
      
      - name: Veritensor AI Security Platform
        uses: ArseniiBrazhnyk/Veritensor@v1.4.1
        with:
          path: '.'         # Scans everything: Models, Notebooks, Datasets, and Lock-files
          force: 'false'
```
### Pre-commit Hook

Prevent committing malicious models to your repository. Add this to .pre-commit-config.yaml:
```yaml
repos:
  - repo: https://github.com/ArseniiBrazhnyk/Veritensor
    rev: v1.4.1
    hooks:
      - id: veritensor-scan
```

---

## 📂 Supported Formats

| Format | Extension | Analysis Method |
| :--- | :--- | :--- |
| **Models** | `.pt`, `.pth`, `.bin`, `.pkl`, `.joblib`, `.h5`, `.keras`, `.safetensors`, `.gguf`, `.whl`  | AST Analysis, Pickle VM Emulation, Metadata Validation |
| **Datasets** | `.parquet`, `.csv`, `.tsv`, `.jsonl`, `.ndjson`, `.ldjson` | Streaming Regex Scan (URLs, Injections, PII) |
| **Notebooks** | `.ipynb` | JSON Structure Analysis + Code AST + Markdown Phishing |
| **RAG Docs** | `.pdf`, `.docx`, `.pptx`, `.txt`, `.md` | Document Object Model (DOM) Text Extraction |

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

# 2. Dataset Scanning
# Sampling limit for quick scans (default: 10000)
dataset_sampling_limit: 10000

# 3. License Firewall Policy
# If true, blocks models that have no license metadata.
fail_on_missing_license: false

# List of license keywords to block (case-insensitive).
custom_restricted_licenses:
  - "cc-by-nc"       # Non-Commercial
  - "agpl"           # Viral licenses
  - "research-only"

# 4. Static Analysis Exceptions (Pickle)
# Allow specific Python modules that are usually blocked by the strict scanner.
allowed_modules:
  - "my_company.internal_layer"
  - "sklearn.tree"

# 5. Model Whitelist (License Bypass)
# List of Repo IDs that are trusted. Veritensor will SKIP license checks for these.
# Supports Regex!
allowed_models:
  - "meta-llama/Meta-Llama-3-70B-Instruct"  # Exact match
  - "regex:^google-bert/.*"                 # Allow all BERT models from Google
  - "internal/my-private-model"
```

To generate a default configuration file, run: veritensor init

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
