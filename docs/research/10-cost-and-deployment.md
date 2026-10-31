# 10 — Cost and Deployment

## 1. Cost Model

Sentinel is a zero-cloud-cost system. All compute runs on the developer's machine.

| Component | Cost | Notes |
|---|---|---|
| Ollama (Qwen2.5-Coder 3B) | Free | Apache 2.0 model, runs locally |
| Bandit | Free | MIT licence, pip package |
| Trivy | Free | Apache 2.0, binary download |
| tree-sitter | Free | MIT licence, pip package |
| SQLite | Free | Public domain |
| Python 3.12 | Free | PSF licence |
| uv (package manager) | Free | MIT licence |

**There are no API keys, no subscriptions, no usage fees, and no data sent to external services.** This is a deliberate design constraint — see the threat model (07) and architecture decision (03).

The only recurring cost is electricity for GPU inference. A single `propose_fix` call on the 3B model uses ~2W for ~15–30 seconds — negligible.

---

## 2. Hardware Requirements

### Minimum

| Component | Minimum | Notes |
|---|---|---|
| OS | Windows 10 / Windows 11 | Linux/macOS supported by all dependencies but untested in this project |
| CPU | Any x64 | Required for Bandit, Trivy, tree-sitter |
| RAM | 8 GB | 16 GB recommended |
| GPU | None required | CPU-only Ollama inference is supported but slow (~5× slower) |
| Disk | 10 GB free | Model files: ~2 GB; Trivy DB: ~1 GB; Python env: ~1 GB |

### Recommended (tested configuration)

| Component | Specification |
|---|---|
| OS | Windows 11 Home |
| CPU | Intel Core i7 (12th gen or later) |
| RAM | 16 GB |
| GPU | NVIDIA RTX 4050 Laptop (6 GB VRAM) |
| Disk | 50 GB free SSD |

### GPU Notes

- Qwen2.5-Coder 3B Q4_K_M requires ~2 GB VRAM. Any NVIDIA GPU with ≥4 GB VRAM will run it with headroom.
- Ollama uses CUDA automatically when an NVIDIA GPU is detected. No manual configuration is required.
- For AMD GPUs: Ollama supports ROCm on Linux. Windows ROCm is experimental — CPU fallback recommended.
- Apple Silicon: Ollama uses Metal automatically. All components supported.

---

## 3. Installation

### Step 1: Python Environment

```bash
# Install uv (fast Python package manager)
pip install uv

# Create and activate virtual environment
cd "C:\Development Work\Sentinel MCP"
uv venv
.venv\Scripts\activate

# Install Sentinel and all dependencies
uv pip install -e .
```

### Step 2: Bandit

Bandit is installed as a dependency via `pyproject.toml`. Verify:

```bash
bandit --version
# Expected: bandit 1.7.x
```

### Step 3: Trivy

Trivy is a standalone binary. Download from https://github.com/aquasecurity/trivy/releases.

For Windows, download `trivy_X.Y.Z_windows-64bit.zip`, extract, and add to PATH.

```powershell
# Verify Trivy is on PATH
trivy --version
# Expected: Version: X.Y.Z

# Update vulnerability database (first run only)
trivy image --download-db-only
```

### Step 4: Ollama

Download from https://ollama.com/download. Run the installer.

```bash
# Start the Ollama server
ollama serve

# Pull the Sentinel model (in a separate terminal)
ollama pull qwen2.5-coder:3b

# Verify
ollama list
# Expected: qwen2.5-coder:3b listed
```

### Step 5: tree-sitter Language Files

tree-sitter language grammars are built from source or downloaded as pre-built wheels. The project pins tree-sitter-javascript and tree-sitter-python in `pyproject.toml`.

On Windows, tree-sitter requires Microsoft Visual C++ Build Tools. If not installed:

```
winget install Microsoft.VisualStudio.2022.BuildTools
```

Then re-run `uv pip install -e .`.

---

## 4. Claude Code MCP Registration

After installation, register Sentinel as an MCP server in Claude Code:

```bash
claude mcp add sentinel -s user -- .venv\Scripts\python.exe -m sentinel.server
```

- `-s user` — user-scope registration (persists across all Claude Code sessions).
- The command path (`.venv\Scripts\python.exe`) must be absolute or resolve from the project root.

Verify registration:

```bash
claude mcp list
# Expected: sentinel listed with status "running"
```

Or from inside Claude Code:

```
Use tool: sentinel.ping
```

Expected response: `{"status": "ok", "version": "0.1.0"}`.

---

## 5. First Use

```
User: Use sentinel.scan_repository with repo_path "C:\path\to\your\project"
```

Claude Code calls the MCP tool, Bandit and Trivy run as subprocesses, and findings are returned ranked by risk score.

```
User: Use sentinel.explain_finding with finding_id "<id from scan>"
```

This calls Ollama. If Ollama is not running, the tool returns:
```
LLMProviderError: Cannot connect to Ollama at localhost:11434. 
Run: ollama serve
```

---

## 6. Windows-Specific Notes

### Path Separators

Sentinel uses `pathlib.Path` throughout. Both forward slashes and backslashes are accepted in `repo_path`. Internally, paths are always resolved to absolute Windows paths.

### Long Paths

Windows has a 260-character MAX_PATH limit by default. Deeply nested repositories may hit this. Enable long paths:

```powershell
# Run as Administrator
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
    -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

### Trivy PATH

If Trivy is downloaded to a user directory, ensure it is on the system PATH or set the `TRIVY_PATH` environment variable:

```powershell
$env:PATH += ";C:\Users\<user>\tools\trivy"
```

### Ollama Service

On Windows, `ollama serve` runs in the foreground. To keep it running in the background, install as a Windows service or use Task Scheduler. Ollama's official installer does this automatically.

---

## 7. Configuration

Sentinel reads configuration from environment variables:

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API endpoint |
| `SENTINEL_OLLAMA_MODEL` | `qwen2.5-coder:3b` | Model name |
| `SENTINEL_AUDIT_DB` | `~/.sentinel/audit.db` | SQLite audit log path |
| `SENTINEL_CONTEXT_RADIUS` | `10` | Lines of context around findings |

No configuration file is required for the default setup.
