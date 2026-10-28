# Windows 11 Setup Guide — Week 1–2 Environment PoC

Every team member must complete this checklist before any scanner work begins.
The gate is: `sentinel ping` returns `"status": "ok"` on your machine.

## Prerequisites

### 1. Python 3.11+

Download from https://www.python.org/downloads/ — select "Add python.exe to PATH".
Verify:
```
python --version
```
Must report 3.11.x or higher.

### 2. Visual Studio Build Tools (required for tree-sitter)

`tree-sitter` is a C extension. Without MSVC, `pip install tree-sitter` will fail.

1. Download "Build Tools for Visual Studio 2022" from:
   https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
2. In the installer, select: **Desktop development with C++**
3. Restart your terminal after installation.

Verify:
```
cl
```
Should print MSVC version info (not "command not found").

> **Alternative:** If MSVC installation fails, try `mingw64` via `winget install msys2`.
> If tree-sitter still fails to build, use the fallback regex extractor (see `context/extractor.py`).

### 3. Node.js (for MCP Inspector)

Download LTS from https://nodejs.org/en/download
Verify:
```
node --version
npx --version
```

### 4. Ollama

Download from https://ollama.com/download — Windows installer available.
After installation:
```
ollama serve
```
In a new terminal:
```
ollama pull qwen2.5-coder:3b
ollama list
```
You should see `qwen2.5-coder:3b` in the list.

### 5. Trivy

Download the Windows binary from https://github.com/aquasecurity/trivy/releases
Add to PATH. Verify:
```
trivy --version
```

---

## Install Sentinel

```powershell
cd "C:\Development Work\Sentinel MCP"
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

If tree-sitter fails to build:
```
pip install tree-sitter --no-build-isolation
```
If it still fails, document the error and continue — the context graph has a regex fallback.

---

## Week 1–2 Gate: Verify the MCP Server

### Option A — Direct Python (quick check)
```powershell
.venv\Scripts\activate
sentinel ping
```
Expected output:
```json
{
  "status": "ok",
  "sentinel_version": "0.1.0",
  ...
}
```

### Option B — Via MCP Inspector (proves MCP protocol works)

Add to your Claude Desktop `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "sentinel": {
      "command": "C:\\Development Work\\Sentinel MCP\\.venv\\Scripts\\python.exe",
      "args": ["-m", "sentinel.server"]
    }
  }
}
```
Restart Claude Desktop. Type `sentinel ping` in Claude. Must return status ok.

Alternatively, use the MCP Inspector:
```
npx @modelcontextprotocol/inspector python -m sentinel.server
```

### Run Tests
```powershell
pytest tests/ -v
```
All `test_ping_*` and `test_schemas_*` tests must pass.

---

## Checklist (sign off before Week 3)

- [ ] Python 3.11+ installed
- [ ] MSVC Build Tools installed (or documented failure)
- [ ] `pip install -e ".[dev]"` completed without errors
- [ ] `sentinel ping` returns `"status": "ok"`
- [ ] `pytest tests/ -v` passes all tests
- [ ] Ollama running with `qwen2.5-coder:3b` available
- [ ] Trivy binary on PATH
- [ ] MCP server responds in Claude Desktop or MCP Inspector
