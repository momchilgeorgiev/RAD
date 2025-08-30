# 🛡️ DevSec Dash v3.0

**Local Security Scanner** - Professional Python backend + Beautiful JavaScript frontend

## Features

🔍 **Triple Scan Modes:**
- ⚡ **Quick Scan** - Regex pattern matching (browser-only)
- 🔬 **Deep Scan** - AST analysis via Pyodide (browser-only)  
- 🛡️ **Professional Scan** - Real Bandit + Semgrep (requires backend)

📊 **Visual Dashboard:**
- Security score calculation
- Vulnerability distribution charts
- Detailed findings with remediation guidance
- Export to JSON, Markdown, and PDF

🔒 **Privacy-First:**
- Everything runs locally (localhost:8080)
- Code never leaves your machine
- No cloud dependencies

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the backend server:**
   ```bash
   python app.py
   ```

3. **Open your browser:**
   ```
   http://localhost:8080
   ```

4. **Choose your scan mode:**
   - Professional scan (if backend is running)
   - Browser-based scans as fallback

## Architecture

**Backend (Python):**
- Flask server with CORS enabled
- Real security tools: Bandit + Semgrep
- JSON API endpoints for scanning
- Automatic tool availability detection

**Frontend (JavaScript):**
- Single-page application
- Real-time server connectivity check
- Automatic fallback to browser-based scanning
- Persistent settings with localStorage

## Security Tools Integrated

- **Bandit** - Python AST security scanner (68 security checks)
- **Semgrep** - Multi-language security patterns (166+ Python rules)
- **Custom AST** - Browser-based Python analysis fallback
- **Regex Patterns** - Fast pattern matching for common issues

## Business Model

- Open source donation-based model
- Privacy-first approach attracts security-conscious developers
- Professional-grade analysis competing with enterprise tools
- Single developer can maintain and monetize

## Development

The tool automatically detects available security scanners and gracefully falls back to browser-based analysis when the backend is unavailable, ensuring it works in all environments.

Built for developers who need security scanning without compromising privacy.