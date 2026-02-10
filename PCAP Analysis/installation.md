# Installation

## Prerequisites

- Python 3.12 or higher
- uv package manager

## Setup

1. Navigate to the project directory:
   ```bash
   cd pcap_analyzer
   ```

2. Create virtual environment and install dependencies:
   ```bash
   uv venv
   uv pip install -e .
   ```

## Configuration

### Claude Desktop

Add the following to your Claude Desktop configuration file:

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "uv",
      "args": [
        "--directory",
        "C:\\Users\\<username>\\path\\to\\pcap_analyzer",
        "run",
        "pcap_analyzer.py"
      ]
    }
  }
}
```
