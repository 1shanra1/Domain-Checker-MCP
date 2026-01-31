# Domain Availability MCP Server

An MCP server that checks domain name availability using WHOIS, DNS, and RDAP lookups. Supports `.com`, `.ai`, and `.net` TLDs.

## Installation

```bash
git clone https://github.com/1shanra1/Domain-Checker-MCP.git
cd Domain-Checker-MCP
uv sync
```

## Add to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "domain-checker": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/Domain-Checker-MCP", "server.py"]
    }
  }
}
```

## Add via CLI

```bash
claude mcp add-json domain-checker '{"type":"stdio","command":"uv","args":["run","--directory","/absolute/path/to/Domain-Checker-MCP","server.py"]}'
```

## Available Tools

| Tool | Description |
|------|-------------|
| `check_domain_availability` | Check if a single domain is available |
| `check_multiple_domains` | Check up to 10 domains at once |
