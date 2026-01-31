# Domain Availability MCP Server

An MCP server that checks domain name availability using WHOIS, DNS, and RDAP lookups. Supports `.com`, `.ai`, and `.net` TLDs.

## Installation

```bash
cd /Users/ishanrai/Documents/DomainNameMCPServer
uv sync
```

## Add to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "domain-checker": {
      "command": "uv",
      "args": ["run", "--directory", "/Users/ishanrai/Documents/DomainNameMCPServer", "server.py"]
    }
  }
}
```

## Add via CLI

```bash
claude mcp add-json domain-checker '{"type":"stdio","command":"uv","args":["run","--directory","/Users/ishanrai/Documents/DomainNameMCPServer","server.py"]}'
```

## Available Tools

| Tool | Description |
|------|-------------|
| `check_domain_availability` | Check if a single domain is available (e.g., `example.com`) |
| `check_multiple_domains` | Check up to 10 domains at once (e.g., `["example.com", "example.ai"]`) |
