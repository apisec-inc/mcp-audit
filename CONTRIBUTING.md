# Contributing to MCP Audit

Thank you for your interest in contributing to MCP Audit! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/mcp-audit.git
   cd mcp-audit
   ```
3. Install dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
4. Run tests to verify setup:
   ```bash
   pytest
   ```

## Development Setup

### CLI Tool (Python)

```bash
# Install in development mode
pip install -e .

# Run the CLI
mcp-audit scan
```

### Web App (JavaScript)

```bash
# Start local server
python -m http.server 8080

# Open http://localhost:8080
```

## Making Changes

### Before You Start

- Check existing [issues](https://github.com/apisec-inc/mcp-audit/issues) for related work
- For new features, open an issue first to discuss the approach
- For bugs, include steps to reproduce

### Code Style

**Python (CLI):**
- Follow PEP 8
- Use type hints
- Run `black` for formatting
- Run `ruff` for linting

**JavaScript (Web App):**
- Use ES6+ features
- Keep functions focused and small
- Add comments for complex logic

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_audit

# Run specific test file
pytest tests/test_scanner.py
```

### Commit Messages

Use clear, descriptive commit messages:
- `Add secrets detection for AWS credentials`
- `Fix API endpoint parsing for SSE connections`
- `Update README with AI-BOM documentation`

## Pull Request Process

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Open a Pull Request with:
   - Clear description of changes
   - Link to related issue (if any)
   - Screenshots for UI changes

5. Address review feedback

## Areas for Contribution

### High Impact
- Add support for new MCP servers to the registry
- Improve secrets detection patterns
- Add new IDE configuration parsers

### Documentation
- Improve README examples
- Add tutorials for enterprise use cases
- Translate documentation

### Testing
- Add test cases for edge cases
- Improve test coverage
- Add integration tests

## Adding to the MCP Registry

To add a new MCP server to the known registry:

1. Edit `mcp_audit/data/known_mcps.json`
2. Add entry with:
   ```json
   {
     "package_name": "@org/mcp-server-name",
     "provider": "Provider Name",
     "type": "official|community|unknown",
     "risk_level": "low|medium|high|critical",
     "verified": true|false,
     "description": "What this MCP does"
   }
   ```
3. Update the registry hash (run `mcp-audit registry stats`)
4. Submit a PR with evidence of the MCP's legitimacy

## Security Issues

For security vulnerabilities, please email security@apisec.ai instead of opening a public issue.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## Questions?

- Open a [GitHub Discussion](https://github.com/apisec-inc/mcp-audit/discussions)
- Email: security@apisec.ai

---

Thank you for contributing to MCP Audit!
