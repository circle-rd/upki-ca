# Contributing to uPKI CA Server

Thank you for your interest in contributing to uPKI CA Server. This document provides guidelines and best practices for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We are committed to providing a welcoming and safe experience for everyone.

- Be respectful and inclusive in your communications
- Accept constructive criticism positively
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** — Click the "Fork" button on GitHub to create your own copy
2. **Clone your fork** — `git clone https://github.com/YOUR_USERNAME/upki.git`
3. **Add upstream remote** — `git remote add upstream https://github.com/circle-rd/upki.git`
4. **Create a branch** — `git checkout -b feature/your-feature-name`

## Development Environment

### Prerequisites

- Python 3.11 or higher
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/circle-rd/upki.git
cd upki

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Run tests to verify setup
pytest
```

### Pre-commit Hooks

We use pre-commit hooks to maintain code quality. Install them with:

```bash
pip install pre-commit
pre-commit install
```

## Coding Standards

### General Rules

- **Language**: All code, comments, and documentation must be in English
- **Naming**: Variables, functions, classes, and methods must use English names
- **Files**: Use `snake_case` for file names (e.g., `file_storage.py`, `validators.py`)
- **Type Hints**: All function parameters and return types must be typed
- **Documentation**: All public functions and classes must have docstrings

### Python Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints for all function parameters and return values
- Line length: 120 characters (configured in `pyproject.toml`)
- Use 4 spaces for indentation (no tabs)

### Code Quality Tools

We use the following tools to maintain code quality:

- **Ruff** — Fast Python linter (configured in `pyproject.toml`)
- **Black** — Code formatter (use `ruff format` which uses Black under the hood)
- **pytest** — Testing framework
- **pytest-cov** — Coverage reporting

Run linting:

```bash
ruff check upki_ca/ tests/
```

Run formatting:

```bash
ruff format upki_ca/ tests/
```

Run type checking (optional, for better IDE support):

```bash
mypy upki_ca/
```

### Naming Conventions

- **Files**: `snake_case.py` (e.g., `file_storage.py`, `validators.py`)
- **Functions/Methods**: `snake_case` (e.g., `generate_certificate`, `get_node`)
- **Classes**: `PascalCase` (e.g., `CertificateAuthority`, `FileStorage`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_VALIDITY_DAYS`, `MAX_CN_LENGTH`)
- **Private methods/attributes**: Prefix with underscore (e.g., `_internal_method`, `_cache`)
- **Instance variables**: `snake_case` (e.g., `self.base_path`, `self._nodes_db`)

### Docstrings

Use Google-style docstrings for all public functions, classes, and methods:

```python
def generate_certificate(csr: str, profile: str) -> Certificate:
    """Generate a certificate from a CSR.

    This function takes a Certificate Signing Request and signs it
    using the configured certificate authority.

    Args:
        csr: The Certificate Signing Request in PEM format.
        profile: The certificate profile to use.

    Returns:
        The generated certificate object.

    Raises:
        ValidationError: If the CSR is invalid.
        StorageError: If there is an error storing the certificate.
    """
```

For classes:

```python
class CertificateAuthority:
    """A Certificate Authority for issuing X.509 certificates.

    This class handles all certificate lifecycle operations including
    issuance, validation, and revocation.

    Attributes:
        name: The CA name.
        validity_days: Default validity period in days.
    """

    def __init__(self, name: str, validity_days: int = 365) -> None:
        """Initialize the Certificate Authority.

        Args:
            name: The CA name.
            validity_days: Default validity period in days.
        """
        self.name = name
        self.validity_days = validity_days
```

## Testing

### Test Types

- **Unit Tests**: Test individual functions and methods in isolation
  - Located in `tests/test_10_*.py` and `tests/test_20_*.py`
  - Fast to run, no external dependencies
- **Functional Tests**: Test complete workflows and integration
  - Located in `tests/test_100_*.py`
  - May take longer, test end-to-end scenarios

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=upki_ca --cov-report=html

# Run specific test file
pytest tests/test_100_pki_functional.py

# Run tests matching a pattern
pytest -k "test_certificate"

# Run only unit tests
pytest tests/test_10_*.py tests/test_20_*.py

# Run only functional tests
pytest tests/test_100_*.py
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files as `test_<module>.py`
- Use descriptive test names: `test_should_generate_valid_certificate`
- Include docstrings for test functions
- Test both positive and negative cases
- Ensure test coverage for new features
- Follow AAA pattern: Arrange, Act, Assert

Example:

```python
def test_should_sign_certificate_with_valid_csr():
    """Test that a valid CSR is signed successfully."""
    # Arrange
    ca = CertificateAuthority()
    csr = generate_test_csr()

    # Act
    cert = ca.sign(csr)

    # Assert
    assert cert is not None
    assert cert.is_valid()
```

## Submitting Changes

### Pull Request Process

1. **Update your branch** — Ensure your branch is up-to-date with `upstream/main`
2. **Run tests** — All tests must pass
3. **Run linting** — Fix any linting errors
4. **Write a clear PR description** — Explain what you changed and why
5. **Reference issues** — Link related issues (e.g., "Fixes #123")

### PR Title Convention

Use conventional commits format:

- `feat: Add new certificate profile support`
- `fix: Resolve ZMQ connection timeout`
- `docs: Update API documentation`
- `test: Add tests for CRL generation`

### Review Process

- At least one maintainer approval required
- All CI checks must pass
- Address any review comments

## Reporting Issues

### Bug Reports

Use GitHub Issues to report bugs. Include:

1. **Description** — Clear description of the bug
2. **Steps to Reproduce** — Detailed steps to reproduce
3. **Expected Behavior** — What you expected to happen
4. **Actual Behavior** — What actually happened
5. **Environment** — Python version, OS, etc.
6. **Logs** — Relevant log output

### Feature Requests

For new features:

1. **Use Case** — Describe the use case
2. **Proposed Solution** — Your proposed implementation
3. **Alternatives** — Any alternatives you considered

## Security Considerations

When contributing to a PKI project:

- Never commit secrets or private keys
- Use secure random number generation
- Validate all inputs thoroughly
- Follow cryptographic best practices
- Report security vulnerabilities privately

## License

By contributing to uPKI CA Server, you agree that your contributions will be licensed under the [MIT License](LICENSE).
