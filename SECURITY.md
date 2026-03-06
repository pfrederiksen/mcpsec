# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

We take security issues in mcpsec seriously. If you discover a security vulnerability, please report it responsibly.

### Responsible Disclosure

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send a detailed report to:

**security@mcpsec**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgement**: Within 48 hours of your report.
- **Assessment**: We will evaluate the severity and impact within 5 business days.
- **Resolution**: We aim to release a fix within 30 days for critical issues.

### Credit

We are happy to credit researchers who report valid vulnerabilities responsibly. Let us know how you would like to be acknowledged.

## Security Best Practices

When using mcpsec:

- Always run the latest version to benefit from the most recent security rules.
- Review scan results and remediate findings promptly.
- Protect Splunk HEC tokens and other credentials used with mcpsec.
- Use environment variables or secret management tools for sensitive configuration values.
