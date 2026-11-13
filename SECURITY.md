# Security Policy

## Supported Versions

Security fixes are currently intended for the latest published release:

| Version | Supported |
| --- | --- |
| v1.0.0 | Yes |
| Older versions | No |

If this support policy changes, this file will be updated.

## Reporting a Vulnerability

If you discover a potential security vulnerability in DeepShield, please report it privately to the repository maintainer before sharing details publicly.

You can use GitHub's **Report a vulnerability** option in the repository's Security tab, if private vulnerability reporting is enabled. If that option is unavailable, contact the maintainer through the contact information on their GitHub profile.

Please include, where possible:

- A clear description of the suspected vulnerability.
- The affected file, endpoint, component, or version.
- Steps to reproduce the issue and any proof-of-concept details needed to verify it safely.
- The potential security impact.
- Relevant logs or screenshots, with passwords, tokens, personal information, and other secrets removed.

You should receive an acknowledgement when the report has been reviewed. Investigation and any fix will depend on the severity, reproducibility, and maintainer availability.

## Responsible Disclosure

- Please do not publish exploit details or publicly disclose an unpatched vulnerability.
- Give the maintainer a reasonable opportunity to investigate and prepare a fix.
- Do not access, modify, or delete data that does not belong to you.
- Do not disrupt services or test against systems without explicit authorization.
- Share only the minimum information needed to demonstrate the issue.

## Security Scope and Project Limitations

DeepShield is an educational and research portfolio project. It is not a production-certified intrusion detection system or a substitute for a properly secured security monitoring platform.

When testing DeepShield:

- Use only networks, devices, and traffic that you own or are explicitly authorized to monitor.
- Do not commit credentials, API keys, tokens, private keys, personal data, packet captures containing sensitive information, or other secrets to the repository.
- Treat model predictions, anomaly flags, and alert severity labels as experimental signals that require human review.
- Do not assume that a BENIGN prediction means traffic is safe or that an ATTACK prediction confirms an incident.

## Security Updates

Security fixes and relevant advisories will be documented in GitHub releases or repository updates when appropriate.
