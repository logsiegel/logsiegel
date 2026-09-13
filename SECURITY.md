# Security Policy

## Supported versions

Only the latest release on PyPI receives security fixes. At the moment that is
**0.1.2**. Logsiegel is pre-1.0: there are no backports to older versions.

## Reporting a vulnerability

Please report security issues privately to **logsiegel@stefan.boeck.name**.
Do not open a public GitHub issue and do not attach a proof of concept to a
public pull request — a bug in a tamper-evidence library is worth reporting
quietly first.

Useful in a report: affected version, what an attacker gains, and the smallest
reproduction you have.

You will get an acknowledgement within **72 hours**. After that we agree on a
fix and a disclosure date; credit in the release notes if you want it.

## Scope

Logsiegel is tamper-*evident*, not tamper-*proof*. The threat model in the
[README](README.md#threat-model-honestly) states what is proven, against whom,
and what is not — in particular that the operator holds the signing key and
that completeness of the log is an integration property, not a cryptographic
one. Reports that restate those documented limits are not vulnerabilities;
anything that breaks a property the threat model does claim is.
