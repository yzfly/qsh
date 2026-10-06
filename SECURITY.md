# Security policy

qsh is a remote shell: a vulnerability in it can give someone a shell on your servers. We treat
reports accordingly.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/yzfly/qsh/security/advisories/new)
on `yzfly/qsh`. This creates a private security advisory that only you and the maintainers see.

Please include what you can of:

- the affected component (`qsh`, `qsh-server`, `qsh-core`, the qsh/1 protocol, `install.sh`,
  release artifacts or packaging) and version or commit;
- the impact: what an attacker gains, and from which position (network path, another local user
  on the server, a malicious server, a malicious client);
- steps or a proof of concept to reproduce it.

You do not need a complete analysis to report; a credible suspicion is enough.

## What happens next

| Step | Target time |
| ---- | ----------- |
| Acknowledgement of your report | 3 working days |
| Initial assessment (confirmed or not, severity) | 10 days |
| Fix released for a confirmed issue | 90 days at most; critical issues as fast as we can |

We keep you informed along the way, agree on a disclosure date with you, request a CVE through
GitHub's advisory process where appropriate, and credit you in the advisory and the changelog
unless you prefer otherwise. We ask that you do not disclose the issue publicly before the fix is
released or the agreed date has passed.

Distributions that package qsh can ask to be notified ahead of public disclosure: open a private
advisory with the contact address of your security team.

## Supported versions

Before 1.0, only the latest release receives security fixes; upgrade to it to get them. From 1.0
on, the latest minor release of the current major version is supported, and the policy for older
lines will be stated here.

| Version | Supported |
| ------- | --------- |
| latest release | yes |
| older releases | no |

## Scope and design

The security model — what qsh defends against, how trust is derived from ssh, how sessions are
authenticated and bound to connections — is documented in [docs/security.md](docs/security.md).
Reports that the implementation does not meet that document are in scope. So are weaknesses in
the document itself.

## Verifying releases

Release assets are listed with their SHA-256 in `SHA256SUMS`, which is signed with the qsh
release key (minisign format, `SHA256SUMS.minisig`; key id 247743DF6C75BDD8), and carry a
build provenance attestation signed by the GitHub Actions workflow that built them:

```sh
minisign -Vm SHA256SUMS -P RWTYvXVs30N3JIE/A5TMPWUWD9ktnPZqQ6lSzYJahI7u5lpiPBCKWHlf
gh attestation verify qsh-VERSION-TARGET.tar.gz --repo yzfly/qsh
```
