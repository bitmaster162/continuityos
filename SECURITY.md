# Security Policy

## Supported versions

ContinuityOS currently provides security fixes for the active `0.10.x` release line.
Older release lines are not actively maintained for security fixes.

| Version | Supported |
| --- | --- |
| `0.10.x` | Yes |
| `< 0.10` | No |

## Reporting a vulnerability

Please do not publish exploit details, credentials, private data, or a proof of concept in a public GitHub issue.

If this repository shows GitHub's private **Report a vulnerability** option, use that channel. If no private reporting channel is available, open a minimal public issue titled `Security contact request` that contains no sensitive technical details, exploit steps, secrets, or proof of concept. The maintainer can then arrange an appropriate private follow-up channel.

A useful private report should include:

- the affected ContinuityOS version or commit;
- the affected component or file;
- the security impact and realistic attack conditions;
- reproducible steps or a proof of concept, shared only through a private channel;
- any suggested mitigation or fix, if known.

## Scope

Security reports are relevant when they affect ContinuityOS itself, including:

- the Python package and command-line interfaces;
- memory, governance, authorization, and integrity boundaries;
- repository CI and release automation;
- packaging or artifact-integrity behavior.

Issues that exist only in third-party platforms or services should normally be reported to the relevant upstream provider unless ContinuityOS introduces the vulnerable behavior.

## Safe research expectations

Please avoid destructive testing, denial of service, social engineering, credential theft, accessing data you do not own, or actions that affect third parties. Use the minimum activity needed to demonstrate the issue safely.

Security fixes and disclosure timing are handled on a best-effort basis after the report has been validated.
