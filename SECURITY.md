# Security policy

meiosis exists to constrain and record what agents do, so a security flaw in it
matters more than most. Thank you for reporting one responsibly.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting
(*Security* tab → *Report a vulnerability*) on this repository. Include what you
did, what you expected, what happened, and the version (`mei version`).

You can expect an acknowledgement within a few working days. We will tell you
whether we consider it a vulnerability, work on a fix with you, and credit you in
the release notes unless you prefer not to be named.

## What counts

Anything that lets a party do what a valid token, the intent's scope or the
policy says it may not: writing outside scope, widening a delegation, forging or
replaying a token, making evidence count that should not, altering a stored
record undetected, bypassing push enforcement, or leaking a secret or key.

The model of who we defend against, and what we knowingly do not, is in
[`docs/threat-model.md`](docs/threat-model.md); a weakness listed there as known
is still welcome as a report if you can show it is worse than described.

## Supported versions

Before v1.0 only the latest release is supported, and the object format may
break between releases.
