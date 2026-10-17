# Security policy

Simulation-Rift is pre-release software. It has not been audited. Do not rely on it to protect sensitive data yet.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/Order52/Simulation-Rift/security/advisories/new) rather than in public issues. Include affected versions, reproduction steps, and the impact you observed. Do not attach live malware; describe the sample or share its hash.

## Scope

The security boundaries, invariants, and explicit non-goals are defined in [`docs/architecture.md`](docs/architecture.md) (§3 to §5). Reports are especially valuable if they show:

- untrusted content (a web page or file) gaining access beyond its documented boundary;
- a confined worker reaching the filesystem, network, or other processes;
- a scan failure being reported as clean;
- an update being accepted when it should have been rejected (bad signature, rollback, expiry, path escape);
- vault plaintext or keys leaking to persistent storage or to the browser process.

Out of scope: an already-compromised OS or kernel, root-level attackers, and same-user non-sandboxed processes on Linux reading an unlocked vault (documented residual risk).
