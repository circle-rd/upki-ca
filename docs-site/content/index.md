---
title: uPKI CA
navigation: false
---

# Your internal PKI, zero internet required.

uPKI CA is a self-hosted Certificate Authority that gives you **complete control** over your internal TLS infrastructure. Issue, renew, and revoke X.509 certificates via ZMQ — no cloud, no third party, no dependency.

[Get Started](/docs/getting-started/introduction) · [GitHub](https://github.com/circle-rd/upki-ca)

## Why uPKI CA?

:::card-group
::card{title="Air-gapped by design" icon="i-lucide-shield"}
Runs fully offline. No internet access required — ideal for secure, regulated, or isolated environments.
::
::card{title="ZMQ protocol" icon="i-lucide-zap"}
Fast, binary-safe JSON-over-ZMQ protocol. One port for CA operations, one for RA registration.
::
::card{title="7 built-in profiles" icon="i-lucide-layers"}
Ready-made profiles for root CA, intermediate CA, server, client, OCSP, email, and code signing.
::
::card{title="Flexible storage" icon="i-lucide-database"}
File-based by default (TinyDB + filesystem). MongoDB adapter available for larger deployments.
::
::card{title="Full lifecycle" icon="i-lucide-refresh-cw"}
Generate, sign, renew, revoke, unrevoke, and delete certificates with a clean ZMQ API.
::
::card{title="uPKI ecosystem" icon="i-lucide-puzzle"}
Works seamlessly with uPKI RA (ACME v2) and uPKI CLI for a complete private PKI stack.
::
:::
