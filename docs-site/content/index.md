---
seo:
  title: uPKI CA — Self-hosted Certificate Authority
  description: Self-hosted Certificate Authority — private PKI with zero internet dependency.
---

:::u-page-hero
#title
Your internal PKI, zero internet required.

#description
uPKI CA is a self-hosted Certificate Authority that gives you **complete control** over your internal TLS infrastructure. Issue, renew, and revoke X.509 certificates via ZMQ — no cloud, no third party, no dependency.

#links
::::u-button{to="/docs/getting-started/introduction" size="xl" trailing-icon="i-lucide-arrow-right" color="neutral"}
Get Started
::::

::::u-button{to="https://github.com/circle-rd/upki-ca" target="\_blank" size="xl" variant="outline" color="neutral" icon="i-simple-icons-github"}
Star on GitHub
::::
:::

:::u-page-section
#title
Why uPKI CA?

#features
::::u-page-feature{icon="i-lucide-shield"}
#title
Air-gapped by design

#description
Runs fully offline. No internet access required — ideal for secure, regulated, or isolated environments.
::::

::::u-page-feature{icon="i-lucide-zap"}
#title
ZMQ protocol

#description
Fast, binary-safe JSON-over-ZMQ protocol. One port for CA operations, one for RA registration.
::::

::::u-page-feature{icon="i-lucide-layers"}
#title
7 built-in profiles

#description
Ready-made profiles for root CA, intermediate CA, server, client, OCSP, email, and code signing.
::::

::::u-page-feature{icon="i-lucide-database"}
#title
Flexible storage

#description
File-based by default (TinyDB + filesystem). MongoDB adapter available for larger deployments.
::::

::::u-page-feature{icon="i-lucide-refresh-cw"}
#title
Full lifecycle

#description
Generate, sign, renew, revoke, unrevoke, and delete certificates with a clean ZMQ API.
::::

::::u-page-feature{icon="i-lucide-puzzle"}
#title
uPKI ecosystem

#description
Works seamlessly with uPKI RA (ACME v2) and uPKI CLI for a complete private PKI stack.
::::
:::
