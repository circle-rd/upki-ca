---
title: uPKI CA
navigation: false
layout: page
---

## ::hero

announcement:
title: 'ACME v2 support'
icon: '🔐'
to: /docs/guides/certificate-profiles
actions:

- name: Get Started
  to: /docs/getting-started/introduction
- name: GitHub
  variant: ghost
  to: https://github.com/circle-rd/upki-ca
  leftIcon: 'lucide:github'

---

#title
Your internal PKI,\nzero internet required.

#description
uPKI CA is a self-hosted Certificate Authority that gives you **complete control** over your internal TLS infrastructure. Issue, renew, and revoke X.509 certificates via ZMQ — no cloud, no third party, no dependency.
::

::card-grid
#title
Why uPKI CA?

#root
:ellipsis

#default
::card

---

icon: lucide:shield

---

#title
Air-gapped by design
#description
Runs fully offline. No internet access required — ideal for secure, regulated, or isolated environments.
::

::card

---

icon: lucide:zap

---

#title
ZMQ protocol
#description
Fast, binary-safe JSON-over-ZMQ protocol. One port for CA operations, one for RA registration.
::

::card

---

icon: lucide:layers

---

#title
7 built-in profiles
#description
Ready-made profiles for root CA, intermediate CA, server, client, OCSP, email, and code signing.
::

::card

---

icon: lucide:database

---

#title
Flexible storage
#description
File-based by default (TinyDB + filesystem). MongoDB adapter available for larger deployments.
::

::card

---

icon: lucide:refresh-cw

---

#title
Full lifecycle
#description
Generate, sign, renew, revoke, unrevoke, and delete certificates with a clean ZMQ API.
::

::card

---

icon: lucide:puzzle

---

#title
uPKI ecosystem
#description
Works seamlessly with uPKI RA (ACME v2) and uPKI CLI for a complete private PKI stack.
::
::
