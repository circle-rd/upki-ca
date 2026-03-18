# uPKI CA-ZMQ Protocol Documentation

This document describes the complete ZMQ protocol between the uPKI Certificate Authority (CA) and Registration Authority (RA). The protocol is designed for implementing the RA side of the communication.

## Table of Contents

1. [Overview](#overview)
2. [Transport Layer](#transport-layer)
3. [Message Format](#message-format)
4. [Port 5000 - CA Operations](#port-5000---ca-operations)
5. [Port 5001 - RA Registration](#port-5001---ra-registration)
6. [Error Handling](#error-handling)
7. [Python Implementation Example](#python-implementation-example)

---

## Overview

The uPKI system uses two separate ZMQ endpoints:

| Endpoint        | Port | Purpose                                                |
| --------------- | ---- | ------------------------------------------------------ |
| CA Operations   | 5000 | All certificate operations (sign, revoke, renew, etc.) |
| RA Registration | 5001 | Initial RA node registration (clear mode)              |

---

## Transport Layer

- **Protocol**: ZMQ REQ/REP with `zmq.REP` socket
- **Address Format**: `tcp://host:port`
- **Default Host**: `127.0.0.1` (localhost)
- **Timeout**: 5000ms (5 seconds)
- **Serialization**: JSON strings

---

## Message Format

### Request Structure

```json
{
  "TASK": "<task_name>",
  "params": {
    "<param1>": "<value1>",
    "<param2>": "<value2>"
  }
}
```

### Response Structure (Success)

```json
{
  "EVENT": "ANSWER",
  "DATA": <result>
}
```

### Response Structure (Error)

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "<error_message>"
}
```

---

## Port 5000 - CA Operations

The following tasks are available via the main ZMQ listener on port 5000:

### Task Reference Table

| Task                                                      | Required Params | Optional Params                                     | Response                    |
| --------------------------------------------------------- | --------------- | --------------------------------------------------- | --------------------------- |
| [`get_ca`](upki_ca/connectors/zmq_listener.py:181)        | none            | none                                                | PEM cert string             |
| [`get_crl`](upki_ca/connectors/zmq_listener.py:188)       | none            | none                                                | Base64 CRL                  |
| [`generate_crl`](upki_ca/connectors/zmq_listener.py:201)  | none            | none                                                | Base64 CRL                  |
| [`register`](upki_ca/connectors/zmq_listener.py:214)      | `seed`, `cn`    | `profile` (default: "server"), `sans` (default: []) | `{dn, certificate, serial}` |
| [`generate`](upki_ca/connectors/zmq_listener.py:243)      | `cn`            | `profile`, `sans`, `local`                          | `{dn, certificate, serial}` |
| [`sign`](upki_ca/connectors/zmq_listener.py:278)          | `csr`           | `profile` (default: "server")                       | `{certificate, serial}`     |
| [`renew`](upki_ca/connectors/zmq_listener.py:296)         | `dn`            | `duration`                                          | `{certificate, serial}`     |
| [`revoke`](upki_ca/connectors/zmq_listener.py:314)        | `dn`            | `reason` (default: "unspecified")                   | boolean                     |
| [`unrevoke`](upki_ca/connectors/zmq_listener.py:327)      | `dn`            | none                                                | boolean                     |
| [`delete`](upki_ca/connectors/zmq_listener.py:341)        | `dn`            | none                                                | boolean                     |
| [`view`](upki_ca/connectors/zmq_listener.py:355)          | `dn`            | none                                                | certificate details dict    |
| [`ocsp_check`](upki_ca/connectors/zmq_listener.py:369)    | `cert`          | none                                                | OCSP status dict            |
| [`list_profiles`](upki_ca/connectors/zmq_listener.py:163) | none            | none                                                | list of profile names       |
| [`get_profile`](upki_ca/connectors/zmq_listener.py:169)   | `profile`       | none                                                | profile details dict        |
| [`list_admins`](upki_ca/connectors/zmq_listener.py:129)   | none            | none                                                | list of admin DNs           |
| [`add_admin`](upki_ca/connectors/zmq_listener.py:133)     | `dn`            | none                                                | boolean                     |
| [`remove_admin`](upki_ca/connectors/zmq_listener.py:147)  | `dn`            | none                                                | boolean                     |

---

### Detailed Request/Response Formats

#### 1. `get_ca` - Get CA Certificate

**Request:**

```json
{
  "TASK": "get_ca",
  "params": {}
}
```

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

---

#### 2. `get_crl` - Get CRL

**Request:**

```json
{
  "TASK": "get_crl",
  "params": {}
}
```

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": "<base64_encoded_crl>"
}
```

---

#### 3. `generate_crl` - Generate New CRL

**Request:**

```json
{
  "TASK": "generate_crl",
  "params": {}
}
```

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": "<base64_encoded_new_crl>"
}
```

---

#### 4. `register` - Register New Node Certificate

**Request:**

```json
{
  "TASK": "register",
  "params": {
    "seed": "seed_string",
    "cn": "node.example.com",
    "profile": "server",
    "sans": []
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                             |
| --------- | ------ | -------- | --------------------------------------- |
| `seed`    | string | Yes      | Registration seed                       |
| `cn`      | string | Yes      | Common Name                             |
| `profile` | string | No       | Certificate profile (default: "server") |
| `sans`    | array  | No       | Subject Alternative Names (default: []) |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "dn": "/CN=node.example.com",
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "serial": "1234567890"
  }
}
```

---

#### 5. `generate` - Generate Certificate

**Request:**

```json
{
  "TASK": "generate",
  "params": {
    "cn": "server.example.com",
    "profile": "server",
    "sans": [],
    "local": true
  }
}
```

**Parameters:**

| Parameter | Type    | Required | Description                             |
| --------- | ------- | -------- | --------------------------------------- |
| `cn`      | string  | Yes      | Common Name                             |
| `profile` | string  | No       | Certificate profile (default: "server") |
| `sans`    | array   | No       | Subject Alternative Names (default: []) |
| `local`   | boolean | No       | Generate key locally (default: true)    |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "dn": "/CN=server.example.com",
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "serial": "1234567890"
  }
}
```

---

#### 6. `sign` - Sign CSR

**Request:**

```json
{
  "TASK": "sign",
  "params": {
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
    "profile": "server"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                             |
| --------- | ------ | -------- | --------------------------------------- |
| `csr`     | string | Yes      | CSR in PEM format                       |
| `profile` | string | No       | Certificate profile (default: "server") |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "serial": "1234567890"
  }
}
```

---

#### 7. `renew` - Renew Certificate

**Request:**

```json
{
  "TASK": "renew",
  "params": {
    "dn": "/CN=server.example.com",
    "duration": 365
  }
}
```

**Parameters:**

| Parameter  | Type    | Required | Description               |
| ---------- | ------- | -------- | ------------------------- |
| `dn`       | string  | Yes      | Distinguished Name        |
| `duration` | integer | No       | Validity duration in days |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "serial": "9876543210"
  }
}
```

---

#### 8. `revoke` - Revoke Certificate

**Request:**

```json
{
  "TASK": "revoke",
  "params": {
    "dn": "/CN=server.example.com",
    "reason": "unspecified"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                                |
| --------- | ------ | -------- | ------------------------------------------ |
| `dn`      | string | Yes      | Distinguished Name of the certificate      |
| `reason`  | string | No       | Revocation reason (default: "unspecified") |

**Valid Reasons:**

- `unspecified` (default)
- `keyCompromise`
- `cACompromise`
- `affiliationChanged`
- `superseded`
- `cessationOfOperation`
- `certificateHold`

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": true
}
```

---

#### 9. `unrevoke` - Unrevoke Certificate

**Request:**

```json
{
  "TASK": "unrevoke",
  "params": {
    "dn": "/CN=server.example.com"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                           |
| --------- | ------ | -------- | ------------------------------------- |
| `dn`      | string | Yes      | Distinguished Name of the certificate |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": true
}
```

---

#### 10. `delete` - Delete Certificate

**Request:**

```json
{
  "TASK": "delete",
  "params": {
    "dn": "/CN=server.example.com"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                           |
| --------- | ------ | -------- | ------------------------------------- |
| `dn`      | string | Yes      | Distinguished Name of the certificate |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": true
}
```

**Note:** Deletion revokes the certificate with reason `cessationOfOperation`.

---

#### 11. `view` - View Certificate Details

**Request:**

```json
{
  "TASK": "view",
  "params": {
    "dn": "/CN=server.example.com"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                           |
| --------- | ------ | -------- | ------------------------------------- |
| `dn`      | string | Yes      | Distinguished Name of the certificate |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "serial_number": "1234567890",
    "subject": "/CN=server.example.com",
    "issuer": "/CN=uPKI Root CA",
    "not_valid_before": "2024-01-01T00:00:00Z",
    "not_valid_after": "2025-01-01T00:00:00Z",
    "signature_algorithm": "sha256WithRSAEncryption",
    "public_key": "RSA 2048 bits",
    "extensions": [...]
  }
}
```

---

#### 12. `ocsp_check` - Check OCSP Status

**Request:**

```json
{
  "TASK": "ocsp_check",
  "params": {
    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description               |
| --------- | ------ | -------- | ------------------------- |
| `cert`    | string | Yes      | Certificate in PEM format |

**Response (Success - Good):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "status": "good",
    "serial": "1234567890",
    "cn": "server.example.com"
  }
}
```

**Response (Success - Revoked):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "status": "revoked",
    "serial": "1234567890",
    "cn": "server.example.com",
    "revoke_reason": "keyCompromise",
    "revoke_date": "2024-06-15T10:30:00Z"
  }
}
```

**Response (Success - Expired):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "status": "expired",
    "serial": "1234567890",
    "cn": "server.example.com"
  }
}
```

---

#### 13. `list_profiles` - List Certificate Profiles

**Request:**

```json
{
  "TASK": "list_profiles",
  "params": {}
}
```

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": ["server", "client", "ra", "ca"]
}
```

---

#### 14. `get_profile` - Get Profile Details

**Request:**

```json
{
  "TASK": "get_profile",
  "params": {
    "profile": "server"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description  |
| --------- | ------ | -------- | ------------ |
| `profile` | string | Yes      | Profile name |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "keyType": "rsa",
    "keyLen": 2048,
    "duration": 365,
    "digest": "sha256",
    "subject": {...},
    "keyUsage": ["digitalSignature", "keyEncipherment"],
    "extendedKeyUsage": ["serverAuth"],
    "certType": "sslServer"
  }
}
```

---

#### 15. `list_admins` - List Administrators

**Request:**

```json
{
  "TASK": "list_admins",
  "params": {}
}
```

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": ["/CN=Admin1/O=uPKI", "/CN=Admin2/O=uPKI"]
}
```

---

#### 16. `add_admin` - Add Administrator

**Request:**

```json
{
  "TASK": "add_admin",
  "params": {
    "dn": "/CN=NewAdmin/O=uPKI"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                      |
| --------- | ------ | -------- | -------------------------------- |
| `dn`      | string | Yes      | Administrator Distinguished Name |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": true
}
```

---

#### 17. `remove_admin` - Remove Administrator

**Request:**

```json
{
  "TASK": "remove_admin",
  "params": {
    "dn": "/CN=AdminToRemove/O=uPKI"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                      |
| --------- | ------ | -------- | -------------------------------- |
| `dn`      | string | Yes      | Administrator Distinguished Name |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": true
}
```

---

## Port 5001 - RA Registration

The following tasks are available via the registration ZMQ listener on port 5001:

### Task Reference Table

| Task                                                | Required Params | Optional Params           | Response                |
| --------------------------------------------------- | --------------- | ------------------------- | ----------------------- |
| [`register`](upki_ca/connectors/zmq_register.py:63) | `seed`, `cn`    | `profile` (default: "ra") | `{status, cn, profile}` |
| [`status`](upki_ca/connectors/zmq_register.py:95)   | none            | `cn`                      | `{status, node?}`       |

---

### Detailed Request/Response Formats

#### 1. `register` - Register RA Node

**Request:**

```json
{
  "TASK": "register",
  "params": {
    "seed": "registration_seed_string",
    "cn": "RA_Node_Name",
    "profile": "ra"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                                                        |
| --------- | ------ | -------- | ------------------------------------------------------------------ |
| `seed`    | string | Yes      | Registration seed for validation (must match server configuration) |
| `cn`      | string | Yes      | Common Name for the RA node                                        |
| `profile` | string | No       | Certificate profile (default: "ra")                                |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "status": "registered",
    "cn": "RA_Node_Name",
    "profile": "ra"
  }
}
```

**Response (Error - Invalid Seed):**

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "Invalid registration seed"
}
```

---

#### 2. `status` - Get Registration Status

**Request:**

```json
{
  "TASK": "status",
  "params": {
    "cn": "RA_Node_Name"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description         |
| --------- | ------ | -------- | ------------------- |
| `cn`      | string | No       | RA node Common Name |

**Response (Registered):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "status": "registered",
    "node": {
      "cn": "RA_Node_Name",
      "profile": "ra",
      "registered_at": "2024-01-15T10:30:00Z"
    }
  }
}
```

**Response (Not Registered):**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "status": "not_registered"
  }
}
```

---

## Error Handling

### Error Response Format

All errors follow this format:

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "<error_message>"
}
```

### Common Error Messages

| Error Message                 | Cause                          | Resolution                 |
| ----------------------------- | ------------------------------ | -------------------------- |
| `Invalid JSON: <details>`     | Malformed JSON in request      | Fix JSON syntax            |
| `Unknown task: <task_name>`   | Invalid task name              | Use valid task name        |
| `Missing <param> parameter`   | Required parameter missing     | Include required parameter |
| `Invalid registration seed`   | Wrong seed for RA registration | Use correct seed           |
| `Authority not initialized`   | CA not initialized             | Initialize CA first        |
| `Certificate not found: <dn>` | Certificate DN not found       | Verify DN is correct       |
| `<error>`                     | Other errors                   | Check error details        |

---

## Python Implementation Example

```python
import zmq
import json

class RAClient:
    """RA client for communicating with CA."""

    def __init__(self, ca_host="127.0.0.1", ca_port=5000, reg_port=5001):
        self.ca_address = f"tcp://{ca_host}:{ca_port}"
        self.reg_address = f"tcp://{ca_host}:{reg_port}"
        self.context = zmq.Context()

    def _send_request(self, address, task, params=None):
        """Send a request and get response."""
        socket = self.context.socket(zmq.REQ)
        socket.connect(address)

        request = {
            "TASK": task,
            "params": params or {}
        }

        socket.send_string(json.dumps(request))
        response = socket.recv_string()
        socket.close()

        return json.loads(response)

    def register(self, seed, cn, profile="ra"):
        """Register RA with CA."""
        return self._send_request(
            self.reg_address,
            "register",
            {"seed": seed, "cn": cn, "profile": profile}
        )

    def sign_csr(self, csr_pem, profile="server"):
        """Sign a CSR."""
        return self._send_request(
            self.ca_address,
            "sign",
            {"csr": csr_pem, "profile": profile}
        )

    def revoke(self, dn, reason="unspecified"):
        """Revoke a certificate."""
        return self._send_request(
            self.ca_address,
            "revoke",
            {"dn": dn, "reason": reason}
        )

    def ocsp_check(self, cert_pem):
        """Check certificate status."""
        return self._send_request(
            self.ca_address,
            "ocsp_check",
            {"cert": cert_pem}
        )
```

---

## Summary

This document provides complete documentation for implementing the RA side of the uPKI CA-RA ZMQ protocol:

- **Port 5000**: 17 CA operation tasks for full certificate lifecycle management
- **Port 5001**: 2 registration tasks for RA node registration
- **JSON over ZMQ**: Simple request/response pattern
- **Error handling**: Consistent error response format
- **Registration flow**: Seed-based RA registration

For implementation support, refer to the source code:

- [`upki_ca/connectors/zmq_listener.py`](upki_ca/connectors/zmq_listener.py) - Main CA operations
- [`upki_ca/connectors/zmq_register.py`](upki_ca/connectors/zmq_register.py) - RA registration
- [`upki_ca/connectors/listener.py`](upki_ca/connectors/listener.py) - Base listener class
- [`upki_ca/ca/authority.py`](upki_ca/ca/authority.py) - Authority implementation
