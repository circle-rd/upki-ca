# uPKI CA-ZMQ Protocol Documentation

This document describes the complete ZMQ protocol between the uPKI Certificate Authority (CA) and Registration Authority (RA). The protocol is designed for implementing the RA side of the communication.

## Table of Contents

1. [Overview](#overview)
2. [Transport Layer](#transport-layer)
3. [Message Format](#message-format)
4. [Message Types](#message-types)
5. [Registration Flow](#registration-flow)
6. [Certificate Operations](#certificate-operations)
7. [OCSP Handling](#ocsp-handling)
8. [Error Handling](#error-handling)
9. [Example Messages](#example-messages)

---

## Overview

The uPKI system uses two separate ZMQ endpoints:

| Endpoint        | Port | Purpose                                                |
| --------------- | ---- | ------------------------------------------------------ |
| CA Operations   | 5000 | All certificate operations (sign, revoke, renew, etc.) |
| RA Registration | 5001 | Initial RA node registration (clear mode)              |

---

## Transport Layer

- **Protocol**: ZMQ REQ/REP (Request/Reply)
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
  "DATA": {
    "<result_field1>": "<value1>",
    "<result_field2>": "<value2>"
  }
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

## Message Types

### 1. CA Operations (Port 5000)

The following tasks are available via the main ZMQ listener:

| Task Name       | Handler Method                                                  | Description              |
| --------------- | --------------------------------------------------------------- | ------------------------ |
| `get_ca`        | [`_upki_get_ca()`](upkica/connectors/zmqListener.py:181)        | Get CA certificate       |
| `get_crl`       | [`_upki_get_crl()`](upkica/connectors/zmqListener.py:188)       | Get CRL                  |
| `generate_crl`  | [`_upki_generate_crl()`](upkica/connectors/zmqListener.py:201)  | Generate new CRL         |
| `register`      | [`_upki_register()`](upkica/connectors/zmqListener.py:214)      | Register a new node      |
| `generate`      | [`_upki_generate()`](upkica/connectors/zmqListener.py:243)      | Generate certificate     |
| `sign`          | [`_upki_sign()`](upkica/connectors/zmqListener.py:278)          | Sign CSR                 |
| `renew`         | [`_upki_renew()`](upkica/connectors/zmqListener.py:296)         | Renew certificate        |
| `revoke`        | [`_upki_revoke()`](upkica/connectors/zmqListener.py:313)        | Revoke certificate       |
| `unrevoke`      | [`_upki_unrevoke()`](upkica/connectors/zmqListener.py:326)      | Unrevoke certificate     |
| `delete`        | [`_upki_delete()`](upkica/connectors/zmqListener.py:340)        | Delete certificate       |
| `view`          | [`_upki_view()`](upkica/connectors/zmqListener.py:354)          | View certificate details |
| `ocsp_check`    | [`_upki_ocsp_check()`](upkica/connectors/zmqListener.py:368)    | Check OCSP status        |
| `list_profiles` | [`_upki_list_profiles()`](upkica/connectors/zmqListener.py:163) | List all profiles        |
| `get_profile`   | [`_upki_get_profile()`](upkica/connectors/zmqListener.py:169)   | Get profile details      |
| `list_admins`   | [`_upki_list_admins()`](upkica/connectors/zmqListener.py:129)   | List administrators      |
| `add_admin`     | [`_upki_add_admin()`](upkica/connectors/zmqListener.py:133)     | Add administrator        |
| `remove_admin`  | [`_upki_remove_admin()`](upkica/connectors/zmqListener.py:147)  | Remove administrator     |

### 2. Registration Operations (Port 5001)

| Task Name  | Handler Method                                            | Description             |
| ---------- | --------------------------------------------------------- | ----------------------- |
| `register` | [`_register_node()`](upkica/connectors/zmqRegister.py:63) | Register new RA node    |
| `status`   | [`_get_status()`](upkica/connectors/zmqRegister.py:95)    | Get registration status |

---

## Request/Response Formats by Message Type

### 1. `get_ca` - Get CA Certificate

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

**Response (Error):**

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "Authority not initialized"
}
```

**Error Conditions:**

- `AuthorityError`: Authority not initialized

---

### 2. `get_crl` - Get CRL

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

**Notes:**

- CRL is returned as base64-encoded DER format

---

### 3. `generate_crl` - Generate New CRL

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

### 4. `register` (Port 5001) - Register RA Node

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

**Response (Error - Missing CN):**

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "Missing cn parameter"
}
```

---

### 5. `register` (Port 5000) - Register New Node Certificate

**Request:**

```json
{
  "TASK": "register",
  "params": {
    "seed": "seed_string",
    "cn": "node.example.com",
    "profile": "server",
    "sans": [{ "type": "DNS", "value": "node.example.com" }]
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                             |
| --------- | ------ | -------- | --------------------------------------- |
| `seed`    | string | Yes      | Registration seed                       |
| `cn`      | string | Yes      | Common Name                             |
| `profile` | string | No       | Certificate profile (default: "server") |
| `sans`    | array  | No       | Subject Alternative Names               |

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

### 6. `generate` - Generate Certificate

**Request:**

```json
{
  "TASK": "generate",
  "params": {
    "cn": "server.example.com",
    "profile": "server",
    "sans": [
      { "type": "DNS", "value": "server.example.com" },
      { "type": "DNS", "value": "www.example.com" }
    ],
    "local": true
  }
}
```

**Parameters:**

| Parameter | Type    | Required | Description                             |
| --------- | ------- | -------- | --------------------------------------- |
| `cn`      | string  | Yes      | Common Name                             |
| `profile` | string  | No       | Certificate profile (default: "server") |
| `sans`    | array   | No       | Subject Alternative Names               |
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

**Response (Error):**

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "Missing cn parameter"
}
```

---

### 7. `sign` - Sign CSR

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

**Response (Error):**

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "Missing csr parameter"
}
```

---

### 8. `renew` - Renew Certificate

**Request:**

```json
{
  "TASK": "renew",
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
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "serial": "9876543210"
  }
}
```

**Response (Error):**

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "Missing dn parameter"
}
```

**Implementation Note:** The renewal process ([`Authority.renew_certificate()`](upkica/ca/authority.py:571)):

1. Loads the old certificate
2. Extracts the CN and SANs
3. Generates a new key pair
4. Creates a new CSR
5. Signs the new certificate with the same profile

---

### 9. `revoke` - Revoke Certificate

**Request:**

```json
{
  "TASK": "revoke",
  "params": {
    "dn": "/CN=server.example.com",
    "reason": "keyCompromise"
  }
}
```

**Parameters:**

| Parameter | Type   | Required | Description                                |
| --------- | ------ | -------- | ------------------------------------------ |
| `dn`      | string | Yes      | Distinguished Name of the certificate      |
| `reason`  | string | No       | Revocation reason (default: "unspecified") |

**Revocation Reasons:**

| Reason                 | Description                     |
| ---------------------- | ------------------------------- |
| `unspecified`          | Unspecified reason (default)    |
| `keyCompromise`        | Private key compromised         |
| `cACompromise`         | CA certificate compromised      |
| `affiliationChanged`   | Subject information changed     |
| `superseded`           | Certificate superseded          |
| `cessationOfOperation` | Certificate no longer needed    |
| `certificateHold`      | Certificate is temporarily held |

**Response (Success):**

```json
{
  "EVENT": "ANSWER",
  "DATA": true
}
```

**Response (Error):**

```json
{
  "EVENT": "UPKI ERROR",
  "MSG": "Missing dn parameter"
}
```

---

### 10. `unrevoke` - Unrevoke Certificate

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

**Implementation Note:** Removes the certificate from the CRL ([`Authority.unrevoke_certificate()`](upkica/ca/authority.py:540)).

---

### 11. `delete` - Delete Certificate

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

**Implementation Note:** Deletion actually revokes the certificate with reason `cessationOfOperation` ([`Authority.delete_certificate()`](upkica/ca/authority.py:663)).

---

### 12. `view` - View Certificate Details

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

**Implementation Note:** Returns parsed certificate details from [`Authority.view_certificate()`](upkica/ca/authority.py:643).

---

### 13. `ocsp_check` - Check OCSP Status

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

**Implementation Note:** The OCSP check ([`Authority.ocsp_check()`](upkica/ca/authority.py:730)):

1. Verifies the certificate is issued by the CA
2. Checks the CRL for revocation status
3. Checks certificate expiration

---

### 14. `list_profiles` - List Certificate Profiles

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

### 15. `get_profile` - Get Profile Details

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

### 16. `list_admins` - List Administrators

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

### 17. `add_admin` - Add Administrator

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

### 18. `remove_admin` - Remove Administrator

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

### 19. `status` (Port 5001) - Get Registration Status

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
| `cn`      | string | Yes      | RA node Common Name |

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

## Registration Flow

### Initial RA Registration Flow

```
┌─────────────┐                           ┌─────────────┐
│     RA     │                           │     CA     │
└──────┬──────┘                           └──────┬──────┘
       │                                        │
       │  1. Registration Request (Port 5001)  │
       │  ──────────────────────────────────── │
       │  {                                    │
       │    "TASK": "register",                │
       │    "params": {                        │
       │      "seed": "configured_seed",       │
       │      "cn": "ra-node-1",               │
       │      "profile": "ra"                  │
       │    }                                  │
       │  }                                    │
       │ ──────────────────────────────────>   │
       │                                        │
       │  2. Registration Response              │
       │  ──────────────────────────────────── │
       │  {                                    │
       │    "EVENT": "ANSWER",                 │
       │    "DATA": {                          │
       │      "status": "registered",          │
       │      "cn": "ra-node-1",               │
       │      "profile": "ra"                  │
       │    }                                  │
       │  }                                    │
       │ <─────────────────────────────────    │
       │                                        │
       │  3. Certificate Operations (Port 5000)│
       │  (After successful registration)      │
       │                                        │
```

### Registration Steps

1. **Configure the RA** with the registration seed (must match CA configuration)
2. **Connect to CA** on port 5001 (registration port)
3. **Send registration request** with:
   - `seed`: Registration seed (validated against server configuration)
   - `cn`: RA node Common Name
   - `profile`: Certificate profile (default: "ra")
4. **Receive response**: If seed is valid, RA is registered
5. **Use CA operations** on port 5000 for certificate operations

---

## Certificate Operations

### Certificate Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    Certificate Lifecycle                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐    ┌─────────┐    ┌──────────┐    ┌───────────┐ │
│   │  CSR   │───>│ Generate│───>│  Signed  │───>│  Active   │ │
│   │ Request│    │   Cert  │    │  Cert    │    │  Cert     │ │
│   └─────────┘    └─────────┘    └──────────┘    └───────────┘ │
│                                              │               │
│                                              v               │
│                                        ┌───────────┐         │
│                                        │  Renewed  │─────────┘
│                                        │   Cert    │         │
│                                        └───────────┘         │
│                                              │               │
│                                              v               │
│                                        ┌───────────┐         │
│                                        │  Revoked  │─────────┘
│                                        │   Cert    │         │
│                                        └───────────┘         │
│                                              │               │
│                                              v               │
│                                        ┌───────────┐         │
│                                        │   CRL     │─────────┘
│                                        │  Entry    │         │
│                                        └───────────┘         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Operation Summary

| Operation  | Task         | Port | Purpose                                 |
| ---------- | ------------ | ---- | --------------------------------------- |
| Generate   | `generate`   | 5000 | Generate new key pair and certificate   |
| Sign CSR   | `sign`       | 5000 | Sign a CSR from external source         |
| Renew      | `renew`      | 5000 | Renew an existing certificate (new key) |
| Revoke     | `revoke`     | 5000 | Revoke a certificate                    |
| Unrevoke   | `unrevoke`   | 5000 | Remove revocation status                |
| Delete     | `delete`     | 5000 | Delete certificate (revokes it)         |
| View       | `view`       | 5000 | View certificate details                |
| OCSP Check | `ocsp_check` | 5000 | Check certificate status                |

---

## OCSP Handling

### OCSP Response Format

The CA provides OCSP status checking through the `ocsp_check` task. The response includes:

| Status    | Description                          |
| --------- | ------------------------------------ |
| `good`    | Certificate is valid and not revoked |
| `revoked` | Certificate has been revoked         |
| `expired` | Certificate has expired              |

### OCSP Check Process

1. **Load certificate**: Parse the PEM certificate
2. **Verify issuer**: Confirm certificate was issued by the CA
3. **Check CRL**: Search CRL for serial number
4. **Check expiration**: Verify certificate validity period
5. **Return status**: Provide status with details

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

### Exception Hierarchy

Errors originate from [`upkica.core.upkiError`](upkica/core/upkiError.py):

| Exception            | Description                               |
| -------------------- | ----------------------------------------- |
| `AuthorityError`     | Authority initialization/operation errors |
| `CommunicationError` | Network/communication errors              |
| `CertificateError`   | Certificate operation errors              |
| `ProfileError`       | Profile configuration errors              |
| `ValidationError`    | Validation errors                         |
| `StorageError`       | Storage backend errors                    |

---

## Example Messages

### Example 1: Sign a CSR

**Request:**

```json
{
  "TASK": "sign",
  "params": {
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICXTCCAUUCAQAwGDEWMBQGA1UEAwwNZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQDGx+6F7M3hT9JqFxN6R2F5vK8J3LmPxE8N2dK\n9hX5B3M4L8K2N6P0Q1R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0F1G2H3I4J5K6L7M8N\n-----END CERTIFICATE REQUEST-----",
    "profile": "server"
  }
}
```

**Response:**

```json
{
  "EVENT": "ANSWER",
  "DATA": {
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKHB8EQXRQZJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAkZSMQ8wDQYDVQQIDAZGcmFuY2UxDzANBgNVBAoMBnVwS0kxEDAOBgNVBAMM\nB3Jvb3RDQTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBkxEzARBgNV\nBAMMCmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----",
    "serial": "1234567890"
  }
}
```

### Example 2: Revoke a Certificate

**Request:**

```json
{
  "TASK": "revoke",
  "params": {
    "dn": "/CN=server.example.com",
    "reason": "keyCompromise"
  }
}
```

**Response:**

```json
{
  "EVENT": "ANSWER",
  "DATA": true
}
```

### Example 3: Check OCSP Status

**Request:**

```json
{
  "TASK": "ocsp_check",
  "params": {
    "cert": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKHB8EQXRQZJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAkZSMQ8wDQYDVQQIDAZGcmFuY2UxDzANBgNVBAoMBnVwS0kxEDAOBgNVBAMM\nB3Jvb3RDQTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBkxEzARBgNV\nBAMMCmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----"
  }
}
```

**Response (Revoked):**

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

---

## RA Implementation Guide

### Python Implementation Example

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

- **Two ports**: 5000 for CA operations, 5001 for RA registration
- **JSON over ZMQ**: Simple request/response pattern
- **19 message types**: Full certificate lifecycle management
- **Error handling**: Consistent error response format
- **Registration flow**: Seed-based RA registration

For implementation support, refer to the source code:

- [`upkica/connectors/zmqListener.py`](upkica/connectors/zmqListener.py) - Main CA operations
- [`upkica/connectors/zmqRegister.py`](upkica/connectors/zmqRegister.py) - RA registration
- [`upkica/connectors/listener.py`](upkica/connectors/listener.py) - Base listener class
- [`upkica/ca/authority.py`](upkica/ca/authority.py) - Authority implementation
