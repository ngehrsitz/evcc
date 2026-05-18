# Leapmotor International API - Protocol Specification

This document describes the authentication and API protocol used by the Leapmotor International mobile app to communicate with Leapmotor cloud services. It is sufficient to reimplement the flow from scratch in any language.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Protocol Constants](#protocol-constants)
3. [Phase 1: Login](#phase-1-login)
4. [Phase 2: Login Response Processing](#phase-2-login-response-processing)
5. [Phase 3: Authenticated API Requests](#phase-3-authenticated-api-requests)
6. [Phase 4: Token Refresh](#phase-4-token-refresh)
7. [API Endpoints](#api-endpoints)
8. [Cryptography Reference](#cryptography-reference)

---

## Prerequisites

| Item | Description |
|------|-------------|
| **Email** | Leapmotor account email address |
| **Password** | Leapmotor account password |
| **App Certificate** | X.509 client certificate extracted from the Leapmotor APK (`app.crt` / `app.key`, RSA-2048, PEM format) |

The app certificate is a static credential embedded in the official Leapmotor mobile application. It is used exclusively for the login request (Phase 1). Its subject is `CN=LeapmotorAppCrtCN, OU=carnet, O=leapmotor` and it is valid until 2029-03-06.

---

## Protocol Constants

| Name | Value |
|------|-------|
| Base URL | `https://appgateway.leapmotor-international.de` |
| App Version | `1.12.3` |
| Source | `leapmotor` |
| Channel | `1` |
| Device Type | `1` |
| P12 Encryption Algorithm | `1` |
| Policy ID | `20260204` |
| Language | `en` |

---

## Phase 1: Login

### TLS Configuration

- **Mutual TLS**: Present the **app certificate** as the client certificate.
- **Server verification**: Validate the server certificate against the CA that issued the app certificate (the `AppSubCA` chain). This is a private CA, so it must be explicitly trusted — standard system trust stores will not contain it.
- **HTTP timeout**: 30 seconds.

### Endpoint

```
POST https://appgateway.leapmotor-international.de/carownerservice/oversea/acct/v1/login
```

### Generate Request Parameters

Before building the request, generate:
- **nonce**: Random integer in range [100000, 9999999], converted to string.
- **timestamp**: Current time as Unix milliseconds, converted to string.
- **deviceID**: Random 16-byte value, hex-encoded (32 characters). This is a one-time initial value; it will be replaced by the server-assigned value from the login response.

### Request Headers

| Header | Value |
|--------|-------|
| `Content-Type` | `application/x-www-form-urlencoded; charset=UTF-8` |
| `acceptLanguage` | `en` |
| `channel` | `1` |
| `deviceType` | `1` |
| `X-P12_ENC_ALG` | `1` |
| `source` | `leapmotor` |
| `version` | `1.12.3` |
| `nonce` | *(generated)* |
| `deviceId` | *(generated)* |
| `timestamp` | *(generated)* |
| `sign` | *(computed, see below)* |

### Login Sign Computation (SHA-256)

Concatenate the following values in this exact order into a single string (no separators):

```
acceptLanguage + deviceType + deviceId + "1" + email + "0" + "1" + nonce + password + policyId + source + timestamp + appVersion
```

With concrete constant substitution:

```
"en" + "1" + deviceId + "1" + email + "0" + "1" + nonce + password + "20260204" + "leapmotor" + timestamp + "1.12.3"
```

Compute SHA-256 of the resulting byte string. Output as lowercase hexadecimal (64 characters).

### Request Body (form-encoded)

| Field | Value |
|-------|-------|
| `email` | User's email address |
| `password` | User's password |
| `loginMethod` | `1` |
| `policyId` | `20260204` |
| `isRecoverAcct` | `0` |

### Success Response (JSON)

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 12345,
    "uid": "user@example.com",
    "token": "<JWT access token>",
    "refreshToken": "<refresh token>",
    "signIkm": "<base64-encoded HKDF input keying material>",
    "signSalt": "<base64-encoded HKDF salt>",
    "signInfo": "<base64-encoded HKDF info>",
    "base64Cert": "<base64-encoded PKCS#12 bundle>"
  }
}
```

A non-zero `code` indicates an error.

---

## Phase 2: Login Response Processing

Process the login response in four steps:

### Step 1: Extract Session Credentials

From the response `data` object, store:
- `token` — JWT access token for authenticated requests
- `refreshToken` — used for token refresh
- `id` — account ID (as string)
- `uid` — user identifier (typically the email)

### Step 2: Extract Session Device ID from JWT

The access token is a JWT. Parse it **without cryptographic verification** (the signing key is not available to clients). Extract the `user_name` claim from the payload.

The `user_name` value is a comma-separated string with at least 3 parts:

```
<email>,<uid>,<deviceId>[,...]
```

Extract the **third element** (index 2) as the session `deviceId`. Use this value for all subsequent requests instead of the randomly generated one.

### Step 3: Derive HMAC Signing Key (HKDF-SHA256)

Using the `signIkm`, `signSalt`, and `signInfo` values from the response (treated as raw byte strings, not base64-decoded):

```
signingKey = HKDF-SHA256(
    ikm  = bytes(signIkm),
    salt = bytes(signSalt),
    info = bytes(signInfo),
    length = 32
)
```

This produces a 32-byte key used to HMAC-sign all authenticated requests.

### Step 4: Decrypt Account Certificate

The `base64Cert` field contains a PKCS#12 (.p12) certificate bundle, base64-encoded and password-protected. To extract the account certificate:

#### 4a. Base64-decode

```
p12Bytes = base64Decode(data.base64Cert)
```

#### 4b. Derive PKCS#12 Password

The password is derived from the account ID and UID using the following algorithm:

```
function deriveP12Password(accountId, uid):
    // 1. MD5 hash the account ID
    md5Hash = MD5(bytes(accountId))
    cn = hexEncode(md5Hash)                // 32 hex characters

    // 2. Extract characters at even indices (0, 2, 4, ...) from cn
    cnEven = ""
    for i = 0; i < length(cn); i += 2:
        cnEven += cn[i]
    // Result: 16 characters

    // 3. Extract characters at odd indices (1, 3, 5, ...) from uid
    uidOdd = ""
    for i = 1; i < length(uid); i += 2:
        uidOdd += uid[i]

    // 4. Concatenate: full cn + cnEven + uidOdd
    appInput = cn + cnEven + uidOdd

    // 5. SHA-256 hash the concatenation
    digest = SHA256(bytes(appInput))        // 32 bytes

    // 6. SM4-ECB encrypt (see Cryptography Reference)
    encrypted = SM4_ECB_Encrypt(digest, SM4_KEY)

    // 7. Base64-encode the FIRST 12 BYTES of the encrypted output
    b64 = base64Encode(encrypted[0:12])

    // 8. Truncate to 15 characters
    if length(b64) > 15:
        return b64[0:15]
    return b64
```

#### 4c. Decode PKCS#12

Decode the PKCS#12 bundle using the derived password. Extract:
- **Private key** — the account's RSA private key
- **Certificate** — the account's X.509 certificate

These form the **account certificate pair**, used for mTLS in all subsequent API calls.

---

## Phase 3: Authenticated API Requests

After login, all API calls use a different TLS and header configuration than the login request.

### TLS Configuration

- **Mutual TLS**: Present the **account certificate** (from Phase 2, Step 4).
- **Server verification**: Validate against the same private CA as the login phase (`AppSubCA` chain).
- **HTTP timeout**: 30 seconds.

### Request Headers

Every authenticated request carries these headers:

| Header | Value |
|--------|-------|
| `Content-Type` | `application/x-www-form-urlencoded` |
| `acceptLanguage` | `en` |
| `channel` | `1` |
| `deviceType` | `1` |
| `X-P12_ENC_ALG` | `1` |
| `source` | `leapmotor` |
| `version` | `1.12.3` |
| `nonce` | Random integer [100000, 9999999] as string |
| `deviceId` | Session device ID (from JWT, Phase 2 Step 2) |
| `timestamp` | Current Unix milliseconds as string |
| `sign` | HMAC-SHA256 signature (see below) |
| `userId` | Account ID (from login response `data.id`) |
| `token` | JWT access token |

If the request targets a specific vehicle, also include:
| `vin` | Vehicle identification number |

### Authenticated Sign Computation (HMAC-SHA256)

1. **Build a field map** containing all of the following key-value pairs:

   | Key | Value |
   |-----|-------|
   | `acceptLanguage` | `en` |
   | `channel` | `1` |
   | `deviceId` | *(session device ID)* |
   | `deviceType` | `1` |
   | `nonce` | *(generated for this request)* |
   | `source` | `leapmotor` |
   | `timestamp` | *(generated for this request)* |
   | `version` | `1.12.3` |
   | `vin` | *(only if VIN is set for this request)* |

   If the request has body parameters, also add each body parameter key-value pair to the map.

2. **Sort keys alphabetically** (lexicographic, ASCII order).

3. **Concatenate all values** (not keys) in sorted-key order into a single string.

4. **Compute HMAC-SHA256** of the concatenated string using the 32-byte signing key derived in Phase 2, Step 3.

5. **Output as lowercase hexadecimal** (64 characters).

### Token Expiry Detection

After each API call, check the response. If `code != 0` AND the `message` field contains the substring `"token"` (case-insensitive), the access token has expired. Perform a token refresh (Phase 4), then retry the request once.

---

## Phase 4: Token Refresh

### Endpoint

```
POST https://appgateway.leapmotor-international.de/carownerservice/oversea/acct/v1/token/refresh
```

### TLS

Uses the **account certificate** (same as authenticated requests).

### Headers

Build signed headers using the same HMAC-SHA256 process as Phase 3, with the body parameter `refreshToken` included in the signing field map.

Additionally include auth headers: `userId` and `token`.

### Request Body (form-encoded)

| Field | Value |
|-------|-------|
| `refreshToken` | Current refresh token |

### Success Response

```json
{
  "code": 0,
  "data": {
    "token": "<new JWT access token>",
    "refreshToken": "<new refresh token>"
  }
}
```

Replace both the stored `token` and `refreshToken` with the new values.

### Fallback

If the refresh request fails (network error, non-zero response code, or parse error), perform a full login (Phase 1) to re-authenticate from scratch.

---

## API Endpoints

### Vehicle List

```
POST https://appgateway.leapmotor-international.de/carownerservice/oversea/vehicle/v1/list
```

**Body**: Empty (no form parameters).

**Response**:
```json
{
  "code": 0,
  "data": {
    "bindcars": [
      { "vin": "LVTL4ANA...", "carType": "c10" }
    ],
    "sharedcars": [
      { "vin": "LVTL4ANB...", "carType": "c16" }
    ]
  }
}
```

- `bindcars`: Vehicles owned by this account.
- `sharedcars`: Vehicles shared with this account.
- Discard entries where `vin` is empty.
- The `carType` field is required for the status endpoint.

### Vehicle Status

```
POST https://appgateway.leapmotor-international.de/carownerservice/oversea/vehicle/v1/status/get/{carType}
```

Where `{carType}` is the lowercase `carType` value from the vehicle list (e.g., `c10`).

**Headers**: Include `vin` header with the vehicle's VIN.

**Body** (form-encoded):

| Field | Value |
|-------|-------|
| `vin` | Vehicle identification number |

**Response**:
```json
{
  "code": 0,
  "data": {
    "soc": 75,
    "chargeState": 1,
    "chargeRemainTime": 120,
    "batteryCurrent": -25.5,
    "batteryVoltage": 400.0,
    "expectedMileage": 310,
    "speed": 0,
    "totalMileage": 12500
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `soc` | int | State of charge, 0-100 (%) |
| `chargeState` | int | 0 = not connected, 1 = AC connected, 2 = DC connected |
| `chargeRemainTime` | int | Minutes remaining until full charge |
| `batteryCurrent` | float | Battery current in Amperes (negative when charging) |
| `batteryVoltage` | float | Battery voltage in Volts |
| `expectedMileage` | int | Estimated remaining range (km) |
| `speed` | int | Current speed (km/h) |
| `totalMileage` | int | Odometer reading (km) |

All fields are nullable; a missing/null field means the data is not yet available from the vehicle.

---

## Cryptography Reference

### SM4-ECB Encryption (for PKCS#12 password derivation)

- **Algorithm**: SM4 (GB/T 32907-2016, Chinese national standard block cipher)
- **Mode**: ECB (Electronic Code Book)
- **Block size**: 16 bytes
- **Key** (16 bytes, hexadecimal):
  ```
  42 9c f4 50 ef 91 7a 98 54 33 43 0b cf ed 62 ac
  ```
- **Padding**: PKCS#7 (pad to next 16-byte boundary; padding byte value = number of padding bytes added)
- **Process**: Pad input with PKCS#7, then encrypt each 16-byte block independently.

### HKDF-SHA256 (for signing key derivation)

- **Hash**: SHA-256
- **IKM**: `signIkm` string from login response (raw UTF-8 bytes)
- **Salt**: `signSalt` string from login response (raw UTF-8 bytes)
- **Info**: `signInfo` string from login response (raw UTF-8 bytes)
- **Output length**: 32 bytes

### SHA-256 (for login sign)

- Standard SHA-256 hash of concatenated ASCII parameter string.
- Output: lowercase hex-encoded (64 characters).

### HMAC-SHA256 (for authenticated request sign)

- **Key**: 32-byte signing key from HKDF derivation.
- **Message**: Concatenated field values (sorted by key name).
- **Output**: lowercase hex-encoded (64 characters).

---

## Protocol Flow Diagram

```
                    +-----------------+
                    | App Certificate |
                    | (from APK)      |
                    +--------+--------+
                             |
                             v
              +-----------------------------+
              | Phase 1: LOGIN              |
              | POST .../acct/v1/login      |
              | mTLS: app cert              |
              | Sign: SHA-256               |
              +-------------+---------------+
                            |
                            v
              +-----------------------------+
              | Phase 2: PROCESS RESPONSE   |
              | - Extract tokens            |
              | - Device ID from JWT        |
              | - HKDF -> signing key       |
              | - Decrypt account cert      |
              |   (SM4 + PKCS#12)           |
              +-------------+---------------+
                            |
                            v
                    +-------+--------+
                    | Account Cert   |
                    | (from server)  |
                    +-------+--------+
                            |
                            v
              +-----------------------------+
              | Phase 3: API CALLS          |
              | mTLS: account cert          |
              | Sign: HMAC-SHA256           |
              | Auth: userId + token        |
              +-------------+---------------+
                            |
                     token expires?
                            |
                            v
              +-----------------------------+
              | Phase 4: REFRESH            |
              | POST .../acct/v1/token/     |
              |       refresh               |
              | On failure -> Phase 1       |
              +-----------------------------+
```
