# GuardFi — Flutter handoff cheat sheet

Everything a Flutter client needs for Phases 1–11. Two files accompany this page:

* [`guardfi_api_client.dart`](guardfi_api_client.dart) — typed REST client with automatic Bearer injection.
* [`guardfi_sos_socket.dart`](guardfi_sos_socket.dart) — Socket.io wrapper for the SOS room and live GPS.

Neither file imports anything outside the three packages below. Copy both into
`lib/api/` and add:

```yaml
dependencies:
  http: ^1.2.0
  http_parser: ^4.0.2        # multipart image MIME type (Multer rejects octet-stream)
  socket_io_client: ^2.0.3+1
  crypto: ^3.0.3             # only if you sign the biometric assertion
  flutter_secure_storage: ^9.0.0  # store the JWT here, never in SharedPreferences
```

---

## 1. Basics

| Item | Value |
|---|---|
| Base URL | Origin only, e.g. `https://guardfi-backend.onrender.com` |
| REST prefix | `/api/v1` (the client appends it) |
| Health | `GET /health` — **not** under `/api/v1` |
| Auth header | `Authorization: Bearer <jwt>` on every route except the three public ones |
| Public routes | `POST /auth/send-otp`, `POST /auth/verify-otp`, `GET /config/global` |
| Body format | JSON, `Content-Type: application/json`, max **1 MB** |
| Upload | `multipart/form-data`, field **`image`**, optional text field `text` |
| Token life | 7 days (`expiresIn: "7d"`); no refresh, no logout endpoint |
| Caching | Every response is `Cache-Control: no-store` |

**Emulator addresses:** Android emulator reaches your laptop at
`http://10.0.2.2:3000`; iOS simulator/web at `http://localhost:3000`. Production
must be HTTPS — never ship a cleartext base URL.

### Envelope

Success:

```json
{ "success": true, "message": "OK", "data": { }, "errors": null }
```

Failure (always HTTP 4xx/5xx):

```json
{
  "success": false,
  "message": "Validation failed.",
  "data": null,
  "errors": [
    { "field": "phone", "code": "custom", "message": "phone must be a valid phone number, e.g. +919876543210" }
  ]
}
```

* `errors` is `null` or a list. Each entry always has `field`, `code`, `message`;
  some add `remainingAttempts`, `retryAfterSeconds`, `msg_en`, `msg_hi`.
* `data` is `null` on every failure.
* Never branch on `message` — branch on `errors[0].code`.

### Status handling

| Status | Meaning for the UI |
|---|---|
| 400 | Validation — show the field messages |
| 401 | Token missing/expired/deleted account → clear secure storage, go to login |
| 403 | Role or emergency-state refusal (`SOS_FORBIDDEN`, `Emergency mode is not active`) |
| 404 | Resource missing **or** not yours (deliberate: no IDOR oracle) |
| 409 | State conflict (`NOMINEE_DUPLICATE`, `RISK_CHECK_REQUIRED`, `SOS_NONE_ACTIVE`) |
| 413 | Body or screenshot too large |
| 429 | Rate limited — honour `errors[0].retryAfterSeconds` when present |
| 503 | Upstream not configured/unready (SMS, Cloudinary, config store, DB) |
| 5xx | Retry with backoff; show a neutral message |

---

## 2. Endpoint map

| # | Module | Method + path | Auth | Purpose |
|---|---|---|---|---|
| 1 | Auth | `POST /api/v1/auth/send-otp` | — | Send the 6-digit code |
| 2 | Auth | `POST /api/v1/auth/verify-otp` | — | Verify code, create account, get JWT |
| 3 | Auth | `DELETE /api/v1/auth/account` | ✅ | Irreversible account + data deletion |
| 4 | Nominees | `POST /api/v1/nominees/add` | ✅ | Add a guardian |
| 5 | Nominees | `GET /api/v1/nominees/list` | ✅ | List guardians, primary first |
| 6 | Nominees | `PATCH /api/v1/nominees/{id}` | ✅ | Update name/relation/primary/fcmToken |
| 7 | Nominees | `DELETE /api/v1/nominees/remove/{id}` | ✅ | Remove, auto-promote next primary |
| 8 | SOS | `POST /api/v1/sos/trigger` | ✅ | Open or return the ACTIVE alert |
| 9 | SOS | `POST /api/v1/sos/resolve` | ✅ | Close the caller's active alert |
| 10 | SOS | `GET /api/v1/sos/active` | ✅ | Recovery after app restart |
| 11 | Analytics | `GET /api/v1/analytics/dashboard` | ✅ | Dashboard aggregates + readiness |
| 12 | Shield Pay | `POST /api/v1/shield-pay/check-upi` | ✅ | Rate a payee |
| 13 | Shield Pay | `POST /api/v1/shield-pay/proceed-transaction` | ✅ | Verify PIN, record payment |
| 14 | Shield Pay | `POST /api/v1/shield-pay/set-pin` | ✅ | Create/change the PIN |
| 15 | Scam Buster | `POST /api/v1/scam-buster/analyze` | ✅ | Text or screenshot analysis |
| 16 | Scam Buster | `GET /api/v1/scam-buster/history` | ✅ | The caller's scans, cursor-paged |
| 17 | Emergency | `POST /api/v1/emergency/biometric-verify` | ✅ | Signed local biometric → unlock |
| 18 | Emergency | `POST /api/v1/emergency/restricted-action` | ✅ + emergency | Audited restricted action |
| 19 | Emergency | `POST /api/v1/emergency/lock` | ✅ | Leave emergency mode |
| 20 | Emergency | `GET /api/v1/emergency/status` | ✅ | Server-authoritative state |
| 21 | Config | `GET /api/v1/config/global` | — | Policy links, helplines, maintenance flag |
| 22 | Config | `PUT /api/v1/config/global` | ✅ admin | Update global config |
| 23 | Health | `GET /health` | — | Liveness/readiness (200/503) |

---

## 3. Auth

### 3.1 Send OTP

`POST /api/v1/auth/send-otp`

```json
{ "phone": "+919876543210" }
```

Phone formats accepted: `+919876543210`, `919876543210`, `09876543210`,
`9876543210` (default country code 91), or any `+<cc>…` number. Everything is
normalised to E.164 server-side.

```json
{
  "success": true,
  "message": "A verification code has been sent to +919876543210.",
  "data": {
    "phone": "+919876543210",
    "expiresInSeconds": 300,
    "attemptsAllowed": 3,
    "sendsRemainingInWindow": 9,
    "delivery": { "delivered": true, "provider": "twilio", "reason": null },
    "devMode": false
  },
  "errors": null
}
```

With `OTP_DEV_MODE` on (local/demo only) the code is also in `data.otp` and
`delivery` is usually `{ "delivered": false, "provider": "none", "reason": "not_configured" }`.

Common failures: `429` with `OTP_COOLDOWN_ACTIVE` (`retryAfterSeconds`) or
`OTP_SEND_LIMIT_REACHED`; `400` for a bad number; `503` when no SMS provider is
configured and dev mode is off.

### 3.2 Verify OTP

`POST /api/v1/auth/verify-otp`

```json
{
  "phone": "+919876543210",
  "otp": "123456",
  "name": "Asha Verma",
  "fcmToken": "fcm-device-token"
}
```

`name` and `fcmToken` are optional and only make sense on first sign-in (they
refresh the profile on every login). `otp` must be a **string** of exactly 6
digits.

```json
{
  "success": true,
  "message": "Account created and signed in.",
  "data": {
    "user": {
      "_id": "665f1c2ab8f1a2c4d5e6f7a8",
      "phone": "+919876543210",
      "name": "Asha Verma",
      "role": "user",
      "isEmergencyMode": false,
      "biometricEnabled": false,
      "emergencyActivatedAt": null,
      "lastKnownLocation": { "type": "Point", "coordinates": [77.209, 28.6139] },
      "lastLoginAt": "2026-10-21T09:12:44.001Z",
      "createdAt": "2026-10-01T08:00:00.000Z",
      "updatedAt": "2026-10-21T09:12:44.001Z"
    },
    "isNewUser": true,
    "token": "eyJhbGciOiJIUzI1NiIs…",
    "tokenType": "Bearer",
    "expiresIn": "7d",
    "expiresAt": "2026-10-28T09:12:44.000Z"
  },
  "errors": null
}
```

The client stores `data.token` automatically. Persist it in
`flutter_secure_storage`, and on app start call `setAccessToken`.

Failures: `400 OTP_NOT_REQUESTED` / `OTP_INVALID` (with `remainingAttempts`) /
`OTP_EXPIRED`; `429 OTP_LOCKED` after 3 wrong codes; `429` from the auth limiter.

### 3.3 Delete account

`DELETE /api/v1/auth/account` — no body. **Irreversible.** Show a typed
confirmation ("DELETE"), then:

```json
{
  "success": true,
  "message": "Your account and all of its personal data have been permanently deleted.",
  "data": {
    "deleted": {
      "user": 1, "nominees": 2, "sosAlerts": 4, "scamScans": 7,
      "transactionAudits": 3, "otps": 1, "sendThrottles": 1
    },
    "cloudinary": { "requested": 5, "destroyed": 5, "failed": 0, "results": [] },
    "sockets": { "alertsClosed": 1, "roomsEmptied": 1, "socketsDisconnected": 2 },
    "audit": { "id": "665f…", "action": "ACCOUNT_DELETED", "createdAt": "…" }
  },
  "errors": null
}
```

After success the token is worthless (every request re-reads the user row).
Clear local storage and any cached images. A failed Cloudinary destroy does
**not** fail the request — `cloudinary.failed > 0` is informational.

---

## 4. Nominees

### 4.1 Add — `POST /api/v1/nominees/add`

```json
{
  "name": "Ravi Verma",
  "phone": "09876543211",
  "relation": "Brother",
  "isPrimary": false,
  "fcmToken": "optional-fcm-token"
}
```

A guardian does not need the app installed. The first nominee is primary
automatically; `isPrimary: true` promotes this one and demotes the previous.
Cap is 5 (server-side). You cannot nominate your own number.

`201`:

```json
{
  "success": true,
  "message": "Ravi Verma was added as a nominee.",
  "data": {
    "nominee": {
      "_id": "665f20…",
      "name": "Ravi Verma",
      "phone": "+919876543211",
      "relation": "Brother",
      "isPrimary": false,
      "createdAt": "2026-10-21T09:20:00.000Z",
      "updatedAt": "2026-10-21T09:20:00.000Z"
    }
  },
  "errors": null
}
```

Errors: `409 NOMINEE_DUPLICATE`, `409 NOMINEE_LIMIT_REACHED`, `400 NOMINEE_SELF`,
`400` field validation.

### 4.2 List — `GET /api/v1/nominees/list`

```json
{
  "success": true,
  "message": "2 nominee(s) on file.",
  "data": {
    "nominees": [
      { "_id": "665f20…", "name": "Ravi Verma", "phone": "+919876543211",
        "relation": "Brother", "isPrimary": true,
        "createdAt": "…", "updatedAt": "…" },
      { "_id": "665f21…", "name": "Meera Singh", "phone": "+919876543212",
        "relation": "Friend", "isPrimary": false,
        "createdAt": "…", "updatedAt": "…" }
    ],
    "count": 2,
    "maxNominees": 5,
    "remainingSlots": 3
  },
  "errors": null
}
```

`fcmToken` is never returned.

### 4.3 Update — `PATCH /api/v1/nominees/{id}`

Send at least one field. Phone is intentionally **not** editable (remove + add).

```json
{ "name": "Ravi V.", "relation": null, "isPrimary": true }
```

`relation: null` clears it. Response is `{ "nominee": { … } }` like add.
Demoting the only primary is `400 NOMINEE_PRIMARY_REQUIRED` — promote someone
else instead. Another user's id is `404`.

### 4.4 Remove — `DELETE /api/v1/nominees/remove/{id}`

```json
{
  "success": true,
  "message": "Ravi Verma was removed. Meera Singh is now your primary nominee.",
  "data": {
    "removed": { "_id": "665f20…", "name": "Ravi Verma", "phone": "+919876543211",
                 "relation": "Brother", "isPrimary": true, "createdAt": "…", "updatedAt": "…" },
    "promotedNomineeId": "665f21…",
    "promotedName": "Meera Singh",
    "remaining": 1
  },
  "errors": null
}
```

---

## 5. SOS

### 5.1 Trigger — `POST /api/v1/sos/trigger`

```json
{
  "location": { "latitude": 28.6139, "longitude": 77.2090, "accuracy": 8.5 },
  "message": "Followed by two men on a bike"
}
```

`message` ≤ 280 chars. Coordinates are validated to real ranges. Response is
`201` on a new alert, `200` when one is already ACTIVE (no second SMS/push round).

```json
{
  "success": true,
  "message": "SOS alert created. Your guardians are being notified.",
  "data": {
    "alert": {
      "id": "665f30…",
      "status": "ACTIVE",
      "roomId": "aB3dE9fG7hJk",
      "initialLocation": { "latitude": 28.6139, "longitude": 77.209 },
      "lastLocation": { "latitude": 28.6139, "longitude": 77.209 },
      "lastLocationAt": "2026-10-21T09:30:00.000Z",
      "locationHistory": [
        { "latitude": 28.6139, "longitude": 77.209, "accuracy": 8.5,
          "recordedAt": "2026-10-21T09:30:00.000Z" }
      ],
      "notifiedNomineeIds": ["665f20…", "665f21…"],
      "notifiedCount": 2,
      "notification": null,
      "triggerNote": "Followed by two men on a bike",
      "resolvedAt": null,
      "resolutionNote": null,
      "createdAt": "2026-10-21T09:30:00.000Z",
      "updatedAt": "2026-10-21T09:30:00.000Z"
    },
    "alreadyActive": false,
    "roomId": "aB3dE9fG7hJk",
    "socket": {
      "event": "join_sos_room",
      "room": "sos:aB3dE9fG7hJk",
      "roomId": "aB3dE9fG7hJk"
    }
  },
  "errors": null
}
```

`notification` (push/SMS outcome) fills in asynchronously; fetch
`GET /sos/active` to see it.

### 5.2 Resolve — `POST /api/v1/sos/resolve`

```json
{ "status": "FALSE_ALARM", "note": "Accidental trigger" }
```

`status` is `RESOLVED` (default) or `FALSE_ALARM`; note ≤ 280.

```json
{
  "success": true,
  "message": "SOS alert closed as a false alarm.",
  "data": {
    "alert": {
      "id": "665f30…", "status": "FALSE_ALARM", "roomId": "aB3dE9fG7hJk",
      "initialLocation": { "latitude": 28.6139, "longitude": 77.209 },
      "lastLocation": { "latitude": 28.6141, "longitude": 77.2092 },
      "lastLocationAt": "…", "locationHistory": [ … ],
      "notifiedNomineeIds": ["665f20…"], "notifiedCount": 1,
      "notification": { "attemptedAt": "…",
        "push": { "attempted": 1, "sent": 0, "failed": 1, "skipped": 0 },
        "sms": { "attempted": 1, "sent": 1, "failed": 0, "skipped": 0 } },
      "triggerNote": null, "resolvedAt": "2026-10-21T09:40:00.000Z",
      "resolutionNote": "Accidental trigger",
      "createdAt": "…", "updatedAt": "…"
    }
  },
  "errors": null
}
```

`404 SOS_NONE_ACTIVE` when nothing is open.

### 5.3 Active — `GET /api/v1/sos/active`

```json
{
  "success": true,
  "message": "You have an active SOS alert.",
  "data": {
    "alert": { "id": "665f30…", "status": "ACTIVE", "roomId": "aB3dE9fG7hJk", "…": "…" },
    "socket": { "event": "join_sos_room", "room": "sos:aB3dE9fG7hJk", "roomId": "aB3dE9fG7hJk" }
  },
  "errors": null
}
```

Both `alert` and `socket` are `null` when none is active.

---

## 6. Dashboard — `GET /api/v1/analytics/dashboard?radiusMeters=5000&windowHours=24`

Both query parameters are optional and bounded: `radiusMeters` 100–50000,
`windowHours` 1–168. Repeated parameters are rejected with 400.

```json
{
  "success": true,
  "message": "Dashboard analytics generated.",
  "data": {
    "generatedAt": "2026-10-21T09:45:00.000Z",
    "perimeter": { "armedUsers": 41, "totalUsers": 380, "armedPercent": 11 },
    "alerts": {
      "activeNow": 3,
      "recent": {
        "windowHours": 24,
        "total": 12,
        "byStatus": { "ACTIVE": 3, "RESOLVED": 7, "FALSE_ALARM": 2 }
      },
      "nearby": {
        "available": true,
        "radiusMeters": 5000,
        "count": 2,
        "byStatus": { "ACTIVE": 1, "RESOLVED": 1, "FALSE_ALARM": 0 }
      }
    },
    "readiness": {
      "score": 75,
      "maxScore": 100,
      "level": "moderate",
      "nomineeCount": 2,
      "components": [
        { "key": "nominees", "label": "Guardians on file", "weight": 30,
          "earned": 30, "satisfied": true, "detail": "2 guardians" },
        { "key": "shieldPayPin", "label": "Shield Pay PIN configured",
          "weight": 20, "earned": 20, "satisfied": true },
        { "key": "pushNotifications", "label": "Push notifications registered",
          "weight": 15, "earned": 0, "satisfied": false },
        { "key": "locationSharing", "label": "Location on file",
          "weight": 15, "earned": 15, "satisfied": true },
        { "key": "biometric", "label": "Biometric enrolment",
          "weight": 10, "earned": 0, "satisfied": false },
        { "key": "emergencyMode", "label": "Perimeter armed",
          "weight": 10, "earned": 10, "satisfied": true }
      ]
    },
    "meta": { "radiusMeters": 5000, "windowHours": 24, "userLocationAvailable": true }
  },
  "errors": null
}
```

When the user has no location on file, `nearby` is
`{ "available": false, "radiusMeters": 5000, "count": 0, "byStatus": {…}, "reason": "no_location_on_file" }`.
Nearby is **counts only** — no ids, no coordinates of other people.

---

## 7. Shield Pay

### 7.1 Check — `POST /api/v1/shield-pay/check-upi`

```json
{ "identifier": "paytm-kyc-help@ybl" }
```

`identifier` may be a UPI VPA, a link (`https://…` or bare `host.tld/path`) or a
phone number. `upiId` is accepted as an alias. QR payloads
(`upi://pay?pa=…`) are reduced to the payee.

```json
{
  "success": true,
  "message": "Payee rated DANGER (risk score 78/100).",
  "data": {
    "identifier": "paytm-kyc-help@ybl",
    "identifierType": "UPI",
    "status": "danger",
    "riskLevel": "DANGER",
    "riskScore": 78,
    "reportCount": 64,
    "matchedBy": "flagged_entity",
    "matchedIdentifier": "paytm-kyc-help@ybl",
    "reasonCode": "REPORTED_DANGER",
    "flags": [{ "code": "REPORTED_DANGER", "msg_en": "…", "msg_hi": "…" }],
    "msg_en": "This UPI ID has been reported…",
    "msg_hi": "…",
    "checkedAt": "2026-10-21T09:50:00.000Z",
    "checkId": "665f40…",
    "checkExpiresAt": "2026-10-21T10:05:00.000Z"
  },
  "errors": null
}
```

SAFE verdicts have `checkId: null` and write nothing. For SUSPICIOUS/DANGER,
keep `checkId` — it expires in 15 minutes and is required to proceed.

### 7.2 Proceed — `POST /api/v1/shield-pay/proceed-transaction`

```json
{
  "identifier": "paytm-kyc-help@ybl",
  "amount": 1500,
  "pin": "4821",
  "riskAccepted": true,
  "checkId": "665f40…"
}
```

* `pin` **must be a string** of 4–6 digits (JSON numbers lose leading zeros).
* For a non-SAFE payee you must send both `riskAccepted: true` and a fresh
  `checkId` from `check-upi` for **this** payee. One check = one payment.
* SAFE payees need neither.
* No idempotency key exists: disable the pay button while the request is in
  flight. A retry records a **second** completed transaction.

```json
{
  "success": true,
  "message": "Transaction recorded after the fraud warning was accepted.",
  "data": {
    "auditId": "665f41…",
    "status": "completed",
    "upiId": "paytm-kyc-help@ybl",
    "identifierType": "UPI",
    "amount": 1500,
    "riskLevel": "DANGER",
    "riskScore": 78,
    "risk_accepted": true,
    "pinVerified": true,
    "transactionHash": "a3f9…64 hex…",
    "completedAt": "2026-10-21T09:52:00.000Z",
    "msg_en": "…",
    "msg_hi": "…"
  },
  "errors": null
}
```

Errors: `409 SHIELD_PAY_PIN_NOT_SET`; `401 INVALID_PIN` (wrong PIN, also writes a
REJECTED audit row); `409 RISK_ACKNOWLEDGEMENT_REQUIRED`;
`409 RISK_CHECK_REQUIRED`; `409 RISK_CHECK_EXPIRED` / `RISK_CHECK_ALREADY_USED` /
`RISK_CHECK_MISMATCH` / `RISK_CHECK_INVALID`; `400` for amount/PIN shape.

### 7.3 Set PIN — `POST /api/v1/shield-pay/set-pin`

```json
{ "pin": "4821", "currentPin": "1234" }
```

`currentPin` is required only once a PIN exists. Weak PINs (repeated digits,
sequences, top-30 list, phone suffix) → `400 WEAK_PIN`.

```json
{
  "success": true,
  "message": "Shield Pay PIN saved.",
  "data": { "pinConfigured": true, "hashAlgorithm": "bcrypt", "rounds": 10,
            "updatedAt": "2026-10-21T09:55:00.000Z" },
  "errors": null
}
```

---

## 8. Scam Buster

### 8.1 Text — `POST /api/v1/scam-buster/analyze` (JSON)

```json
{ "text": "Dear customer, your KYC is suspended. Click http://bit.ly/xyz to verify." }
```

### 8.2 Screenshot — `POST /api/v1/scam-buster/analyze` (multipart)

| Part | Type | Notes |
|---|---|---|
| `image` | file | JPEG / PNG / WebP, ≤ **5 MB**, exactly one file |
| `text` | field | optional caption, ≤ 5000 chars |

```dart
final scan = await api.analyzeImage(
  bytes: fileBytes,
  mimeType: 'image/jpeg',
  filename: 'screenshot.jpg',
  text: 'Got this on WhatsApp',
);
```

Send at least one of `image` or `text`. A scan uses AI quota, so the endpoint is
limited to 20 requests / 15 min per IP.

`201`:

```json
{
  "success": true,
  "message": "Scan complete: fraud signals were detected in this message.",
  "data": {
    "scanId": "665f50…",
    "inputType": "IMAGE",
    "imageUrl": "https://res.cloudinary.com/…/guardfi/scam-scans/abc.png",
    "imageStorage": "CLOUDINARY",
    "isScam": true,
    "riskLevel": "DANGER",
    "confidenceScore": 92,
    "explanation_en": "This message impersonates a bank KYC check and links to a phishing site.",
    "explanation_hi": "यह संदेश बैंक KYC के नाम पर…",
    "redFlags": ["asks for KYC", "shortened link", "urgency"],
    "extractedText": "…",
    "analysisSource": "GEMINI",
    "fallbackReason": null,
    "aiModel": "gemini-2.5-flash",
    "analysisMs": 2140,
    "createdAt": "2026-10-21T10:00:00.000Z",
    "checkedAt": "2026-10-21T10:00:02.140Z"
  },
  "errors": null
}
```

`analysisSource` is `GEMINI` or `HEURISTIC`; `fallbackReason` explains a degraded
scan (`AI_TIMEOUT`, `AI_NOT_CONFIGURED`, `AI_RESPONSE_INVALID`, …). Show the
verdict either way — the request succeeds by design. `imageStorage` can be
`CLOUDINARY`, `LOCAL`, `DATA_URI` or `NONE`; `imageUrl` may be `null`.

### 8.3 History — `GET /api/v1/scam-buster/history?limit=20&before=<nextBefore>`

```json
{
  "success": true,
  "message": "Retrieved 2 scan(s).",
  "data": {
    "scans": [
      { "scanId": "665f50…", "inputType": "TEXT", "imageUrl": null,
        "imageStorage": null, "isScam": false, "riskLevel": "SAFE",
        "confidenceScore": 70, "explanation_en": "…", "explanation_hi": "…",
        "redFlags": [], "extractedText": "Hey, are we still on for lunch?",
        "analysisSource": "GEMINI", "fallbackReason": null,
        "aiModel": "gemini-2.5-flash", "analysisMs": 900,
        "createdAt": "2026-10-21T09:59:00.000Z" }
    ],
    "count": 1,
    "hasMore": false,
    "nextBefore": null
  },
  "errors": null
}
```

Pass `nextBefore` back verbatim as `before` for the next page. `limit` 1–50.

---

## 9. Emergency biometric bypass

### 9.1 What the app must sign

The device performs the local biometric check, then signs this exact string with
HMAC-SHA256 using `BIOMETRIC_SHARED_SECRET`:

```
guardfi-biometric-v1|<userId>|true|<verifiedAt epoch ms>|<nonce>
```

* `userId` — `user._id` from login (the JWT `sub`).
* `true` — literal, only when the local check succeeded.
* `verifiedAt` — the **same** instant sent in the body, as epoch milliseconds.
* `nonce` — 16–128 chars of `[A-Za-z0-9_-]`, fresh for every attempt.
* signature — lowercase or uppercase hex (64 chars).

```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';

final verifiedAt = DateTime.now().toUtc();
final nonce = base64Url.encode(List<int>.generate(18, (_) => Random.secure().nextInt(256))).replaceAll('=', '');

final canonical =
    'guardfi-biometric-v1|$userId|true|${verifiedAt.millisecondsSinceEpoch}|$nonce';
final signature = Hmac(sha256, utf8.encode(secret)).convert(utf8.encode(canonical)).toString();

await api.verifyBiometric(
  signature: signature,
  nonce: nonce,
  verifiedAt: verifiedAt,
  platform: 'android',
  deviceId: deviceId,
);
```

Assertions are valid for **120 seconds** (30 s future skew allowed) and each
nonce is single-use — reuse is `409 BIOMETRIC_ASSERTION_REPLAYED`.

### 9.2 Verify — `POST /api/v1/emergency/biometric-verify`

Body:

```json
{
  "success": true,
  "verifiedAt": "2026-10-21T10:05:00.000Z",
  "nonce": "q8Zr2mS1c0V6pQ4t",
  "signature": "9f2c…64 hex…",
  "deviceMetadata": {
    "deviceId": "android-id",
    "platform": "android",
    "appVersion": "1.0.0",
    "model": "Pixel 7",
    "osVersion": "14"
  }
}
```

`platform` must be `android`, `ios`, `web` or `unknown`; the object is strict.

```json
{
  "success": true,
  "message": "Biometric verification accepted. Emergency mode is now active.",
  "data": {
    "user": { "id": "665f1c…", "isEmergencyMode": true, "biometricEnabled": true },
    "emergencyPermissions": {
      "active": true,
      "biometricEnabled": true,
      "actions": ["SOS_TRIGGER", "RESTRICTED_ACTION", "BIOMETRIC_BYPASS"],
      "activatedAt": "2026-10-21T10:05:00.000Z",
      "restrictedActionEndpoint": "/api/v1/emergency/restricted-action",
      "lockEndpoint": "/api/v1/emergency/lock"
    },
    "audit": { "id": "665f60…", "action": "EMERGENCY_MODE_UNLOCKED",
               "createdAt": "2026-10-21T10:05:00.010Z" },
    "alreadyActive": false
  },
  "errors": null
}
```

`201` on first unlock, `200` when already active. Errors: `401`
`BIOMETRIC_SIGNATURE_INVALID`, `401 BIOMETRIC_ASSERTION_EXPIRED`, `403
BIOMETRIC_VERIFICATION_FAILED`, `409 BIOMETRIC_ASSERTION_REPLAYED`, `503`
when the server has no shared secret.

### 9.3 Restricted action — `POST /api/v1/emergency/restricted-action`

Requires emergency mode **in the database** (a token issued before unlock is not
enough).

```json
{ "action": "CONTACT_POLICE", "note": "Near Gate 3" }
```

```json
{
  "success": true,
  "message": "Emergency action permitted.",
  "data": {
    "action": "CONTACT_POLICE",
    "performedAt": "2026-10-21T10:06:00.000Z",
    "emergencyPermissions": { "active": true, "biometricEnabled": true, "…": "…" },
    "audit": { "id": "665f61…", "action": "RESTRICTED_ACTION_PERFORMED",
               "createdAt": "2026-10-21T10:06:00.001Z" }
  },
  "errors": null
}
```

`403` when emergency mode is off.

### 9.4 Lock — `POST /api/v1/emergency/lock`

```json
{
  "success": true,
  "message": "Emergency mode has been locked. Restricted routes are closed again.",
  "data": {
    "user": { "id": "665f1c…", "isEmergencyMode": false, "biometricEnabled": true },
    "emergencyPermissions": { "active": false, "biometricEnabled": true,
                              "actions": [], "activatedAt": null, "…": "…" },
    "audit": { "id": "665f62…", "action": "EMERGENCY_MODE_LOCKED", "createdAt": "…" },
    "alreadyInactive": false
  },
  "errors": null
}
```

### 9.5 Status — `GET /api/v1/emergency/status`

```json
{
  "success": true,
  "message": "Emergency mode is inactive for this account.",
  "data": {
    "user": { "id": "665f1c…", "isEmergencyMode": false, "biometricEnabled": true },
    "emergencyPermissions": { "active": false, "biometricEnabled": true,
                              "actions": [], "activatedAt": null,
                              "restrictedActionEndpoint": "/api/v1/emergency/restricted-action",
                              "lockEndpoint": "/api/v1/emergency/lock" }
  },
  "errors": null
}
```

---

## 10. Global config

### 10.1 Read — `GET /api/v1/config/global` (public)

```json
{
  "success": true,
  "message": "Global configuration served from the in-memory cache.",
  "data": {
    "source": "cache",
    "config": {
      "key": "GLOBAL_CONFIG",
      "privacyPolicyUrl": "https://guardfi.in/privacy",
      "termsUrl": "https://guardfi.in/terms",
      "globalWarningThresholds": {
        "upiRiskScoreThreshold": 70,
        "sosRadiusMeters": 5000,
        "maxNomineesPerUser": 5
      },
      "maintenanceMode": false,
      "emergencyHelplines": [
        { "name_en": "Police", "name_hi": "पुलिस", "number": "112" },
        { "name_en": "Cyber Crime Helpline", "name_hi": "साइबर अपराध हेल्पलाइन", "number": "1930" },
        { "name_en": "Women Helpline", "name_hi": "महिला हेल्पलाइन", "number": "1091" }
      ],
      "version": 4,
      "updatedBy": "665f0000…",
      "createdAt": "2026-10-01T…",
      "updatedAt": "2026-10-20T…"
    }
  },
  "errors": null
}
```

Call this on launch and cache it. Show the helplines from here — do not hard-code
them. In a full outage a cold cache answers `503 CONFIG_STORE_UNAVAILABLE`; keep
the last successful copy on the device.

### 10.2 Update — `PUT /api/v1/config/global` (admin only)

Partial body; at least one field; unknown keys are rejected.

```json
{
  "maintenanceMode": true,
  "globalWarningThresholds": { "sosRadiusMeters": 8000 },
  "emergencyHelplines": [
    { "name_en": "Police", "name_hi": "पुलिस", "number": "112" }
  ]
}
```

Response: `{ "config": { … }, "changedFields": ["maintenanceMode", …],
"previousVersion": 4, "version": 5, "cacheInvalidated": true,
"audit": { "id": "…", "action": "CONFIG_UPDATED", "createdAt": "…" } }`.

---

## 11. Health — `GET /health`

Unversioned. `200` when the API and database are ready, `503` when degraded.
The payload includes `database.connected`, `database.indexesReady` and
`otp` readiness flags. Useful for a status banner; do not show the raw payload
to users.

---

## 12. SOS Socket.io

### 12.1 Connect

```dart
final sos = GuardFiSosSocket(
  baseUrl: 'https://guardfi-backend.onrender.com',
  token: jwt,
)..connect();

sos.errors.listen((e) {
  if (e.isAuthFailure) signOut();
});

await sos.waitUntilConnected();
```

The wrapper sends the JWT as `auth: { token }`. Server failures arrive as
`connect_error` with `data.code`:

| Code | Meaning |
|---|---|
| `AUTH_REQUIRED` | No token in the handshake |
| `AUTH_EXPIRED` | JWT past `exp` |
| `AUTH_INVALID` | Bad signature, bad subject, or deleted account |
| `AUTH_UNAVAILABLE` | Database not ready |

### 12.2 Events

| Direction | Event | Payload |
|---|---|---|
| server → client | `server:ready` | `{ phase: 4, userId, events: ["join_sos_room","location_update","stop_sos"] }` |
| client → server (ack) | `join_sos_room` | `{ alertId }` **or** `{ roomId }` |
| server ack | `join_sos_room` | `{ ok: true, alertId, roomId, status, participants }` |
| server → client | `sos_joined` | same shape as the ack (sent alongside it) |
| client → server (ack) | `location_update` | `{ alertId\|roomId, latitude, longitude, accuracy? }` |
| server ack | `location_update` | `{ ok: true, persisted, recordedAt, roomId }` |
| server → room + owner | `nominee_location_stream` | `{ alertId, roomId, latitude, longitude, accuracy, recordedAt, persisted }` |
| client → server (ack) | `stop_sos` | `{ alertId\|roomId, status: "RESOLVED"\|"FALSE_ALARM", note? }` |
| server ack | `stop_sos` | `{ ok: true, alertId, roomId, status, resolvedAt }` |
| server → room + owner | `sos:stopped` | `{ alertId, roomId, status, resolvedAt, resolvedBy }` |
| server → owner's personal room | `sos:resolved` | same as `sos:stopped` |
| server → owner's personal room | `sos:created` | alert snapshot + `{ alreadyActive }` (from the REST trigger) |
| server → owner's sockets | `account:deleted` | `{ reason: "ACCOUNT_DELETED", at }` — connection closes immediately after |

Acknowledgements that fail send `{ ok: false, code, message, errors? }` — the
wrapper throws `GuardFiSocketException`. Codes you may see:
`VALIDATION_FAILED`, `SOS_NOT_FOUND`, `SOS_INACTIVE`, `SOS_FORBIDDEN`,
`SOS_RATE_LIMITED`, `SOS_INTERNAL`.

### 12.3 Flow — victim

```dart
final trigger = await api.triggerSos(latitude: lat, longitude: lng, accuracy: 6);
final room = await sos.joinRoom(alertId: trigger.alert.id); // or roomId:
sos.locations.listen((p) => debugPrint('guardian sees ${p.latitude},${p.longitude}'));

// Pipe the GPS stream; 5 packets/s max.
final sub = sos.broadcastPositions(positionStream.map(
  (p) => SosCoordinates(latitude: p.latitude, longitude: p.longitude, accuracy: p.accuracy),
));

// On "I'm safe":
await sos.stopSos(status: SosStopStatus.resolved);
await sub.cancel();
```

`persisted: false` in a location ack means "broadcast, not written to MongoDB"
(the 5-second persistence throttle). The guardian still received it. Do not
retry.

### 12.4 Flow — guardian

The guardian gets the SMS with the 12-char room code, or `sos:created` on their
own socket if the app is open:

```dart
final roomId = 'aB3dE9fG7hJk';
final joined = await sos.joinRoom(roomId: roomId);
sos.locations.listen((p) {
  map.animateMarker(p.latitude, p.longitude);
});
sos.stopped.listen((event) => showAlertEnded(event.status));
```

A guardian is a `Nominee` whose phone equals the authenticated user's phone. A
stranger with a leaked room code is refused (`SOS_FORBIDDEN`). Guardians cannot
send `location_update` or `stop_sos`.

### 12.5 Reconnection

The server drops rooms on disconnect, so the wrapper re-joins the active room
automatically after a reconnect (`sos_joined` fires again). No action needed.
Server limits: 25 concurrent sockets per IP, 2000 total, 1 MB max frame.

---

## 13. Platform gotchas

1. **Store the JWT in `flutter_secure_storage`**, not `SharedPreferences`.
   It is a 7-day credential with no revocation UI.
2. **Handle 401 globally**: clear the token and route to login. A deleted account
   also answers 401.
3. **No idempotency on payments.** Disable the pay button while in flight; a
   double tap records two completed transactions.
4. **PINs are strings.** `"0123"` must not be serialised as `123`.
5. **OTP is a 6-digit string**, and a code is locked after 3 wrong attempts.
   Request a new code rather than retrying.
6. **`sender`/message text is untrusted** — never render HTML from
   `extractedText` or `explanation_*`.
7. **Guardian phone numbers are unverified** at add time. Say so in the UI: the
   SMS is the only proof the number is reachable.
8. **`DELETE /account` is irreversible** and needs no second factor beyond the
   JWT. Gate it behind an "are you sure" screen that requires typing `DELETE`.
9. **Location updates**: send at most 5/s. The wrapper's default
   `minLocationInterval` already enforces that.
10. **`maintenanceMode` in `/config/global`** is a client hint: show a banner and
    disable writes when true. (The server does not block requests for you.)

---

## 14. Quick cURL smoke test

```bash
BASE=https://guardfi-backend.onrender.com/api/v1

# 1. dev-mode OTP (returns the code in the body when the server has OTP_DEV_MODE on)
curl -s -X POST $BASE/auth/send-otp \
  -H 'Content-Type: application/json' \
  -d '{"phone":"+919876543210"}'

# 2. exchange it for a JWT
TOKEN=$(curl -s -X POST $BASE/auth/verify-otp \
  -H 'Content-Type: application/json' \
  -d '{"phone":"+919876543210","otp":"123456"}' | jq -r '.data.token')

# 3. authenticated call
curl -s $BASE/nominees/list -H "Authorization: Bearer $TOKEN" | jq
```

---

## 15. Verification status

* The REST and socket contracts above were read from the route/validator/service
  code (not from memory) and match the passing Phase 1–10 + account-deletion
  suites (370 checks).
* The Dart files were **not compiled** here: this machine has no Dart/Flutter
  SDK. They are written for null-safety and the current package APIs, but run
  `flutter analyze` after dropping them in — treat any analyzer finding as a bug
  in the file, not in the server.
