# GuardFi — Manual Checklist for the Founder

Everything the code can do is already done and verified. This file lists **only the external actions a coding agent cannot perform for you** — accounts, dashboards, secrets, pushes and the Flutter handoff — with the exact values to copy-paste.

---

## 1. External API keys (5–10 minutes, all free tiers)

| # | Service | Where | What to do with the value |
|---|---|---|---|
| 1.1 | **Gemini (AI)** | https://aistudio.google.com/apikey → *Create API key* | Paste into `.env` as `GEMINI_API_KEY=…` (and into Render/Railway env vars). Without it, Scam Buster answers with the deterministic offline verdict instead of failing — so this is an upgrade, not a blocker. |
| 1.2 | **Cloudinary** | https://console.cloudinary.com → *Product Environment Credentials* | Copy the three values: `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`. Without them screenshots are stored on local disk, which is ephemeral on a deployed host. |
| 1.3 | **Firebase (push, optional)** | https://console.firebase.google.com → Project settings → *Service accounts* → *Generate new private key* | Copy `project_id` → `FIREBASE_PROJECT_ID`, `client_email` → `FIREBASE_CLIENT_EMAIL`, `private_key` → `FIREBASE_PRIVATE_KEY` (keep the quotes and the `\n` escapes). Without it SOS falls back to SMS. |
| 1.4 | **SMS for real OTPs (optional for the demo)** | https://console.twilio.com or https://www.fast2sms.com | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE_NUMBER`, or `FAST2SMS_API_KEY`. For the hackathon demo you can leave these empty and keep `OTP_DEV_MODE=true`, which returns the OTP in the API response. |
| 1.5 | **Biometric HMAC secret** | Your terminal | Run this and copy the value into `.env` **and** into the Flutter build: |

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# BIOMETRIC_SHARED_SECRET=<paste the 64 hex characters>
```

The server refuses to unlock emergency mode (HTTP 503) while this is missing — deliberately, because an unsigned `{"success": true}` from the wire must never be trusted. One value, two places: server env and the phone app.

---

## 2. MongoDB Atlas (one-time, ~5 minutes)

1. **Allow this machine's IP**: cloud.mongodb.com → your project → **Security → Network Access → Add IP Address → Add Current IP Address**. If startup logs `MongooseServerSelectionError` or a TLS alert, this is almost always the cause — run `npm run diagnose:atlas` to see the exact failing layer.
2. **Connection string**: **Connect → Drivers** → copy the full URI **including the database name in the path** (`…mongodb.net/guardfi?retryWrites=true&w=majority`) into `MONGO_URI`.
3. **Seed the demo data** (run once from your machine, it is idempotent):

```bash
npm run seed:demo
```

4. **Indexes**: nothing to do. They are created automatically outside production. On a deployed production service the indexes must be created once — run the seeder or any verification script from your machine against the same cluster, or temporarily unset `NODE_ENV=production` for the first boot.

---

## 3. GitHub push (you must run these — the agent does not push)

```bash
cd path/to/guard_fi_project
git init -b main
git add .
git status          # ← CHECK: .env must appear in the "not staged" ignore list, never in the add list
git commit -m "GuardFi backend — Phases 1–10"
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

If `.env` ever shows up in `git status` as a tracked file, stop and run `git rm --cached .env` before pushing. `.gitignore` already covers `.env`, `node_modules/`, `uploads/`, `*.pem`, `*.key` and `firebase-service-account*.json`.

---

## 4. Deploy on Render (free tier, ~10 minutes)

1. Render Dashboard → **New → Blueprint** → pick the repo. `render.yaml` is already in the repository, so Render fills in the build/start commands and the health check automatically.
2. Paste the `sync: false` secrets when Render asks for them (Dashboard → your service → **Environment**):

```
MONGO_URI                 mongodb+srv://…/guardfi?retryWrites=true&w=majority
JWT_SECRET                (click "Generate" — or reuse your local one)
GEMINI_API_KEY            AIza…
CLOUDINARY_CLOUD_NAME     your-cloud
CLOUDINARY_API_KEY        123456789012345
CLOUDINARY_API_SECRET     xxxx…
BIOMETRIC_SHARED_SECRET   (the 64 hex characters from step 1.5)
FIREBASE_PROJECT_ID       (optional)
FIREBASE_CLIENT_EMAIL     (optional)
FIREBASE_PRIVATE_KEY      (optional)
```

3. **CORS**: replace `CORS_ORIGINS=*` with your real origins before launch, e.g. `https://app.guardfi.in,https://guardfi-admin.vercel.app`. With `*`, credentialed CORS is automatically disabled — fine for a demo, wrong for production.
4. **Trust proxy** is already `1` in `render.yaml`, which is what makes per-IP rate limits and `req.ip` audit logging see the real client behind Render's proxy. If you deploy somewhere else, set `TRUST_PROXY=1` there too.
5. **WebSockets** need no extra setting: Socket.io upgrades on the same port. Verify after deploy by opening the API base URL + `/health` → `{"success": true, …}`.
6. Free instances sleep after 15 minutes idle; the first request afterwards takes ~30 seconds. Use **Railway** (same `Procfile`) if you need the demo always-on, or upgrade the Render plan for demo day.

**Railway alternative**: New Project → Deploy from GitHub → Railway reads the `Procfile` (`web: node server.js`) → add the same environment variables → it sets `PORT` itself.

---

## 5. Postman (import, 2 minutes)

1. Import both files: `docs/GuardFi.postman_collection.json` and `docs/GuardFi.postman_environment.json`.
2. Select the **GuardFi Backend — Local** environment.
3. Set `base_url` to `http://localhost:3000`, or to your Render URL for a deployed run.
4. Set `biometric_secret` to the same value as `BIOMETRIC_SHARED_SECRET`.
5. Run folder **01 · Auth** first — it stores `{{jwt_token}}` for every later request automatically. Folder **07 · Emergency** signs its own biometric assertion, so no extra work is needed there.

---

## 6. Flutter handoff (for whoever builds the app)

| What | Value |
|---|---|
| REST base URL (emulator on the same laptop) | `http://10.0.2.2:3000` (Android emulator) or `http://localhost:3000` (iOS simulator) |
| REST base URL (physical phone on the same Wi-Fi) | `http://<your-laptop-LAN-IP>:3000` — find it with `ipconfig` (Windows) / `ifconfig` (macOS) |
| REST base URL (deployed) | `https://guardfi-backend.onrender.com` (your Render URL) |
| Socket.io URL | the same base URL; connect with `auth: { token }` |
| Demo login | phone `+919876500001`, then the OTP returned in the `/send-otp` response while `OTP_DEV_MODE=true` |
| Demo Shield Pay PIN | `4821` (already configured on the seeded account) |
| Biometric signing string | `guardfi-biometric-v1\|<userId>\|true\|<verifiedAtEpochMs>\|<nonce>` signed with HMAC-SHA256 using `BIOMETRIC_SHARED_SECRET`; send `{ success, verifiedAt, nonce, signature, deviceMetadata }` to `POST /api/v1/emergency/biometric-verify` |

Android emulator note: `10.0.2.2` is the host machine's loopback. A physical phone cannot reach `localhost` — use the LAN IP, and make sure your firewall allows port 3000.

---

## 7. Demo-day script (5 minutes, in order)

1. `npm run seed:demo` against the deployed database (or locally).
2. `POST /api/v1/scam-buster/analyze` with the fake KYC message → DANGER verdict in English + Hindi.
3. `POST /api/v1/shield-pay/check-upi` with `paytm-kyc-help@ybl` → "Fraud Alert" and a risk check.
4. `POST /api/v1/sos/trigger` → guardians notified, live location room opened.
5. `POST /api/v1/emergency/biometric-verify` (Postman folder 07 does the signing) → then `/restricted-action` succeeds, `/status` shows the audit trail.
6. `GET /api/v1/config/global` twice → `source: "database"` then `source: "cache"`; `PUT` as an admin → back to `database`.

---

## 8. Things that are intentionally NOT done for you

- **Pushing to GitHub / deploying** — you must trigger those (sections 3–4).
- **Paying for services** — every step above works on a free tier; production Cloudinary/Firebase/Twilio plans are your call.
- **App-store or Play-store signing** — out of scope.
- **Real device attestation (Play Integrity / App Attest)** — the current biometric assertion is an HMAC shared secret. It blocks a `curl`-and-forge attack; a rooted device could still extract the key. Upgrade before handling real money.
