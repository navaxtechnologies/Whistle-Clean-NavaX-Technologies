# Phase 6 — Bookings & Inquiries → Email + Google Sheets + Google Calendar

**Goal:** every contact-form inquiry **and** every Calendly booking lands in three places automatically:
1. An email to **whistleclean100@gmail.com**
2. A row in a **Google Sheet** (the lead log)
3. A **Google Calendar** event

**How it works:**
- The website contact form posts to the site's server (`/api/quote`), which forwards it (with a secret token) to a **Google Apps Script Web App**. That script emails, logs to the Sheet, and creates a calendar follow-up.
- **Calendly bookings** use Calendly's **native Google Calendar sync + email confirmations**, and *also* fire a **Calendly webhook** to the same Apps Script so the booking is logged into the same Sheet.

> Do all of this signed in to Google as **whistleclean100@gmail.com** so the Sheet, emails, and calendar all belong to that account.

---

## Part A — Create the Apps Script Web App (the engine)

1. Go to **https://sheets.google.com** → **Blank spreadsheet**. Name it `Whistle Clean — Leads`.
2. In that sheet: **Extensions → Apps Script**. Delete the default `myFunction` code.
3. Open `integrations/whistle-clean-apps-script.gs` from this project, copy **all** of it, and paste it into the Apps Script editor.
4. At the top of the script, change:
   - `var SECRET = 'CHANGE_ME_to_a_long_random_string';` → a long random string (e.g. mash 30+ letters/numbers). **Save this string** — you'll reuse it. Call it `YOUR_SECRET`.
   - Confirm `NOTIFY_EMAIL` is `whistleclean100@gmail.com`.
5. Click **Save** (💾).
6. Click **Deploy → New deployment**. Gear icon → **Web app**. Set:
   - **Description:** Whistle Clean handler
   - **Execute as:** **Me (whistleclean100@gmail.com)**
   - **Who has access:** **Anyone**
   - Click **Deploy**, then **Authorize access** and approve the permissions (Sheets, Gmail, Calendar). Google may warn "unverified app" → **Advanced → Go to (project) → Allow** (safe — it's your own script).
7. Copy the **Web app URL** (looks like `https://script.google.com/macros/s/AKfyc.../exec`). Call it `YOUR_WEBAPP_URL`.

**Test it now:** paste this in a terminal (replace both placeholders):
```bash
curl -X POST "YOUR_WEBAPP_URL" -H "Content-Type: application/json" \
  -d '{"token":"YOUR_SECRET","type":"inquiry","name":"Test Lead","email":"test@example.com","phone":"210-555-0000","service":"apartment","date":"2026-07-01","message":"Just testing"}'
```
You should get `{"ok":true,...}`, a new row in the Sheet, an email to whistleclean100@gmail.com, and a calendar event on July 1.

---

## Part B — Connect the website server

In **Railway → your project → Variables** (and in local `.env` for testing), set:

| Variable | Value |
|---|---|
| `QUOTE_WEBHOOK_URL` | `YOUR_WEBAPP_URL` |
| `QUOTE_WEBHOOK_TOKEN` | `YOUR_SECRET` (the exact string from the script) |

Redeploy (Railway auto-redeploys on save). Now every contact-form submission flows through to email + Sheet + Calendar. The token stays on the server — it's never exposed in the browser.

---

## Part C — Calendly bookings → Google Calendar + email (native)

1. In **Calendly → Account → Integrations → Google Calendar** → **Connect**, sign in as whistleclean100@gmail.com. This makes every booking:
   - appear on the Google Calendar automatically, and
   - send email confirmations to you and the customer.
2. Make sure the website's `/book` page points at the real Calendly link (set `VITE_CALENDLY_URL` in Railway).

That alone covers **calendar + email** for bookings. Part D adds bookings to the **Sheet** too.

---

## Part D — Calendly bookings → the same Google Sheet (webhook)

This logs bookings into the same lead Sheet as inquiries.

> **Requires a Calendly plan that supports Webhooks (Standard or higher).** On the free plan, skip this — or use Calendly's built-in **Zapier/Google Sheets** integration instead. Bookings still hit Calendar + email via Part C regardless.

Register the webhook with Calendly's API (one-time). You need a **Personal Access Token** from Calendly → Integrations → API & Webhooks, and your **organization URI** (from the same page or `GET https://api.calendly.com/users/me`).

```bash
curl -X POST "https://api.calendly.com/webhook_subscriptions" \
  -H "Authorization: Bearer CALENDLY_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "YOUR_WEBAPP_URL?token=YOUR_SECRET",
    "events": ["invitee.created"],
    "organization": "https://api.calendly.com/organizations/XXXXXXXX",
    "scope": "organization"
  }'
```

Note the `?token=YOUR_SECRET` on the URL — that's how the script authorizes the Calendly webhook (Calendly can't send a JSON token field). When someone books, Calendly posts to the script, which appends a `booking` row to the Sheet (and emails you, unless you set `EMAIL_ON_BOOKING = false` to avoid duplicating Calendly's own confirmation).

---

## What the client ends up with

| Channel | Email to whistleclean100 | Google Sheet row | Google Calendar event |
|---|---|---|---|
| **Contact-form inquiry** | ✅ (script) | ✅ (script) | ✅ follow-up (script) |
| **Calendly booking** | ✅ (Calendly + script) | ✅ (webhook, Part D) | ✅ (Calendly native) |

## Tuning (top of the Apps Script)
- `CREATE_EVENT_FOR_INQUIRIES` — set `false` if you don't want calendar events for form inquiries.
- `EMAIL_ON_BOOKING` — set `false` so Calendly is the only booking email.
- `CALENDAR_ID` — use a specific calendar's ID instead of `'primary'` to keep leads on a separate calendar.
- `SHEET_NAME` — the tab name for the log (default `Leads`).

## Security & notes
- The shared `SECRET`/token blocks random spam to the Web App URL. Keep it private.
- Apps Script free quotas (email/day, etc.) are far above a local cleaning business's volume.
- If you ever rotate the secret, update it in **both** the script and the Railway variables (and the Calendly webhook URL).
