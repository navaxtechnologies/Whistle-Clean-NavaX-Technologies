# Whistle Clean — CONTEXT HANDOFF
_Last updated: 2026-07-08. Optimized for an AI to resume immediately._

# Mission
Grow **Whistle Clean** (San Antonio family INTERIOR-cleaning business: apartment/move-out/office/laundry + recurring "Property Manager" plan) by landing **recurring B2B cleaning contracts** (unit turnovers / move-out cleans) with property managers, and keep the website booking/lead system running. Executed by Mauricio/NavaX on behalf of the family (owners: Jose Romero; operator receiving jobs: Fabrizio Romero).

# Current State
15 personalized **cold emails SENT** 2026-07-08 ~1:30pm CT to SA property managers, from `whistleclean100@gmail.com` via the **Superhuman MCP connector** (connector is on `navaxtechnologies@gmail.com`; `whistleclean100` added as verified Gmail send-as). Only response so far = 1 **auto-responder** (Flat Fee Landlord — ignore). 14 pending. Booking system live. Now in reply/follow-up phase.

# Completed
- Calendly event **"Cleaning Estimate"** live: `calendly.com/navaxtechnologies/cleaning-estimate` (30 min, outbound phone call, bilingual EN/ES confirmation text).
- Website `/book` pointed at real Calendly link — committed+pushed to `main` (commit `22f0748`), Railway auto-redeployed, verified live.
- Gmail **send-as `whistleclean100@gmail.com` verified** (required App Password + SMTP smtp.gmail.com:465; Superhuman had to re-sync to see it).
- Prospect research: ~33 verified SA prospects (8 first batch + 25 expanded); emails scraped from company sites (never fabricated).
- **15 cold emails written + SENT** (plain text, CAN-SPAM footer w/ Blanco Rd addr + opt-out, CTA "call Fabrizio (210) 859-4422", no website link, no images).
- Reply playbook (4 scenarios) + follow-up #2 copy written (not yet sent).
- Side work: created skill `building-agent-skills`; added "don't gate reviews" caveat to `local-business-growth`; saved memory `feedback-skills-commodity-vs-proprietary`.

# In Progress
- Monitoring inbox for real replies (manual/ping-based — no live listener).
- Follow-up #2 queued for ~day 3–4 (≈2026-07-11 to 07-14) to non-responders only.

# Next Actions
1. Check `whistleclean100` inbox for replies → draft on-brand responses (playbook ready).
2. Day 3–4: send **threaded** follow-up to non-responders only (nobody double-tapped).
3. Write **phone/form scripts** for 7 no-email prospects: **SYLIS (top fit)**, RPM Alamo, Tarantino, BMG (ask for Edith Lopez, Dir PM), CloverLeaf, Valiant, Green Residential.
4. (Optional) Build Make.com automation: reply detected → auto-acknowledge + booking link + SMS Fabrizio.
5. Verify emails for "Group C" (10 more named prospects: FirstService, SYNC, Alliance, Univest, DB Broker, Ziprent, Coldwell Banker D'Ann Harper, Neal & Neal, Emery Group, Kuper Sotheby's).

# Decisions Made
- **Send-from = `whistleclean100@gmail.com`** (send-as on NavaX Superhuman) so replies reach family. Set **reply-to = whistleclean100** (CONFIRM it's set).
- **CTA phone = Fabrizio (210) 859-4422** (owner's explicit instruction). ⚠️ Conflicts with marketing collateral (210-414-5688) and prior memory (Fabrizio=323-9752). Unresolved.
- Cold email = **plain text, no images, no website link**, CAN-SPAM footer. (Images/website reserved for social + follow-ups + in-person.)
- Booking on **NavaX Calendly** for now; shared availability w/ NavaX "Free Strategy Call" accepted. Full separation later via **GoHighLevel**.
- Fabrizio booking alerts via **free Google Calendar share** (Calendly free has no SMS/workflows). "Whistle Clean Jobs" Google Calendar CREATED; sharing + Calendly-connect are owner's OAuth tasks (not done).
- **Do NOT auto-send AI replies to prospects** (reputation risk) — auto-acknowledgment only.
- House rule: adopt commodity skills, build only proprietary/moat skills.

# Architecture
- **Outreach:** Superhuman MCP (on navaxtechnologies@gmail.com) → sends AS whistleclean100 → replies to whistleclean100 inbox; calls → Fabrizio's phone.
- **Booking:** Site `/book` (React/Vite/Express) → Calendly inline embed → Calendly event → (future) Google Calendar "Whistle Clean Jobs" + Fabrizio notification.
- **Hosting:** Railway (project "carefree-amazement"), deploys from GitHub `main`.

# Folder Structure
- Project root: `C:\Users\Navas\Downloads\Business\Whistle Clean\whistle-clean (3)\whistle-clean (2)` (React 19 + Vite + Express).
  - `client/src/pages/Book.tsx` — Calendly embed (URL fallback = real link).
  - `growth-plan/` — strategy docs + `overnight-research/` (audit, 90-day plan, financials).
  - `integrations/whistle-clean-apps-script.gs` — lead pipeline (Calendly/contact → Sheet/email).
  - `CONTEXT-HANDOFF.md` — this file.
- GitHub: `navaxtechnologies/Whistle-Clean-NavaX-Technologies` (branch `main`).
- Memory: `C:\Users\Navas\.claude\projects\C--Users-Navas-Downloads-navax-technologies\memory\whistle-clean-case-study.md` (fullest running state).

# APIs
- **Superhuman connector** (MCP): `create_or_update_draft`, `send_draft`, `query_email_and_calendar`. Account: navaxtechnologies@gmail.com. Send-as whistleclean100 verified. May be unavailable in headless/cron runs.
- **Calendly**: navaxtechnologies account, FREE plan (no workflows/automated SMS).
- **Railway**: hosting/deploy.
- **Make.com**: available (owner has experience) for future reply-automation.
- **Google Calendar**: "Whistle Clean Jobs" calendar created (NavaX Google acct).

# Important Files
- `client/src/pages/Book.tsx` (Calendly link default: `calendly.com/navaxtechnologies/cleaning-estimate`).
- `growth-plan/06-integrations-setup.md`, `07-railway-deploy.md`.
- Memory file `whistle-clean-case-study.md`.

# Constraints
- AI cannot handle user passwords or OAuth (Google login, calendar sharing = owner's tasks).
- Calendly free = no SMS/workflows.
- Cold-email deliverability: `whistleclean100` is a NEW sending identity — **space future sends ~5/day**.
- Never fabricate prospect emails; verify from sources.
- CAN-SPAM compliance required on all cold mail.
- Superhuman connector may not work in scheduled/background runs.

# Bugs
- **whistlecleantexas.com does NOT resolve** (dead/unpointed) — do not link it anywhere live.
- **Phone-number inconsistency** unresolved: 859-4422 (used) vs 414-5688 (marketing/QR) vs 323-9752 (old memory as Fabrizio).
- **reply-to** on send-as: confirm = whistleclean100 (else replies land in NavaX inbox).
- Superhuman write calls intermittently time out ("server not responding") — retry succeeds, no duplicates.

# Open Questions
- Which number is actually Fabrizio's / correct for the CTA?
- Is reply-to set to whistleclean100?
- Register + point whistlecleantexas.com (or use Railway URL / custom domain)?
- When to migrate booking to GoHighLevel for full NavaX separation?

# Ideas Backlog
- Make.com: reply → auto-ack + booking link + SMS Fabrizio (safe automation; keep substantive replies human).
- Use the 5 Whistle Clean marketing graphics for social posts, follow-up touches, and an in-person flyer/leave-behind.
- Reusable **template**: "PM turnover-cleaning cold email" (params: contact name, segment = SF/multifamily/STR/commercial).
- Reusable **framework**: prospect pipeline = find → verify email (site scrape) → personalized draft → send (send-as, spaced) → monitor → threaded follow-up.
- Move Whistle Clean to its own Calendly account or GHL calendar (separation from NavaX).
- Verify Group C (10 more prospects); add realtor + STR-manager segments.

# Recommended First Task
Open the `whistleclean100` inbox and check for real replies. If any → draft a response from the playbook (esp. the "send me a quote" path) for owner approval. If none → write the 7 phone-call scripts (lead with **SYLIS**) so Fabrizio can dial while emails marinate, and confirm (a) the correct Fabrizio phone number and (b) that reply-to = whistleclean100.
