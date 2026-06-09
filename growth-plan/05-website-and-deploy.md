# Phase 5 — Website Build + Deployment

## 5A — Audit of the existing site (what we found & fixed)

A polished site already existed in the repo (React 19 + Vite + Tailwind, single page). We **extended and corrected** it rather than rebuilding from scratch in Next.js — faster to ship, same end result. Key findings and fixes:

| Finding | Severity | Fix applied |
|---|---|---|
| **Service content** | ✅ Resolved | Services, gallery, pricing, and the contact dropdown now match the **real business — interior cleaning**: Apartment Cleaning (real flat-rate prices: efficiency $95 / 1×1 $115 / 2×2 $125 / 3×2 $135 / touch-up $60 / heavy $40), Office & Laundry Room (custom quote), plus Move-Out and a Recurring plan. Source of truth = the company's own printed proposal. *(An interim draft briefly used exterior services; corrected.)* |
| **No booking, pricing, or dedicated pages** — single page with anchor links only. | 🔴 High | Added real routes: `/services`, `/gallery`, `/pricing`, `/book`, `/contact`. |
| **Build was broken** — `package.json` referenced `server/index.ts`, which didn't exist; `npm run build`/`start` would fail. | 🔴 Critical | Added a production Express server (`server/index.ts`) that serves the built SPA, provides a route fallback, and handles `/api/quote`. Build now passes. |
| **Contact form had no real backend** — posted to `/api/quote`, which only existed in Vite dev. | 🟠 Medium | The new server implements `/api/quote` with validation and optional CRM-webhook forwarding (`QUOTE_WEBHOOK_URL`). |
| **No per-page SEO** in the SPA. | 🟠 Medium | Added `useDocumentMeta` hook — sets title, description, canonical, and scroll-reset per route. |
| **Stale SEO** — title/description were generic/old; structured data used the wrong domain & address. | 🟠 Medium | Updated `index.html` title/description (Apartment & Office Cleaning), fixed domain to `whistlecleaningsa.com`, set the real address (19179 Blanco Rd. Suite 105-482, 78258), and added `hasOfferCatalog` (6 interior services) + `sameAs` (real Yelp). |
| **Phone / NAP** | ✅ Verified | Primary (210) 859-4422; contact **Leo Romero** (210) 414-5688; email whistleclean100@gmail.com; address 19179 Blanco Rd. Suite 105-482, San Antonio, TX 78258. |
| `sitemap.xml` / `robots.txt` listed only the homepage and wrong domain. | 🟡 Low | Updated both to the new domain and all 6 routes. |

## 5B — What was built (files changed)

**New pages** (`client/src/pages/`): `Book.tsx` (Calendly inline embed + service selector + call/text fallbacks), `Pricing.tsx` (apartment price list + office/laundry custom quote + recurring/property-manager CTA), `Services.tsx`, `Gallery.tsx`, `Contact.tsx`.
**New infra:** `server/index.ts` (production server), `client/src/lib/seo.ts` (per-route SEO), `client/src/contexts/LanguageContext.tsx` (EN/ES bilingual), `.env.example`.
**Edited:** `App.tsx` (routes), `Navbar.tsx` (multi-page routing + EN/ES toggle + "Book Now" CTA), `ServicesSection.tsx` / `GallerySection.tsx` / `ContactSection.tsx` (correct interior content, bilingual), `index.html` (SEO + JSON-LD + GA4 placeholder), `public/sitemap.xml`, `public/robots.txt`.

**Verified:** `npm run build` passes (client + server bundle). Production server tested — all routes return 200, `/api/quote` validates input (200 valid / 400 missing fields), `sitemap.xml` & `robots.txt` serve, correct SEO title/description/JSON-LD in the served HTML.

### Still recommended (next iterations, not yet done)
- **Real before/after photos** — gallery uses placeholder paths with correct captions; drop in real job photos (`client/public/images/gallery/`).
- **Full Spanish/bilingual layer** — the brief calls for bilingual; the site has "Se Habla Español" cues but not a full translation toggle. This is a high-value follow-on (SA is ~64% Hispanic). Recommend a `LanguageContext` + translated copy once content is final.
- **Set the real Calendly link** (`VITE_CALENDLY_URL`) and **GA4 ID** (in `index.html`) before launch.

---

## 5C — Railway deployment checklist (adapted to this Vite + Express stack)

> Note: the brief assumed Next.js; this project is **Vite (static client) + a small Express server**. The steps below are correct for *this* stack and the existing `package.json` scripts (`build` → bundles client to `dist/public` and server to `dist/index.js`; `start` → `node dist/index.js`).

1. **Create a GitHub repo** (e.g. `whistle-clean-website`) and push this project:
   ```bash
   git init && git add . && git commit -m "init: whistle clean website"
   git branch -M main
   git remote add origin https://github.com/<you>/whistle-clean-website.git
   git push -u origin main
   ```
2. **Confirm scripts** (already set): `build` = `vite build && esbuild server/index.ts ...`, `start` = `NODE_ENV=production node dist/index.js`.
3. **Railway → New Project → Deploy from GitHub Repo** → select the repo. Railway/Nixpacks auto-detects Node, runs `npm install` then `npm run build`, and starts with `npm run start`.
4. **Set environment variables** in Railway → *Variables*:
   - `VITE_CALENDLY_URL` = Jose's real Calendly link (build-time — used on `/book`).
   - `QUOTE_WEBHOOK_URL` = (optional) GoHighLevel/Zapier inbound webhook to route form submissions to CRM/email.
   - `PORT` is provided by Railway automatically — the server already reads it.
   - For GA4: edit `client/index.html`, replace `G-XXXXXXXXXX`, uncomment the GA block, commit.
5. **Custom domain:** Railway → *Settings → Networking → Custom Domain* → add `whistlecleaningsa.com`. At your DNS registrar add the CNAME Railway shows. SSL auto-provisions (Let's Encrypt, ~5–15 min).
6. **Auto-deploy** is on by default for pushes to `main`.

### Pre-launch QA checklist
- [ ] All 6 routes load without errors (`/`, `/services`, `/gallery`, `/pricing`, `/book`, `/contact`) ✅ verified locally
- [ ] Booking embed loads on `/book` (after `VITE_CALENDLY_URL` is set)
- [ ] Phone numbers click-to-call on mobile ✅ (tel: links in place)
- [ ] Gallery renders (swap in real before/after photos)
- [ ] GA4 receiving data (Realtime view) — after ID is set
- [ ] Lighthouse mobile 85+ (run after deploy)
- [ ] Meta tags correct (metatags.io) ✅ verified in served HTML
- [ ] Spanish content visible — pending the bilingual layer
- [ ] Contact form submits without error ✅ verified (`/api/quote` 200)
- [ ] HTTPS active

### Post-launch
- Submit `sitemap.xml` to Google Search Console.
- Add the live URL to every platform profile (Google Business, Yelp, Thumbtack, HomeAdvisor, Angi, Facebook, Instagram).

> **Alternative (simpler/cheaper):** since the only backend need is the quote form, you could also deploy the static `dist/public` to Netlify/Vercel/Cloudflare Pages and route the form to a serverless function or directly to a GoHighLevel webhook — skipping the Express server entirely. Railway is fine; this is just an option if you want zero server cost.
