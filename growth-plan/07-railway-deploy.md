# Phase 7 — Railway Deployment (current, click-by-click)

This repo is **deploy-ready** for Railway: `railway.json` sets the builder + start command, `.node-version` pins Node 22, and `package.json` declares `engines.node >=20.19` (Vite 7 needs it). Railway builds with `npm run build` (Vite → `dist/public`, esbuild → `dist/index.js`) and runs `npm run start`, which serves the SPA + the `/api/quote` endpoint and reads `PORT` automatically.

> **CNAME note:** the repo contains a `CNAME` file (it was set up for GitHub Pages). Railway ignores it. **Don't run GitHub Pages and Railway on the same domain** — point `whistlecleaningsa.com`'s DNS at whichever host actually serves the app (Railway, since this app needs a server). GitHub Pages can't run the contact-form backend.

---

## Option A — Railway Dashboard (recommended: gives auto-deploy on every push)

1. Go to **railway.app** → sign in → **New Project** → **Deploy from GitHub repo**.
2. Authorize Railway for the **navaxtechnologies** GitHub account if prompted, then pick **`Whistle-Clean-NavaX-Technologies`**, branch **`main`**.
3. Railway auto-detects the config and starts building. (Build = `npm run build`, Start = `npm run start`, Node 22 — all already pinned in the repo.)
4. **Variables** tab → add:
   | Variable | Value |
   |---|---|
   | `VITE_CALENDLY_URL` | the real Calendly link (used on `/book`) |
   | `QUOTE_WEBHOOK_URL` | the Apps Script Web App URL (see `06-integrations-setup.md`) |
   | `QUOTE_WEBHOOK_TOKEN` | the same secret as the Apps Script `SECRET` |

   `PORT` is provided automatically — do **not** set it.
   > `VITE_CALENDLY_URL` is read at **build time**, so after you set/change it, trigger a redeploy.
5. **Settings → Networking → Generate Domain** to get a free `*.up.railway.app` URL and test immediately. For the real domain: **Custom Domain → add `whistlecleaningsa.com`**, then at your DNS registrar add the **CNAME** Railway shows. SSL provisions automatically (~5–15 min).
6. Auto-deploy is on by default — every push to `main` redeploys.

---

## Option B — Railway CLI (if you'd rather I drive it)

The CLI is installed (v4.66) but **not logged in**, and `railway login` needs a browser, so I can't run it for you. If you want this path:

1. **You run once**, in your terminal in the project folder:
   ```bash
   railway login
   ```
2. Tell me when that's done. Then I can run:
   ```bash
   railway init            # or: railway link   (to attach to an existing project)
   railway up              # build & deploy this directory
   railway variables --set VITE_CALENDLY_URL=... --set QUOTE_WEBHOOK_URL=... --set QUOTE_WEBHOOK_TOKEN=...
   railway domain          # generate a domain
   ```
   Note: `railway up` deploys the local folder. For **auto-deploy on git push**, the dashboard GitHub connection (Option A) is better — so A is still recommended even if you use the CLI to bootstrap.

---

## Post-deploy QA
- [ ] Railway URL loads `/`, `/services`, `/gallery`, `/pricing`, `/book`, `/contact` (hard-refresh each — SPA fallback should serve them)
- [ ] EN/ES toggle works
- [ ] `/book` shows the Calendly embed (after `VITE_CALENDLY_URL` is set + redeploy)
- [ ] Submit a test quote on `/contact` → row in the Google Sheet + email to whistleclean100@gmail.com (after Apps Script is deployed and the two `QUOTE_WEBHOOK_*` vars are set)
- [ ] HTTPS active on the custom domain
- [ ] Submit `sitemap.xml` to Google Search Console; add the live URL to all platform profiles
