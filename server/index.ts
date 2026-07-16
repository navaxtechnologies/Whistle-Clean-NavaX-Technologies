/**
 * Production server for Whistle Clean.
 *
 * Built by esbuild to dist/index.js (see package.json "build"). Serves the
 * Vite-built SPA from dist/public, provides an SPA fallback so client-side
 * routes (/services, /pricing, /book, ...) work on hard refresh, and exposes
 * a real /api/quote endpoint for the contact form.
 *
 * Set QUOTE_WEBHOOK_URL (e.g. a GoHighLevel / Zapier inbound webhook) to
 * forward submitted quote requests to your CRM/email. It is REQUIRED: without
 * it (or if the forward fails) /api/quote returns an error rather than
 * silently dropping the lead.
 */
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// The contact form's "Preferred Service Date" is an <input type="date"> (YYYY-MM-DD).
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * True only for a real calendar date in YYYY-MM-DD form. The round-trip matters:
 * Date.parse("2026-02-31") happily rolls over to March 3 instead of failing.
 */
function isRealISODate(value: string): boolean {
  if (!DATE_RE.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

// Client-side routes that render a real page (HTTP 200). Anything else that
// falls through to the SPA shell is a genuine 404.
const KNOWN_ROUTES = new Set([
  "/",
  "/services",
  "/gallery",
  "/pricing",
  "/book",
  "/contact",
  "/404",
]);

const app = express();

// Railway terminates TLS at a proxy in front of us; trust one proxy hop so the
// rate limiter (and req.ip) keys on the real client IP, not the proxy's.
app.set("trust proxy", 1);

// --- Security headers (helmet) ---------------------------------------------
// Hide the framework fingerprint and set a hardened header baseline. The CSP
// is helmet's secure defaults extended just enough to allow the Calendly
// inline embed on /book (script + iframe + XHR + images from Calendly).
app.disable("x-powered-by");

const CALENDLY_HOSTS = [
  "https://assets.calendly.com",
  "https://calendly.com",
  "https://*.calendly.com",
];

app.use(
  helmet({
    xFrameOptions: { action: "deny" },
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'", ...CALENDLY_HOSTS],
        "frame-src": ["'self'", ...CALENDLY_HOSTS],
        "connect-src": ["'self'", ...CALENDLY_HOSTS],
        "img-src": ["'self'", "data:", ...CALENDLY_HOSTS],
      },
    },
  }),
);

// Cap request bodies at 10kb — the quote form is tiny; anything larger is abuse.
app.use(express.json({ limit: "10kb" }));

// Serve static assets produced by `vite build`.
app.use(express.static(publicDir));

// Rate limiter for the lead endpoint: 5 requests / 10 minutes / IP.
const quoteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests. Please try again later." },
});

// Quote request endpoint — matches the contact form's POST /api/quote.
app.post("/api/quote", quoteLimiter, async (req, res) => {
  const raw = req.body ?? {};

  // Honeypot: bots fill the hidden `wcx_note` field; humans never see it. Drop
  // the submission silently and return a fake success so bots learn nothing.
  // (Deliberately NOT named "company"/"website" — Chrome autofill fills those
  // for real users even with autocomplete="off", which silently ate real leads.)
  if (typeof raw.wcx_note === "string" && raw.wcx_note.trim() !== "") {
    console.warn("[quote] honeypot drop at", new Date().toISOString());
    return res.json({ success: true, message: "Quote request received." });
  }

  // Server-side validation — never trust the client. Trim, then check.
  const name = typeof raw.name === "string" ? raw.name.trim() : "";
  const email = typeof raw.email === "string" ? raw.email.trim() : "";
  const phone = typeof raw.phone === "string" ? raw.phone.trim() : "";
  const message = typeof raw.message === "string" ? raw.message.trim() : "";
  const service = typeof raw.service === "string" ? raw.service.trim() : "";
  const date = typeof raw.date === "string" ? raw.date.trim() : "";

  if (!name || !email) {
    return res.status(400).json({ success: false, error: "Name and email are required." });
  }
  if (name.length > 100) {
    return res.status(400).json({ success: false, error: "Name is too long." });
  }
  if (email.length > 200 || !EMAIL_RE.test(email)) {
    return res.status(400).json({ success: false, error: "A valid email address is required." });
  }
  if (phone.length > 30) {
    return res.status(400).json({ success: false, error: "Phone number is too long." });
  }
  if (message.length > 2000) {
    return res.status(400).json({ success: false, error: "Message is too long." });
  }
  if (service.length > 50) {
    return res.status(400).json({ success: false, error: "Invalid service selection." });
  }
  // Optional — blank means "as soon as possible". When given it must be a real
  // calendar date: round-trip it, since Date.parse rolls 2026-02-31 over to Mar 3.
  if (date && !isRealISODate(date)) {
    return res.status(400).json({ success: false, error: "Invalid preferred service date." });
  }

  // Never log customer PII (name/email/phone/message) to server logs.
  console.log(
    `[quote] received ${Object.keys(raw).length} fields at ${new Date().toISOString()}`,
  );

  const webhook = process.env.QUOTE_WEBHOOK_URL;
  if (!webhook) {
    // No CRM/email destination configured — do NOT pretend the lead was saved.
    console.error("[quote] QUOTE_WEBHOOK_URL is not configured; lead not delivered");
    return res.status(503).json({
      success: false,
      error: "Unable to submit your request right now. Please call or text us.",
    });
  }

  try {
    const forward = await fetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // Forward an explicit allowlist only — never arbitrary keys from the body.
      body: JSON.stringify({
        name,
        email,
        phone,
        message,
        service,
        date,
        type: "inquiry",
        token: process.env.QUOTE_WEBHOOK_TOKEN || "",
        source: "whistle-clean-website",
        receivedAt: new Date().toISOString(),
      }),
    });

    if (!forward.ok) {
      throw new Error(`webhook responded with HTTP ${forward.status}`);
    }
  } catch (err) {
    // Fail loudly: the customer sees an error (and a call/text fallback) so the
    // lead is never silently lost.
    console.error("[quote] webhook forward failed:", err instanceof Error ? err.message : err);
    return res.status(502).json({
      success: false,
      error: "Unable to submit your request right now. Please call or text us.",
    });
  }

  console.log("[quote] forwarded to webhook: ok");
  res.json({ success: true, message: "Quote request received." });
});

// --- API guard rails -------------------------------------------------------
// Any non-POST method on /api/quote is not allowed; never fall through to the
// SPA shell for API paths.
app.all("/api/quote", (_req, res) => {
  res.set("Allow", "POST");
  res.status(405).json({ success: false, error: "Method Not Allowed." });
});

// Unknown /api/* paths return JSON 404 (never the HTML SPA shell).
app.use("/api", (_req, res) => {
  res.status(404).json({ success: false, error: "Not Found." });
});

// SPA fallback: serve index.html for client-side routes. Known routes render
// at HTTP 200; every other path is a real 404 (the client renders NotFound).
app.get("*", (req, res) => {
  const status = KNOWN_ROUTES.has(req.path) ? 200 : 404;
  res.status(status).sendFile(path.join(publicDir, "index.html"));
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`Whistle Clean server listening on port ${port}`);
});
