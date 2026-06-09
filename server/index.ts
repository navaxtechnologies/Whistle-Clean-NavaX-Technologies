/**
 * Production server for Whistle Clean.
 *
 * Built by esbuild to dist/index.js (see package.json "build"). Serves the
 * Vite-built SPA from dist/public, provides an SPA fallback so client-side
 * routes (/services, /pricing, /book, ...) work on hard refresh, and exposes
 * a real /api/quote endpoint for the contact form.
 *
 * Set QUOTE_WEBHOOK_URL (e.g. a GoHighLevel / Zapier inbound webhook) to
 * forward submitted quote requests to your CRM/email automatically.
 */
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");

const app = express();
app.use(express.json({ limit: "100kb" }));

// Serve static assets produced by `vite build`.
app.use(express.static(publicDir));

// Quote request endpoint — matches the contact form's POST /api/quote.
app.post("/api/quote", async (req, res) => {
  const body = req.body ?? {};
  if (!body.name || !body.email) {
    return res.status(400).json({ success: false, error: "Missing required fields." });
  }

  console.log("[quote] New request:", JSON.stringify(body));

  const webhook = process.env.QUOTE_WEBHOOK_URL;
  if (webhook) {
    try {
      await fetch(webhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...body,
          type: "inquiry",
          token: process.env.QUOTE_WEBHOOK_TOKEN || "",
          source: "whistle-clean-website",
          receivedAt: new Date().toISOString(),
        }),
      });
    } catch (err) {
      console.error("[quote] webhook forward failed:", err);
      // Still return success to the user; the request is logged server-side.
    }
  }

  res.json({ success: true, message: "Quote request received." });
});

// SPA fallback: send index.html for any non-API, non-file route.
app.get("*", (_req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`Whistle Clean server listening on port ${port}`);
});
