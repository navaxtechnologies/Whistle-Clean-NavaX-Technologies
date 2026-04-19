// server/index.ts
import express from "express";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);
async function startServer() {
  const app = express();
  const server = createServer(app);
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(self), payment=()"
    );
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https: blob:",
        "connect-src 'self' https:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
      ].join("; ")
    );
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload"
    );
    res.removeHeader("X-Powered-By");
    next();
  });
  const rateLimitMap = /* @__PURE__ */ new Map();
  const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1e3;
  const RATE_LIMIT_MAX_REQUESTS = 100;
  app.use((req, res, next) => {
    const clientIp = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    const record = rateLimitMap.get(clientIp);
    if (!record || now > record.resetTime) {
      rateLimitMap.set(clientIp, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
      return next();
    }
    record.count++;
    if (record.count > RATE_LIMIT_MAX_REQUESTS) {
      res.status(429).json({
        error: "Too many requests. Please try again later."
      });
      return;
    }
    next();
  });
  setInterval(() => {
    const now = Date.now();
    rateLimitMap.forEach((value, key) => {
      if (now > value.resetTime) {
        rateLimitMap.delete(key);
      }
    });
  }, 60 * 1e3);
  app.use((req, res, next) => {
    const blockedPatterns = [
      /\.env/i,
      /\.git/i,
      /\.config/i,
      /\.secret/i,
      /\.key$/i,
      /\.pem$/i,
      /\.crt$/i,
      /api[_-]?key/i,
      /token/i,
      /password/i,
      /credentials/i,
      /\.htaccess/i,
      /\.htpasswd/i,
      /web\.config/i,
      /wp-config/i,
      /\.sql$/i,
      /\.bak$/i,
      /\.backup$/i,
      /\.log$/i,
      /node_modules/i,
      /package\.json$/i,
      /package-lock\.json$/i,
      /pnpm-lock\.yaml$/i,
      /tsconfig/i,
      /vite\.config/i,
      /\.tsx?$/i,
      /server\//i,
      /shared\//i
    ];
    const requestPath = decodeURIComponent(req.path);
    for (const pattern of blockedPatterns) {
      if (pattern.test(requestPath)) {
        res.status(404).send("Not Found");
        return;
      }
    }
    next();
  });
  app.use((req, res, next) => {
    const rawUrl = req.originalUrl || req.url;
    if (rawUrl.includes("..") || rawUrl.includes("%2e%2e") || rawUrl.includes("%252e")) {
      res.status(400).send("Bad Request");
      return;
    }
    next();
  });
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: false, limit: "10kb" }));
  const staticPath = process.env.NODE_ENV === "production" ? path.resolve(__dirname, "public") : path.resolve(__dirname, "..", "dist", "public");
  app.use(express.static(staticPath, {
    // Security options for static file serving
    dotfiles: "deny",
    // Deny access to dotfiles
    index: "index.html",
    maxAge: process.env.NODE_ENV === "production" ? "1d" : 0
  }));
  app.post("/api/quote", (req, res) => {
    const { name, email, phone, service, date, message } = req.body;
    console.log("--- NEW QUOTE REQUEST ---");
    console.log(`Time: ${(/* @__PURE__ */ new Date()).toISOString()}`);
    console.log(`From: ${name} (${email})`);
    console.log(`Phone: ${phone}`);
    console.log(`Service: ${service}`);
    console.log(`Date: ${date || "Not specified"}`);
    console.log(`Message: ${message}`);
    console.log("-------------------------");
    res.status(200).json({ success: true, message: "Quote request received" });
  });
  app.get("*", (_req, res) => {
    res.sendFile(path.join(staticPath, "index.html"));
  });
  const port = process.env.PORT || 3e3;
  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
    console.log("Security headers and protections enabled.");
  });
}
startServer().catch(console.error);
