import path from "node:path";
import { fileURLToPath } from "node:url";

import cookieParser from "cookie-parser";
import express from "express";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = Number(process.env.FRONTEND_PORT ?? process.env.PORT ?? 8787);
const HALTCHAIN_API_URL = process.env.HALTCHAIN_API_URL ?? "http://127.0.0.1:8080";
const SESSION_COOKIE = "hc_admin_session";
// 8-hour session max-age matches the Rust JWT expiry.
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const DIST_DIR = path.join(__dirname, "dist", "public");

app.disable("x-powered-by");
app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());

function jwtFromRequest(req) {
  return req.cookies[SESSION_COOKIE] ?? null;
}

function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: SESSION_TTL_MS,
    path: "/",
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });
}

// Forward a request to the Axum API using the session JWT as Bearer token.
async function proxyWithJwt(req, res, upstreamPath, method) {
  const token = jwtFromRequest(req);
  if (!token) {
    res.status(401).json({ error: "No active admin session" });
    return;
  }

  try {
    const search = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
    const url = `${HALTCHAIN_API_URL}${upstreamPath}${search}`;
    const upstream = await fetch(url, {
      method,
      headers: {
        "content-type": "application/json",
        "authorization": `Bearer ${token}`,
      },
      body: method === "GET" || method === "DELETE" ? undefined : JSON.stringify(req.body ?? {}),
    });

    const text = await upstream.text();
    res.status(upstream.status);
    if ((upstream.headers.get("content-type") ?? "").includes("application/json")) {
      res.type("application/json");
    }
    res.send(text);
  } catch {
    res.status(503).json({ error: "Failed to reach Haltchain API" });
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

app.get("/api/health", async (_req, res) => {
  try {
    const upstream = await fetch(`${HALTCHAIN_API_URL}/health`);
    const body = await upstream.text();
    res.status(upstream.status).type("application/json").send(body);
  } catch {
    res.status(503).json({ error: "Upstream health check failed" });
  }
});

// Check whether the stored JWT is still valid by calling /auth/admin/me.
app.get("/api/auth/session", async (req, res) => {
  const token = jwtFromRequest(req);
  if (!token) {
    res.json({ unlocked: false });
    return;
  }
  try {
    const upstream = await fetch(`${HALTCHAIN_API_URL}/auth/admin/me`, {
      headers: { "authorization": `Bearer ${token}` },
    });
    res.json({ unlocked: upstream.ok });
  } catch {
    res.json({ unlocked: false });
  }
});

// Login: validate credentials at the API, store returned JWT in HttpOnly cookie.
app.post("/api/auth/admin/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    res.status(400).json({ error: "email and password are required" });
    return;
  }
  try {
    const upstream = await fetch(`${HALTCHAIN_API_URL}/auth/admin/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!upstream.ok) {
      const body = await upstream.json().catch(() => ({}));
      clearSessionCookie(res);
      res.status(upstream.status).json({ ok: false, error: body.error ?? "Invalid credentials" });
      return;
    }
    const { token } = await upstream.json();
    setSessionCookie(res, token);
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false, error: "Unable to reach Haltchain API" });
  }
});

app.post("/api/auth/logout", (_req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

// ── Admin proxy routes ─────────────────────────────────────────────────────────

app.get("/api/admin/review-queue", (req, res) =>
  proxyWithJwt(req, res, "/admin/review-queue", "GET"));

app.post("/api/admin/review-queue/:txId/outcome", (req, res) =>
  proxyWithJwt(req, res, `/admin/review-queue/${encodeURIComponent(req.params.txId)}/outcome`, "POST"));

app.get("/api/admin/recommendations", (req, res) =>
  proxyWithJwt(req, res, "/admin/recommendations", "GET"));

app.post("/api/admin/recommendations/run", (req, res) =>
  proxyWithJwt(req, res, "/admin/recommendations/run", "POST"));

app.post("/api/admin/recommendations/:id/approve", (req, res) =>
  proxyWithJwt(req, res, `/admin/recommendations/${encodeURIComponent(req.params.id)}/approve`, "POST"));

app.post("/api/admin/recommendations/:id/reject", (req, res) =>
  proxyWithJwt(req, res, `/admin/recommendations/${encodeURIComponent(req.params.id)}/reject`, "POST"));

app.post("/api/admin/recommendations/:id/revert", (req, res) =>
  proxyWithJwt(req, res, `/admin/recommendations/${encodeURIComponent(req.params.id)}/revert`, "POST"));

app.get("/api/admin/thresholds", (req, res) =>
  proxyWithJwt(req, res, "/admin/thresholds", "GET"));

app.patch("/api/admin/thresholds", (req, res) =>
  proxyWithJwt(req, res, "/admin/thresholds", "PATCH"));

app.get("/api/admin/ab-variants", (req, res) =>
  proxyWithJwt(req, res, "/admin/ab-variants", "GET"));

app.post("/api/admin/ab-variants", (req, res) =>
  proxyWithJwt(req, res, "/admin/ab-variants", "POST"));

app.get("/api/admin/audit-log", (req, res) =>
  proxyWithJwt(req, res, "/admin/audit-log", "GET"));

app.get("/api/status/:agentId", (req, res) =>
  proxyWithJwt(req, res, `/status/${encodeURIComponent(req.params.agentId)}`, "GET"));

app.get("/api/agent/improvement/lineage/:agentId", (req, res) =>
  proxyWithJwt(
    req,
    res,
    `/agent/improvement/lineage/${encodeURIComponent(req.params.agentId)}`,
    "GET",
  ));

// ── Public pass-through routes ─────────────────────────────────────────────────

app.get("/api/public-key", async (_req, res) => {
  try {
    const upstream = await fetch(`${HALTCHAIN_API_URL}/public-key`);
    res.status(upstream.status).type("application/json").send(await upstream.text());
  } catch { res.status(503).json({ error: "Failed to reach Haltchain API" }); }
});

app.get("/api/merkle/root", async (_req, res) => {
  try {
    const upstream = await fetch(`${HALTCHAIN_API_URL}/merkle/root`);
    res.status(upstream.status).type("application/json").send(await upstream.text());
  } catch { res.status(503).json({ error: "Failed to reach Haltchain API" }); }
});

app.get("/api/drift/:agentId/:sessionId", async (req, res) => {
  try {
    const url = `${HALTCHAIN_API_URL}/drift/${encodeURIComponent(req.params.agentId)}/${encodeURIComponent(req.params.sessionId)}`;
    const upstream = await fetch(url);
    res.status(upstream.status).type("application/json").send(await upstream.text());
  } catch { res.status(503).json({ error: "Failed to reach Haltchain API" }); }
});

// ── Risk advisories ────────────────────────────────────────────────────────────

app.get("/api/risk/advisories/:agentId", (req, res) =>
  proxyWithJwt(req, res, `/risk/advisories/${encodeURIComponent(req.params.agentId)}`, "GET"));

// SSE proxy: streams new advisories in real-time.
app.get("/api/risk/advisories/:agentId/stream", async (req, res) => {
  const token = jwtFromRequest(req);
  if (!token) {
    res.status(401).json({ error: "No active admin session" });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const url = `${HALTCHAIN_API_URL}/risk/advisories/${encodeURIComponent(req.params.agentId)}/stream`;
  const abort = new AbortController();
  req.on("close", () => abort.abort());

  try {
    const upstream = await fetch(url, {
      headers: { "authorization": `Bearer ${token}` },
      signal: abort.signal,
    });
    if (!upstream.ok || !upstream.body) { res.end(); return; }
    const decoder = new TextDecoder();
    for await (const chunk of upstream.body) {
      if (res.writableEnded) break;
      res.write(decoder.decode(chunk, { stream: true }));
    }
  } catch {
    // client disconnected or upstream error
  } finally {
    res.end();
  }
});

// ── Static files + SPA fallback ────────────────────────────────────────────────

app.use(express.static(DIST_DIR, { index: false }));
app.get("*", (_req, res) => {
  res.sendFile(path.join(DIST_DIR, "index.html"));
});

app.listen(PORT, () => {
  console.log(`frontend server running on :${PORT}`);
});
