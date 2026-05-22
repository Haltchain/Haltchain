#!/usr/bin/env node

const API_BASE = process.env.SMOKE_API_BASE_URL ?? "http://127.0.0.1:3000";
const ADMIN_EMAIL = process.env.SMOKE_ADMIN_EMAIL ?? "";
const ADMIN_PASSWORD = process.env.SMOKE_ADMIN_PASSWORD ?? "";
const LOOP = process.argv.includes("--loop");
const LOOPS = Number(process.env.SMOKE_E2E_LOOPS ?? "5");
const SLEEP_MS = Number(process.env.SMOKE_E2E_SLEEP_MS ?? "400");

function fail(msg) {
  console.error(`SMOKE FAIL: ${msg}`);
  process.exit(1);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function call(path, init = {}, cookie = "") {
  const headers = {
    "content-type": "application/json",
    ...(init.headers ?? {}),
  };
  if (cookie) {
    headers.cookie = cookie;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });

  return res;
}

function readSessionCookie(res) {
  const raw = res.headers.get("set-cookie") ?? "";
  const m = raw.match(/hc_admin_session=[^;]+/);
  return m ? m[0] : "";
}

async function runRound(round) {
  const health = await call("/api/health", { method: "GET" });
  if (!health.ok) {
    fail(`round ${round}: /api/health returned ${health.status}`);
  }

  const login = await call("/api/auth/admin/login", {
    method: "POST",
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  });
  if (!login.ok) {
    const body = await login.text();
    fail(`round ${round}: login failed ${login.status} ${body}`);
  }

  const sessionCookie = readSessionCookie(login);
  if (!sessionCookie) {
    fail(`round ${round}: login succeeded but no session cookie returned`);
  }

  const sessionOn = await call("/api/auth/session", { method: "GET" }, sessionCookie);
  if (!sessionOn.ok) {
    fail(`round ${round}: /api/auth/session returned ${sessionOn.status}`);
  }
  const sessionOnBody = await sessionOn.json();
  if (!sessionOnBody.unlocked) {
    fail(`round ${round}: session not unlocked after login`);
  }

  const queue = await call("/api/admin/review-queue", { method: "GET" }, sessionCookie);
  if (!queue.ok) {
    const body = await queue.text();
    fail(`round ${round}: /api/admin/review-queue returned ${queue.status} ${body}`);
  }
  const queueBody = await queue.json();
  const queueItems = Array.isArray(queueBody)
    ? queueBody
    : Array.isArray(queueBody?.pending)
      ? queueBody.pending
      : null;
  if (!queueItems) {
    fail(`round ${round}: /api/admin/review-queue returned unexpected payload shape`);
  }

  const logout = await call("/api/auth/logout", {
    method: "POST",
    body: JSON.stringify({}),
  }, sessionCookie);
  if (!logout.ok) {
    fail(`round ${round}: logout returned ${logout.status}`);
  }

  const sessionOff = await call("/api/auth/session", { method: "GET" });
  if (!sessionOff.ok) {
    fail(`round ${round}: post-logout /api/auth/session returned ${sessionOff.status}`);
  }
  const sessionOffBody = await sessionOff.json();
  if (sessionOffBody.unlocked) {
    fail(`round ${round}: session still unlocked after logout`);
  }

  console.log(`SMOKE PASS: round ${round} (queue entries=${queueItems.length})`);
}

async function main() {
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    fail("set SMOKE_ADMIN_EMAIL and SMOKE_ADMIN_PASSWORD in frontend/.env before running smoke:e2e");
  }

  if (!LOOP) {
    await runRound(1);
    return;
  }

  for (let i = 1; i <= LOOPS; i += 1) {
    await runRound(i);
    if (i < LOOPS && SLEEP_MS > 0) {
      await sleep(SLEEP_MS);
    }
  }
}

main().catch((err) => {
  fail(err instanceof Error ? err.message : String(err));
});
