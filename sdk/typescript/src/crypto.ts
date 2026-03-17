/**
 * Cryptographic helpers — mirrors the Python SDK's crypto.py.
 * Uses the WebCrypto API (built-in in browsers and Node.js 18+).
 */

/** Returns (nonce, timestamp, hex_signature) for an outbound request.
 *  Canonical form: `{agentId}\0{nonce}\0{timestamp}` — HMAC-SHA256 with apiKey.
 */
export async function signRequest(
  agentId: string,
  apiKey: string,
): Promise<[string, string, string]> {
  const nonce = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const message = `${agentId}\0${nonce}\0${timestamp}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(apiKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sigBuf = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message),
  );
  const hex = Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return [nonce, timestamp, hex];
}

/** Mirrors Rust's canonical_decision_payload(). */
function canonicalDecisionPayload(
  transactionId: string,
  decision: string,
  agentId: string,
  timestamp: string,
): string {
  return `${transactionId}\0${decision}\0${agentId}\0${timestamp}`;
}

/** Mirrors Rust's canonical_message() — null-byte separated fields. */
function buildVerifyMessage(
  payload: string,
  nonce: string,
  signedAt: string,
): Uint8Array {
  return new TextEncoder().encode(`${payload}\0${nonce}\0${signedAt}`);
}

function base64Decode(b64: string): Uint8Array {
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Verifies an Ed25519 server response signature.
 * Requires Node.js 15+ or a browser that supports the Ed25519 WebCrypto algorithm.
 * Returns false (instead of throwing) if the host platform doesn't support Ed25519.
 */
export async function verifyResponse(
  response: {
    transaction_id: string;
    decision: string;
    timestamp: string;
    sig?: Record<string, string>;
  },
  agentId: string,
  publicKeyB64: string,
): Promise<boolean> {
  const sig = response.sig;
  if (!sig?.nonce || !sig.signed_at || !sig.signature) return false;

  try {
    const keyBytes = base64Decode(publicKeyB64);
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );

    const payload = canonicalDecisionPayload(
      response.transaction_id,
      response.decision,
      agentId,
      response.timestamp,
    );
    const message = buildVerifyMessage(payload, sig.nonce, sig.signed_at);
    const sigBytes = base64Decode(sig.signature);

    return await crypto.subtle.verify("Ed25519", key, sigBytes, message);
  } catch {
    // Ed25519 not supported on this platform, or malformed data.
    return false;
  }
}
