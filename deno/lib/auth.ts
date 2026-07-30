const TOKEN_CHARS = 32;
const WINDOW_SECS = 30;
const WINDOW_TOLERANCE = 1;

export function currentWindow(): number {
  return Math.floor(Date.now() / 1000 / WINDOW_SECS);
}

export async function generate(
  secret: string,
  purpose: string,
  window: number,
): Promise<string> {
  const msg = `${purpose}:${window}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  const hex = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hex.slice(0, TOKEN_CHARS);
}

export async function verify(
  secret: string,
  purpose: string,
  token: string,
  serverWindow: number,
): Promise<boolean> {
  if (!token || token.length !== TOKEN_CHARS) return false;

  for (let offset = -WINDOW_TOLERANCE; offset <= WINDOW_TOLERANCE; offset++) {
    const candidate = await generate(secret, purpose, serverWindow + offset);
    if (timingSafeEqual(token, candidate)) {
      return true;
    }
  }
  return false;
}

export async function verifySync(
  secret: string,
  purpose: string,
  token: string,
  clientWindow: number,
  serverWindow: number,
): Promise<boolean> {
  if (!token || token.length !== TOKEN_CHARS) return false;
  if (Math.abs(clientWindow - serverWindow) > WINDOW_TOLERANCE) return false;

  for (let offset = -WINDOW_TOLERANCE; offset <= WINDOW_TOLERANCE; offset++) {
    const candidate = await generate(secret, purpose, serverWindow + offset);
    if (timingSafeEqual(token, candidate)) {
      return true;
    }
  }
  return false;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
