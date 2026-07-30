import { createHmac, timingSafeEqual } from 'node:crypto';

const TOKEN_CHARS = 32;
const WINDOW_SECS = 30;
const WINDOW_TOLERANCE = 1;

export function currentWindow() {
  return Math.floor(Date.now() / 1000 / WINDOW_SECS);
}

export function generate(secret, purpose, window) {
  const msg = `${purpose}:${window}`;
  return createHmac('sha256', secret).update(msg).digest('hex').slice(0, TOKEN_CHARS);
}

export function verify(secret, purpose, token, serverWindow) {
  if (!token || token.length !== TOKEN_CHARS) return false;

  for (let offset = -WINDOW_TOLERANCE; offset <= WINDOW_TOLERANCE; offset++) {
    const candidate = generate(secret, purpose, serverWindow + offset);
    if (timingSafeEqual(Buffer.from(candidate), Buffer.from(token))) {
      return true;
    }
  }
  return false;
}

// Anti-replay: check client window is within ±1 of server window,
// then verify against server window.
export function verifySync(secret, purpose, token, clientWindow, serverWindow) {
  if (!token || token.length !== TOKEN_CHARS) return false;
  if (Math.abs(clientWindow - serverWindow) > WINDOW_TOLERANCE) return false;

  for (let offset = -WINDOW_TOLERANCE; offset <= WINDOW_TOLERANCE; offset++) {
    const candidate = generate(secret, purpose, serverWindow + offset);
    if (timingSafeEqual(Buffer.from(candidate), Buffer.from(token))) {
      return true;
    }
  }
  return false;
}
