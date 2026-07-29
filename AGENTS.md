# AGENTS.md

## Project status

Formal project, **implementation language is Rust** (user requirement). No Rust
code exists yet — the repo currently holds only prior research and credentials.
Not yet a git repo; when initializing one, add `cf_auth.txt` and `vercel.txt`
to `.gitignore` first (both contain live API tokens).

## Directory layout

- `research/` — read-only Python/Bash experiments from the NAT-traversal
  research phase. Do not extend or "fix" these files; they are reference
  material for the Rust implementation.
- `research/nat-traversal-report.md` — verified NAT behavior facts (source of
  truth for the assumptions below).
- `research/expose_ssh.sh`, `research/nat_backend.py` — working reference
  implementations of STUN TCP hole-punch + hairpin keepalive to port to Rust.

## Verified environment facts (do not re-derive, trust the report)

- NAT is **Full Cone** behind China Telecom **CGNAT**; mapping is
  endpoint-independent but the public port is **not** preserved — it must be
  discovered via STUN after each punch.
- NAT TCP mapping idle timeout is **~5–8 s**; only **outbound** traffic
  refreshes it (inbound does not). Hairpin self-connection keepalive is
  verified to hold a mapping open indefinitely.
- The telecom BRAS resets around **02:00 daily**: all mappings die and the
  public IP may change. Any daemon must detect this (hairpin failure, STUN
  re-probe mismatch) and re-punch + re-register automatically.
- STUN server quirk: `stunserver2025.stunprotocol.org:3478` (TCP) does **not**
  use the RFC 5389 §11.2 2-byte length prefix — send raw STUN messages.
- `SO_REUSEADDR` is required to bind a listener on the punched port, and lets
  the listener survive re-punches on the same local port.

## Agreed architecture (from planning with the user)

Three components, to be built:

1. **Host daemon** (`nat_sshd`, Rust): STUN punch → listen on same local port
   → hairpin keepalive → HMAC gate → bridge to `127.0.0.1:22`; heartbeat
   registration to Vercel every 20 s; state machine
   ACTIVE → SUSPECT → REPUNCH for BRAS-reset recovery; runs as a systemd user
   service with `Restart=always`.
2. **Vercel Functions registry**: `POST /api/register` (host writes), `GET
   /api/endpoint` (clients read), storage in **Vercel KV (Upstash Redis)**;
   endpoint record includes sshd host public key for MITM protection.
3. **Client wrapper** `ssh-nat` + `zt-gate-proxy` (ProxyCommand): fetches
   endpoint, sends gate token, then execs ssh with pinned host key.

## Security design (decided, do not regress)

- One 32-byte shared secret, three HMAC purposes (domain-separated):
  `register` / `discover` / `gate`.
- Token = truncated hex HMAC-SHA256 over `"{purpose}:{window}"`, window =
  30 s, verify with ±1 window tolerance (~60 s anti-replay).
- The exposed port runs a **gate**, never sshd directly: first line must be a
  valid gate token within 3 s, else drop silently (no SSH banner — this is
  intentional, to hide from scanners and shield sshd/PAM from the internet).
- sshd hardening (`PasswordAuthentication no`) is a manual step for the user;
  do not edit system sshd config unprompted.

## Secrets in this repo (never commit, never echo into logs)

- `cf_auth.txt` — Cloudflare API token (legacy, used by research scripts).
- `vercel.txt` — Vercel token, to be used for deploying the registry.
