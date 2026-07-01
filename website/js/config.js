/**
 * config.js — BlockVote Server URL Configuration (v5.0 — Cloud Edition)
 *
 * Backend is PERMANENTLY hosted on Fly.io at a fixed URL.
 * No discovery, no tunnel, no KV store needed!
 * Frontend at: https://blockchain300809.web.app
 * Backend at:  https://blockchain300809-api.fly.dev
 */

(function () {
  'use strict';

  // ── Permanent Backend URL (Fly.io — always online, never changes) ──────────
  const FLY_URL    = 'https://blockchain300809-api.fly.dev';

  // ── Development override (localhost when running locally) ──────────────────
  const isLocalhost = window.location.hostname === 'localhost'
    || window.location.hostname === '127.0.0.1'
    || window.location.hostname === '0.0.0.0';

  // ── Choose server URL ──────────────────────────────────────────────────────
  // In production: always use Fly.io URL
  // In local dev:  use localhost for easier testing
  const SERVER_URL = isLocalhost
    ? `${window.location.protocol}//${window.location.hostname}:3000`
    : FLY_URL;

  const WS_URL = SERVER_URL.replace(/^https?/, SERVER_URL.startsWith('https') ? 'wss' : 'ws');

  // ── Expose globally ────────────────────────────────────────────────────────
  window.BLOCKVOTE_CONFIG = {
    serverUrl:     SERVER_URL,
    wsUrl:         WS_URL,
    flyUrl:        FLY_URL,
    isCloud:       !isLocalhost,
    version:       '5.0',
  };

  // Legacy compatibility
  window.BLOCKVOTE_SERVER_URL = SERVER_URL;
  window.BLOCKVOTE_WS_URL     = WS_URL;

  console.log(`[BlockVote] Server: ${SERVER_URL} (${isLocalhost ? 'local dev' : 'Fly.io cloud ☁️'})`);
})();
