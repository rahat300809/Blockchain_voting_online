/**
 * config.js — BlockVote Server Configuration
 *
 * ════════════════════════════════════════════════════════════
 *  HOW TO CONFIGURE
 * ════════════════════════════════════════════════════════════
 *
 *  OPTION A — Local Network (3 PCs on same WiFi):
 *    Leave BLOCKVOTE_SERVER_URL as null.
 *    The system auto-connects to the server PC's IP on port 3000.
 *    On other PCs: open http://SERVER_IP:3000/admin etc.
 *
 *  OPTION B — Internet access via ngrok:
 *    1. Run:  ngrok http 3000
 *    2. Copy the HTTPS URL, e.g.: https://abc123.ngrok-free.app
 *    3. Set BLOCKVOTE_SERVER_URL below to that URL.
 *    4. Re-deploy: firebase deploy --only hosting
 *
 *  OPTION C — Your own VPS / cloud server:
 *    Set BLOCKVOTE_SERVER_URL to your server's public URL.
 *    Example: "https://vote.yourdomain.com"
 *    The Node.js server + C++ exes must be running on that server.
 *
 * ════════════════════════════════════════════════════════════
 */

// Set your server URL here (null = auto-detect from hostname)
window.BLOCKVOTE_SERVER_URL = "https://41dbeebf4b1e7a.lhr.life";

// Examples:
// window.BLOCKVOTE_SERVER_URL = "https://abc123.ngrok-free.app";   // ngrok
// window.BLOCKVOTE_SERVER_URL = "http://192.168.1.100:3000";       // LAN IP
// window.BLOCKVOTE_SERVER_URL = "https://vote.yourdomain.com";     // VPS
