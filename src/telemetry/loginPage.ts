/**
 * Login page (Feature 1) — public shell at GET /login.
 *
 * Lets a user enter the Meridian base URL (prefilled to the current origin)
 * and an API token. On submit it stores both in localStorage via the shared
 * `meridianApi` client, validates by calling /auth/whoami, and redirects to
 * the dashboard (or the ?next= path). When auth is disabled (open mode) the
 * token is optional and any value works.
 */
import { themeCss } from "./profileBar"
import { authClientJs } from "./authClient"

export const loginPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Meridian — Sign in</title>
  <style>
    ${themeCss}
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    }
    .card {
      width: 100%; max-width: 380px; background: var(--surface);
      border: 1px solid var(--border); border-radius: 14px; padding: 28px;
    }
    .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
    .brand h1 { font-size: 18px; margin: 0; font-weight: 600; }
    .sub { color: var(--muted); font-size: 12px; margin: 0 0 22px; }
    label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); margin: 0 0 6px; }
    input {
      width: 100%; background: var(--bg); color: var(--text); border: 1px solid var(--border);
      border-radius: 8px; padding: 10px 12px; font-size: 13px; margin-bottom: 16px;
      font-family: 'SF Mono', SFMono-Regular, Consolas, monospace;
    }
    input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
    button {
      width: 100%; background: var(--accent); color: #0d1117; border: none; border-radius: 8px;
      padding: 11px; font-size: 13px; font-weight: 600; cursor: pointer; transition: opacity 0.15s;
    }
    button:hover { opacity: 0.9; }
    button:disabled { opacity: 0.5; cursor: default; }
    .err { color: var(--red); font-size: 12px; margin: 0 0 14px; min-height: 16px; }
    .hint { color: var(--muted); font-size: 11px; margin-top: 16px; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand"><h1>Meridian</h1></div>
    <p class="sub">Sign in to the dashboard</p>
    <form id="loginForm">
      <label for="token">API token</label>
      <input id="token" type="password" autocomplete="off" spellcheck="false" placeholder="sk-meridian-...">
      <p class="err" id="err"></p>
      <button type="submit" id="submitBtn">Sign in</button>
    </form>
    <p class="hint">The token is stored in this browser only and sent as <code>x-api-key</code> with each request. Leave blank if this server has no API key configured.</p>
  </div>
  <script>${authClientJs}</script>
  <script>
    (function() {
      var api = window.meridianApi;
      var tokenInput = document.getElementById('token');
      var err = document.getElementById('err');
      var btn = document.getElementById('submitBtn');

      function nextPath() {
        var m = location.search.match(/[?&]next=([^&]+)/);
        var p = m ? decodeURIComponent(m[1]) : '';
        if (!p || p === '/login') return '/telemetry';
        return p;
      }

      document.getElementById('loginForm').onsubmit = function(e) {
        e.preventDefault();
        err.textContent = '';
        btn.disabled = true;
        api.setToken(tokenInput.value.trim());
        api.whoami().then(function(who) {
          location.href = nextPath();
        }).catch(function(ex) {
          // whoami's apiFetch already redirected on a true 401; this catch
          // covers network errors and the thrown 'unauthorized'.
          if (ex && ex.message === 'unauthorized') {
            err.textContent = 'Invalid token for this server.';
          } else {
            err.textContent = 'Could not reach the server. Try again.';
          }
          api.clear();
          btn.disabled = false;
        });
      };
    })();
  </script>
</body>
</html>`
