/**
 * Admin panel (Feature 2) — public shell at GET /admin; data via /admin/keys
 * (admin-only). Lets an admin mint scoped API keys, edit their allowed model
 * families + expiry, and revoke them. The freshly-minted plaintext key is
 * shown exactly once. A non-admin caller's /admin/keys request returns 403,
 * and the page renders an "admin only" empty state instead of crashing.
 */
import { themeCss, profileBarCss, profileBarHtml, profileBarJs } from "./profileBar"
import { authClientJs } from "./authClient"

export const adminPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Meridian — Admin</title>
  <style>
    ${themeCss}
    ${profileBarCss}
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; }
    .wrap { max-width: 1000px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 20px; margin: 0 0 4px; }
    .sub { color: var(--muted); font-size: 13px; margin: 0 0 24px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; }
    .card h2 { font-size: 14px; margin: 0 0 16px; }
    label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); margin: 0 0 6px; }
    input, select { background: var(--bg); color: var(--text); border: 1px solid var(--border);
      border-radius: 8px; padding: 8px 10px; font-size: 13px; }
    input:focus, select:focus { outline: none; border-color: var(--accent); }
    .row { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 14px; }
    .row > div { flex: 1; min-width: 140px; }
    .models { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
    .models label { display: inline-flex; align-items: center; gap: 6px; text-transform: none; letter-spacing: 0; font-size: 13px; color: var(--text); margin: 0; cursor: pointer; }
    button { background: var(--accent); color: #0d1117; border: none; border-radius: 8px;
      padding: 9px 18px; font-size: 13px; font-weight: 600; cursor: pointer; }
    button.ghost { background: transparent; color: var(--muted); border: 1px solid var(--border); }
    button.danger { background: transparent; color: var(--red); border: 1px solid var(--border); }
    button:hover { opacity: 0.9; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 500; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px; }
    td code { font-family: 'SF Mono', SFMono-Regular, Consolas, monospace; color: var(--lavender); }
    .badge { font-size: 10px; padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border); }
    .badge.admin { color: var(--accent2); }
    .badge.revoked { color: var(--red); }
    .badge.expired { color: var(--yellow); }
    .keybox { background: var(--bg); border: 1px solid var(--green); border-radius: 8px; padding: 14px; margin-bottom: 16px; }
    .keybox code { display: block; word-break: break-all; color: var(--green); font-size: 13px; margin: 8px 0; }
    .keybox .warn { color: var(--yellow); font-size: 11px; }
    .empty { color: var(--muted); text-align: center; padding: 40px; }
    .muted { color: var(--muted); }
  </style>
</head>
<body>
  ${profileBarHtml}
  <div class="wrap">
    <h1>Admin · API Keys</h1>
    <p class="sub">Mint scoped keys for users. Each key is limited to model families and an optional expiry.</p>

    <div id="readOnlyBanner" style="display:none">
      <div class="card" style="border-color: var(--yellow); background: rgba(210,153,34,0.06); padding: 12px 16px; margin-bottom: 16px;">
        <strong style="color:var(--yellow)">Read-only view.</strong>
        <span style="color:var(--muted); font-size: 13px; margin-left: 6px;">You can see existing keys, but creating and revoking keys requires the admin (master) key.</span>
      </div>
    </div>

    <div id="adminBody">
      <div class="card">
        <h2>Create key</h2>
        <div id="newKeyBox"></div>
        <div class="row">
          <div><label for="f-label">Label</label><input id="f-label" placeholder="alice's laptop"></div>
          <div><label for="f-user">User ID</label><input id="f-user" placeholder="alice"></div>
          <div><label for="f-expiry">Expires in</label>
            <div style="display:flex;gap:8px">
              <input id="f-expiry" type="number" min="0" placeholder="never" style="flex:1;min-width:0">
              <select id="f-expiry-unit"><option value="hours">hours</option><option value="days" selected>days</option></select>
            </div>
          </div>
        </div>
        <div style="margin-bottom:16px">
          <label>Allowed models</label>
          <div class="models">
            <label><input type="checkbox" id="m-all" checked> All (*)</label>
            <label><input type="checkbox" class="m-fam" value="opus"> Opus</label>
            <label><input type="checkbox" class="m-fam" value="sonnet"> Sonnet</label>
            <label><input type="checkbox" class="m-fam" value="haiku"> Haiku</label>
          </div>
        </div>
        <p class="err" id="createErr" style="color:var(--red);font-size:12px"></p>
        <button id="createBtn">Create key</button>
      </div>

      <div class="card">
        <h2>Existing keys</h2>
        <table>
          <thead><tr><th>Label</th><th>User</th><th>Prefix</th><th>Models</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
          <tbody id="keysBody"></tbody>
        </table>
        <div class="empty" id="noKeys" style="display:none">No keys yet.</div>
      </div>
    </div>
  </div>

  <script>${authClientJs}</script>
  <script>
    (function() {
      var api = window.meridianApi;
      var readOnlyBanner = document.getElementById('readOnlyBanner');
      var keysBody = document.getElementById('keysBody');
      var noKeys = document.getElementById('noKeys');
      // Read-only mode = signed in but not admin. Server enforces the same gate
      // on every mutating endpoint (POST/PATCH/POST-revoke return 403); this
      // flag is purely UI to hide buttons and disable the form so a user
      // doesn't get a 403 by clicking something they shouldn't see active.
      var readOnly = false;

      function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
      function fmtDate(ms) { return ms ? new Date(ms).toLocaleString() : '—'; }
      function fmtExpiry(ms) {
        if (!ms) return 'never';
        return (ms <= Date.now() ? 'expired · ' : '') + new Date(ms).toLocaleString();
      }
      function selectedModels() {
        if (document.getElementById('m-all').checked) return ['*'];
        var out = [];
        document.querySelectorAll('.m-fam').forEach(function(cb) { if (cb.checked) out.push(cb.value); });
        return out.length ? out : ['*'];
      }
      // "All" and specific families are mutually exclusive in the UI.
      document.getElementById('m-all').onchange = function() {
        if (this.checked) document.querySelectorAll('.m-fam').forEach(function(cb) { cb.checked = false; });
      };
      document.querySelectorAll('.m-fam').forEach(function(cb) {
        cb.onchange = function() { if (this.checked) document.getElementById('m-all').checked = false; };
      });

      function render(keys) {
        if (!keys.length) { keysBody.innerHTML = ''; noKeys.style.display = 'block'; return; }
        noKeys.style.display = 'none';
        keysBody.innerHTML = keys.map(function(k) {
          var status = k.revoked ? '<span class="badge revoked">revoked</span>'
            : (k.expiresAt && k.expiresAt <= Date.now() ? '<span class="badge expired">expired</span>' : '');
          var models = (k.allowedModels || []).join(', ');
          var actions = readOnly || k.revoked
            ? ''
            : '<button class="danger" data-revoke="' + esc(k.id) + '">Revoke</button>';
          return '<tr><td>' + esc(k.label) + ' ' + status +
            '</td><td>' + esc(k.userId) + '</td><td><code>' + esc(k.keyPrefix) + '…</code></td><td>' + esc(models) + '</td><td>' + esc(fmtExpiry(k.expiresAt)) +
            '</td><td class="muted">' + esc(fmtDate(k.lastUsedAt)) + '</td><td>' + actions + '</td></tr>';
        }).join('');
        keysBody.querySelectorAll('[data-revoke]').forEach(function(btn) {
          btn.onclick = function() {
            if (!confirm('Revoke this key? Apps using it will stop working immediately.')) return;
            api.apiFetch('/admin/keys/' + btn.getAttribute('data-revoke') + '/revoke', { method: 'POST' })
              .then(function() { load(); }).catch(function() {});
          };
        });
      }

      function applyReadOnly() {
        readOnlyBanner.style.display = 'block';
        // Disable the whole Create form. Visual + functional — apiFetch would
        // still 403 a non-admin POST, but better not to suggest the action.
        var disable = ['f-label', 'f-user', 'f-expiry', 'f-expiry-unit', 'm-all'];
        disable.forEach(function(id) {
          var el = document.getElementById(id);
          if (el) { el.disabled = true; el.style.opacity = '0.5'; }
        });
        document.querySelectorAll('.m-fam').forEach(function(cb) {
          cb.disabled = true; cb.style.opacity = '0.5';
        });
        var btn = document.getElementById('createBtn');
        if (btn) {
          btn.disabled = true;
          btn.style.opacity = '0.5';
          btn.style.cursor = 'not-allowed';
          btn.title = 'Admin privileges required';
        }
      }

      function load() {
        api.apiFetch('/admin/keys').then(function(res) {
          // /admin/keys is now open to any authed caller for reading; mutations
          // remain admin-only. A 403 here would mean a future server change
          // re-tightened the gate — degrade gracefully to an empty list.
          if (!res.ok) return null;
          return res.json();
        }).then(function(data) { if (data) render(data.keys || []); }).catch(function() {});
      }

      // Determine role first so the form/buttons render in the right state,
      // then load the keys list (which is open to any authed caller).
      api.whoami().then(function(who) {
        readOnly = !who || who.role !== 'admin';
        if (readOnly) applyReadOnly();
        load();
      }).catch(function() {
        // whoami's apiFetch already redirects on 401; we land here only on a
        // network failure. Default to read-only (safer) and still try the load.
        readOnly = true;
        applyReadOnly();
        load();
      });

      document.getElementById('createBtn').onclick = function() {
        var err = document.getElementById('createErr');
        err.textContent = '';
        var amount = parseInt(document.getElementById('f-expiry').value, 10);
        var unit = document.getElementById('f-expiry-unit').value;
        var userId = document.getElementById('f-user').value.trim();
        if (!userId) { err.textContent = 'User ID is required.'; return; }
        // Role is always "user" (server enforces it too). Label is an optional
        // grouping tag; it falls back to the user ID when left blank. Admins can
        // mint multiple keys for the same user, each with its own label.
        var label = document.getElementById('f-label').value.trim() || userId;
        var body = {
          label: label,
          userId: userId,
          allowedModels: selectedModels()
        };
        if (amount > 0) {
          var msPer = unit === 'hours' ? 3600000 : 86400000;
          body.expiresAt = Date.now() + amount * msPer;
        }
        api.apiFetch('/admin/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        }).then(function(res) { return res.json().then(function(j) { return { ok: res.ok, j: j }; }); })
          .then(function(r) {
            if (!r.ok) { err.textContent = r.j.error || 'Failed to create key'; return; }
            document.getElementById('newKeyBox').innerHTML =
              '<div class="keybox"><strong>New key — copy it now</strong>' +
              '<code>' + esc(r.j.key) + '</code>' +
              '<span class="warn">⚠ This is the only time the full key is shown.</span></div>';
            document.getElementById('f-user').value = '';
            document.getElementById('f-label').value = '';
            load();
          }).catch(function() { err.textContent = 'Request failed'; });
      };
    })();
  </script>
  <script>${profileBarJs}</script>
</body>
</html>`
