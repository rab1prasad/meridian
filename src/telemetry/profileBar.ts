/**
 * Shared profile switcher bar — injected into all HTML pages.
 *
 * CSS and JS are self-contained. The bar auto-hides when no profiles
 * are configured. Profile changes take effect immediately via
 * POST /profiles/active — no page reload needed.
 */

/**
 * Canonical Meridian theme — purple brand palette.
 *
 * Every inline HTML page (landing, telemetry dashboard, profiles,
 * settings, plugins) prepends this block before its own styles so
 * `var(--bg)`, `var(--accent)` etc. resolve consistently everywhere.
 *
 * Extra variables (--queue, --ttfb, --upstream, --blue, --purple) exist
 * so the telemetry waterfall and lineage-colored badges keep their
 * semantic meaning without needing per-page overrides.
 */
export const themeCss = `
  :root {
    /* Cool-gray neutral palette — matches the original dashboard/profiles/
       settings look. Better for data-dense dashboards: high contrast,
       surface/border separation, no color cast muddying the text. Purple
       accents are retained as secondary brand color for hover states,
       gradients, and a handful of telemetry badges. */
    --bg:        #0d1117;
    --surface:   #161b22;
    --surface2:  #1c2128;
    --border:    #30363d;
    /* Text */
    --text:      #e6edf3;
    --muted:     #8b949e;
    /* Brand — blue primary, purple secondary */
    --accent:    #58a6ff;
    --accent2:   #bc8cff;
    --violet:    #bc8cff;
    --lavender:  #d2a8ff;
    /* Semantic */
    --green:     #3fb950;
    --yellow:    #d29922;
    --red:       #f85149;
    /* Telemetry-specific aliases (waterfall + lineage badges) */
    --blue:      #58a6ff;
    --purple:    #bc8cff;
    --queue:     #d29922;
    --ttfb:      #58a6ff;
    --upstream:  #3fb950;
  }
`

export const profileBarCss = `
  .meridian-profile-bar {
    position: sticky; top: 0; z-index: 100;
    display: none; align-items: center; gap: 12px;
    padding: 8px 24px;
    background: rgba(13, 17, 23, 0.92);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border, #30363d);
    font-size: 12px;
    color: var(--muted, #8b949e);
  }
  .meridian-profile-bar.visible { display: flex; }
  .meridian-profile-bar .profile-label {
    font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;
    font-size: 10px; color: var(--muted, #8b949e);
  }
  .meridian-profile-bar select {
    background: var(--surface, #161b22); color: var(--text, #e6edf3);
    border: 1px solid var(--border, #30363d); border-radius: 6px;
    padding: 4px 24px 4px 10px; font-size: 12px; cursor: pointer;
    appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath d='M3 5l3 3 3-3' fill='none' stroke='%238b949e' stroke-width='1.5'/%3E%3C/svg%3E");
    background-repeat: no-repeat; background-position: right 6px center;
  }
  .meridian-profile-bar select:hover { border-color: var(--accent, #58a6ff); }
  .meridian-profile-bar select:focus { outline: none; border-color: var(--accent, #58a6ff); box-shadow: 0 0 0 1px var(--accent, #58a6ff); }
  .meridian-profile-bar .profile-status {
    font-size: 11px; color: var(--green, #3fb950); opacity: 0;
    transition: opacity 0.3s;
  }
  .meridian-profile-bar .profile-status.show { opacity: 1; }
  .meridian-profile-bar .profile-type {
    font-size: 10px; padding: 2px 8px; border-radius: 4px;
    background: var(--surface, #161b22); border: 1px solid var(--border, #30363d);
  }
  .meridian-profile-bar .spacer { flex: 1; }
  .meridian-profile-bar .profile-nav a {
    color: var(--muted, #8b949e); text-decoration: none; font-size: 11px;
    padding: 4px 8px; border-radius: 4px; transition: color 0.15s;
  }
  .meridian-profile-bar .profile-nav a:hover { color: var(--text, #e6edf3); }
  .meridian-profile-bar .profile-nav a.active { color: var(--accent, #58a6ff); }
`

export const profileBarHtml = `
<div class="meridian-profile-bar" id="meridianProfileBar">
  <span class="profile-label">Profile</span>
  <select id="meridianProfileSelect"></select>
  <span class="profile-type" id="meridianProfileType"></span>
  <span class="profile-status" id="meridianProfileStatus">✓ Switched</span>
  <div class="spacer"></div>
  <div class="profile-nav">
    <a href="/" id="nav-home">Home</a>
    <a href="/settings" id="nav-settings">Settings</a>
    <a href="/profiles" id="nav-profiles">Profiles</a>
    <a href="/telemetry" id="nav-telemetry">Telemetry</a>
    <a href="/plugins" id="nav-plugins">Plugins</a>
    <a href="/admin" id="nav-admin" style="display:none">Admin</a>
    <a href="#" id="nav-logout" style="display:none">Logout</a>
  </div>
</div>
`

export const profileBarJs = `
(function() {
  var profileBar = document.getElementById('meridianProfileBar');
  var profileSelect = document.getElementById('meridianProfileSelect');
  var profileType = document.getElementById('meridianProfileType');
  var profileStatus = document.getElementById('meridianProfileStatus');
  var profileLabel = document.querySelector('.meridian-profile-bar .profile-label');
  var adminLink = document.getElementById('nav-admin');
  var logoutLink = document.getElementById('nav-logout');
  var statusTimeout;
  var hasProfiles = false;

  // Auth client (Feature 1). Falls back to plain fetch if not loaded.
  var api = window.meridianApi;
  function af(path, opts) { return api ? api.apiFetch(path, opts) : fetch(path, opts); }

  // Highlight active nav link
  var path = location.pathname;
  var navLinks = document.querySelectorAll('.profile-nav a');
  navLinks.forEach(function(a) {
    if (a.getAttribute('href') === path || (path === '/telemetry' && a.id === 'nav-telemetry') || (path === '/' && a.id === 'nav-home')) {
      a.classList.add('active');
    }
  });

  function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  // Keep the bar visible whenever there's something to show: a profile picker,
  // an admin's Admin link, or a logged-in user's Logout. Hide the profile
  // picker controls when no profiles are configured.
  function syncVisibility() {
    var showLogout = !!(api && api.getToken());
    var showAdmin = adminLink && adminLink.style.display !== 'none';
    if (logoutLink) logoutLink.style.display = showLogout ? '' : 'none';
    var showPicker = hasProfiles;
    if (profileLabel) profileLabel.style.display = showPicker ? '' : 'none';
    profileSelect.style.display = showPicker ? '' : 'none';
    profileType.style.display = showPicker ? '' : 'none';
    if (hasProfiles || showAdmin || showLogout) profileBar.classList.add('visible');
    else profileBar.classList.remove('visible');
  }

  function loadProfiles() {
    af('/profiles/list').then(function(r) { return r.json(); }).then(function(data) {
      hasProfiles = !!(data.profiles && data.profiles.length > 0);
      if (hasProfiles) {
        var current = data.profiles.find(function(p) { return p.isActive; });
        profileSelect.innerHTML = data.profiles.map(function(p) {
          return '<option value="' + esc(p.id) + '"' + (p.isActive ? ' selected' : '') + '>' + esc(p.id) + '</option>';
        }).join('');
        if (current) profileType.textContent = current.type;
      }
      syncVisibility();
    }).catch(function() {});
  }

  profileSelect.onchange = function() {
    af('/profiles/active', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile: profileSelect.value })
    }).then(function(r) { return r.json(); }).then(function(data) {
      if (data.success) {
        profileStatus.classList.add('show');
        clearTimeout(statusTimeout);
        statusTimeout = setTimeout(function() { profileStatus.classList.remove('show'); }, 2000);
        loadProfiles();
      }
    }).catch(function() {});
  };

  if (logoutLink) logoutLink.onclick = function(e) { e.preventDefault(); if (api) api.logout(); };

  // Admin link is visible to any authenticated user. The panel itself is
  // read-only for non-admins (create/revoke disabled in the UI) and the server
  // enforces 403 on mutations, so a user can browse the key list but not change
  // it. Admins get the fully editable panel.
  if (api) {
    api.whoami().then(function(who) {
      if (who && adminLink) adminLink.style.display = '';
      syncVisibility();
    }).catch(function() {});
  }

  loadProfiles();
  setInterval(loadProfiles, 10000);
})();
`
