/**
 * Shared browser auth client — injected into every HTML page (Feature 1).
 *
 * When MERIDIAN_API_KEY is set the page shells are public but their data APIs
 * are gated. This script defines `window.meridianApi`, whose `apiFetch` wraps
 * `fetch` to attach the stored `x-api-key` to every call and bounce to /login
 * on 401. The token + base URL live in localStorage (set by the login page).
 *
 * Base URL defaults to the current origin (same-origin design), so existing
 * relative paths keep working and no CORS surface is opened. Include this
 * BEFORE profileBarJs and any page script so they can use `meridianApi`.
 */
export const authClientJs = `
(function() {
  var TOKEN_KEY = 'meridian.token';
  var URL_KEY = 'meridian.baseUrl';

  function get(k) { try { return localStorage.getItem(k) || ''; } catch (e) { return ''; } }
  function set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function getToken() { return get(TOKEN_KEY); }
  function setToken(t) { set(TOKEN_KEY, t); }
  function getBaseUrl() { return get(URL_KEY); }
  function setBaseUrl(u) { set(URL_KEY, u); }
  function clear() { try { localStorage.removeItem(TOKEN_KEY); } catch (e) {} }

  function buildUrl(path) {
    var base = getBaseUrl();
    if (!base) return path; // same-origin relative
    return base.replace(/\\/+$/, '') + path;
  }

  function apiFetch(path, opts) {
    opts = opts || {};
    var headers = {};
    if (opts.headers) { for (var k in opts.headers) headers[k] = opts.headers[k]; }
    var tok = getToken();
    if (tok) headers['x-api-key'] = tok;
    var merged = {};
    for (var p in opts) merged[p] = opts[p];
    merged.headers = headers;
    return fetch(buildUrl(path), merged).then(function(res) {
      if (res.status === 401) {
        clear();
        if (location.pathname !== '/login') {
          location.href = '/login?next=' + encodeURIComponent(location.pathname);
        }
        throw new Error('unauthorized');
      }
      return res;
    });
  }

  function whoami() { return apiFetch('/auth/whoami').then(function(r) { return r.json(); }); }
  function logout() { clear(); location.href = '/login'; }

  window.meridianApi = {
    apiFetch: apiFetch,
    whoami: whoami,
    getToken: getToken, setToken: setToken,
    getBaseUrl: getBaseUrl, setBaseUrl: setBaseUrl,
    logout: logout, clear: clear
  };
})();
`
