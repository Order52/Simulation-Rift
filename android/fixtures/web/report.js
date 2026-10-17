// Sends one observation to the fixture server (never to the app: no bridge exists).
const TEST = new URLSearchParams(location.search).get("test") || document.documentElement.dataset.test;
function report(key, value) {
  return fetch(`/report?test=${encodeURIComponent(TEST)}&key=${encodeURIComponent(key)}&value=${encodeURIComponent(String(value))}`);
}
