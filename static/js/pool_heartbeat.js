(() => {
  // Lightweight best-effort heartbeat.
  // Enabled by templates via window.MA_PING_ENABLED = true.
  const enabled = !!window.MA_PING_ENABLED;
  if (!enabled) return;

  async function ping() {
    try {
      await fetch('/api/pool/ping', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: '{}'
      });
    } catch (e) {
      // silent
    }
  }

  // Immediate + interval
  ping();
  setInterval(ping, 60_000);
})();
