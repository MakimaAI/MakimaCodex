const until = Date.now() + 150;
while (Date.now() < until) {
  // Deliberately block only this worker to model slow Codex/PowerShell inspection.
}

postMessage({
  installed: true,
  registered: true,
  enabled: true,
  tokenPresent: true,
  tokenSecure: true,
  marketplaceReady: true,
  mcpReady: true,
  ready: true,
  warnings: [],
});
