import { expect, test } from "bun:test";

test("Vite dev proxy rewrites only its own same-origin browser requests to the backend origin", async () => {
  const source = await Bun.file("gui/vite.config.ts").text();

  expect(source).toContain("function sameOriginDevProxy");
  expect(source).toContain("new URL(origin).host !== host");
  expect(source).toContain('proxyReq.setHeader("Origin", targetOrigin)');
  expect(source).toContain("'/api': sameOriginDevProxy(proxyTarget)");
});
