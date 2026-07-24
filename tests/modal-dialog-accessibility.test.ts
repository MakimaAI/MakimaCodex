import { describe, expect, test } from "bun:test";

const modalSources = [
  {
    name: "AddProviderModal",
    path: "gui/src/components/AddProviderModal.tsx",
  },
  {
    name: "AddCodexAccountModal",
    path: "gui/src/components/AddCodexAccountModal.tsx",
  },
] as const;

describe("add modal accessibility", () => {
  for (const modal of modalSources) {
    test(`${modal.name} uses native modal semantics and restores trigger focus`, async () => {
      const source = await Bun.file(modal.path).text();

      expect(source).toContain("useRef<HTMLDialogElement>(null)");
      expect(source).toMatch(/<dialog\s[\s\S]*?ref=\{dialogRef\}/);
      expect(source).toContain("dialog.showModal()");
      expect(source).toContain("onCancel={handleCancel}");
      expect(source).toMatch(/handleCancel[\s\S]*?preventDefault\(\)[\s\S]*?closeModal\(\)/);
      expect(source).toMatch(/event\.target === event\.currentTarget/);
      expect(source).toMatch(/dialog\.open[\s\S]*?dialog\.close\(\)/);
      expect(source).toContain("previousFocusRef.current?.focus()");
      expect(source).not.toContain('window.addEventListener("keydown"');
      expect(source).not.toContain('<div role="dialog"');
    });
  }
});
