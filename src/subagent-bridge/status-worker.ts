import { statusSubagentBridge } from "./lifecycle";

try {
  postMessage({ ok: true, status: statusSubagentBridge() });
} catch {
  postMessage({ ok: false });
}
