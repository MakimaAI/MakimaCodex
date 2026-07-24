import { useT } from "../i18n/shared";
import { Trans } from "../i18n/provider";
import {
  bridgeHealthItems,
  modelCompatibilityKey,
  safeBridgeWarningKeys,
  type SubagentBridgeState,
  type SubagentModelRow,
} from "./subagent-view";

export function SubagentBridgePresentation({ bridge, warnings }: {
  bridge: SubagentBridgeState | null;
  warnings: readonly string[];
}) {
  const t = useT();
  if (!bridge) return null;
  const healthItems = bridgeHealthItems(bridge);
  const warningKeys = safeBridgeWarningKeys(warnings);

  return (
    <div className="card" aria-label={t("sub.bridgeTitle")} style={{ padding: 14, marginBottom: 14 }}>
      <div className="row" style={{ justifyContent: "space-between", gap: 10, marginBottom: 10 }}>
        <strong>{t("sub.bridgeTitle")}</strong>
        <span className={`badge ${bridge.ready ? "badge-green" : "badge-amber"}`}>
          {t(bridge.ready ? "sub.bridgeHealthy" : "sub.bridgeNeedsAttention")}
        </span>
      </div>
      <div className="row" style={{ alignItems: "stretch", flexWrap: "wrap", gap: 8 }}>
        {healthItems.map(item => (
          <div key={item.labelKey} style={{ minWidth: 132, flex: "1 1 132px", padding: "8px 10px", border: "1px solid var(--border-soft)", borderRadius: "var(--radius-sm)" }}>
            <div className="muted text-caption">{t(item.labelKey)}</div>
            <div className={item.ready ? "pws-status-ok" : "pws-status-warn"}>{t(item.valueKey)}</div>
          </div>
        ))}
      </div>
      {!bridge.ready && (
        <div className="muted text-label leading-body" style={{ marginTop: 10 }}>
          {!bridge.installedReady && <div><Trans k="sub.bridgeInstallGuidance" cmd="ocx subagents bridge install" /></div>}
          {(bridge.restartRequired || !bridge.installedReady) && <div><Trans k="sub.bridgeRestartGuidance" cmd="ocx restart" /></div>}
        </div>
      )}
      {warningKeys.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div className="muted text-caption">{t("sub.bridgeWarnings")}</div>
          <ul className="muted text-label leading-body" style={{ margin: "4px 0 0", paddingLeft: 20 }}>
            {warningKeys.map(key => <li key={key}>{t(key)}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

export function SubagentCompatibilityBadge({ row }: { row?: SubagentModelRow }) {
  const t = useT();
  if (!row) return null;
  const key = modelCompatibilityKey(row);
  const tone = key === "sub.modelV2Ready" ? "badge-green" : key === "sub.modelBridgeRequired" ? "badge-amber" : "badge-muted";
  return <span className={`badge ${tone}`}>{t(key)}</span>;
}
