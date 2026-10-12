import { gatewayFetch, type RemediationItem } from "@/lib/gateway";
import { NoAccess, PageHeader, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

const PHASES: RemediationItem["roadmap_phase"][] = ["Immediate", "Short-term", "Medium-term", "Long-term"];

export default async function RemediationPage() {
  const roadmap = await optional(() => gatewayFetch<{ items: RemediationItem[] }>("/api/v1/risk/remediation?limit=100"));
  const header = (
    <PageHeader
      title="Remediation roadmap"
      description="One action per weak control, ordered by phase and by expected risk reduction per unit of effort."
    />
  );
  if (roadmap === null) return <>{header}<NoAccess what="the remediation roadmap" /></>;

  return (
    <>
      {header}
      {roadmap.items.length === 0 && <p className="muted empty">No open remediation items.</p>}
      {PHASES.map((phase) => {
        const items = roadmap.items.filter((i) => i.roadmap_phase === phase);
        if (items.length === 0) return null;
        return (
          <section key={phase} className="section">
            <div className="section-header"><h2>{phase} <span className="muted small">{items.length}</span></h2></div>
            <table>
              <thead><tr><th>#</th><th>Action</th><th>Effort</th><th>Risk reduction</th><th>Breaks scenarios</th><th>Status</th></tr></thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.item_id}>
                    <td>{i.priority}</td>
                    <td>
                      {i.title}
                      <div className="muted small wrap">{i.guidance}</div>
                      <div className="muted small">
                        {i.control_id} · {i.open_findings} open finding{i.open_findings === 1 ? "" : "s"}
                        {i.techniques.length > 0 && ` · ATT&CK ${i.techniques.map((t) => t.technique_id).join(", ")}`}
                      </div>
                    </td>
                    <td>{i.effort}</td>
                    <td><div className="bar"><span style={{ width: `${Math.min(100, i.expected_risk_reduction)}%` }} /></div>{i.expected_risk_reduction}%</td>
                    <td className="muted small">{i.scenarios.map((s) => s.title).join("; ") || "—"}</td>
                    <td><span className={`status ${i.status}`}>{i.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        );
      })}
      {roadmap.items.length > 0 && (
        <p className="muted small">
          Risk reduction is the share of current open finding and scenario scores removed by fixing the control.
        </p>
      )}
    </>
  );
}
