import { VerifyFix } from "@/components/VerifyFix";
import { gatewayFetch, type FixVerification, type RemediationItem } from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, Section, formatDate, getMe, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

const PHASES: RemediationItem["roadmap_phase"][] = ["Immediate", "Short-term", "Medium-term", "Long-term"];
const VERIFICATION_LABELS: Record<FixVerification["status"], string> = {
  pending: "pending", verified: "verified", still_failing: "still failing", inconclusive: "inconclusive",
  failed: "run failed",
};

export default async function RemediationPage() {
  const [me, roadmap, verifications] = await Promise.all([
    getMe(),
    optional(() => gatewayFetch<{ items: RemediationItem[] }>("/api/v1/risk/remediation?limit=100")),
    optional(() => gatewayFetch<{ items: FixVerification[] }>("/api/v1/assessments/verifications?limit=20")),
  ]);
  const canVerify = me.permissions.includes("assessments:run");
  const header = (
    <PageHeader
      title="Remediation roadmap"
      description="One action per weak control, ordered by phase and by expected risk reduction per unit of effort. After fixing, verify the fix with a targeted reassessment."
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
                      {canVerify && i.finding_ids.length > 0 && (
                        <VerifyFix findingIds={i.finding_ids} label={i.finding_ids.length > 50 ? "Verify fix (first 50)" : "Verify fix"} />
                      )}
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
          Verify fix reassesses only the affected controls and hosts; findings that are no longer observed are
          resolved and recorded as verified.
        </p>
      )}

      {verifications !== null && (
        <Section title="Recent fix verifications">
          <table>
            <thead><tr><th>Requested</th><th>Finding</th><th>Result</th><th>Finding state</th></tr></thead>
            <tbody>
              {verifications.items.length === 0 && <EmptyRow colSpan={4}>No fix verifications yet.</EmptyRow>}
              {verifications.items.map((v) => (
                <tr key={v.verification_id}>
                  <td className="small">{formatDate(v.requested_at)}<div className="muted">{v.requested_by}</div></td>
                  <td>{v.control_id}<div className="muted small wrap">{v.asset_id} · {v.subject_key || "—"}</div></td>
                  <td>
                    <span className={`status verification-${v.status}`}>{VERIFICATION_LABELS[v.status]}</span>
                    {v.summary && <div className="muted small">{v.summary}</div>}
                  </td>
                  <td className="muted">{v.lifecycle_state.replace("_", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}
    </>
  );
}
