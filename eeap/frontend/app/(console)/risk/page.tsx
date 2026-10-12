import { gatewayFetch, type Rating, type RiskSummary, type TopFinding } from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, Section, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

const RATINGS: Rating[] = ["Critical", "High", "Medium", "Low"];

export default async function RiskPage() {
  const [risk, topFindings] = await Promise.all([
    optional(() => gatewayFetch<RiskSummary>("/api/v1/risk/summary")),
    optional(() => gatewayFetch<{ items: TopFinding[] }>("/api/v1/risk/top-findings?limit=100")),
  ]);
  if (risk === null) return <><PageHeader title="Risks & findings" /><NoAccess what="risk scores" /></>;

  const byRating = risk.open_by_rating.finding;
  const exposure = risk.exposure_score;

  return (
    <>
      <PageHeader
        title="Risks & findings"
        description="Correlated attack scenarios and the highest scored open findings."
      />
      <div className="cards">
        <div className="card">
          <div className="label">Exposure score</div>
          <div className="value">
            {exposure ? <>{exposure.score} <span className={`badge ${exposure.rating}`}>{exposure.rating}</span></> : "—"}
          </div>
        </div>
        {RATINGS.map((r) => (
          <div key={r} className="card">
            <div className="label">{r} findings</div>
            <div className="value"><span className={`dot ${r}`} />{byRating[r] ?? 0}</div>
          </div>
        ))}
      </div>

      <Section title={`Attack scenarios (${risk.active_scenarios} active)`}>
        <table>
          <thead><tr><th>Score</th><th>Scenario</th><th>Chain</th><th>Assets</th></tr></thead>
          <tbody>
            {(risk.top_scenarios?.length ?? 0) === 0 && <EmptyRow colSpan={4}>No correlated risk scenarios.</EmptyRow>}
            {risk.top_scenarios?.map((s) => (
              <tr key={s.scenario_id}>
                <td><span className={`badge ${s.rating}`}>{s.score}</span></td>
                <td>{s.title}<div className="muted small">{s.rule_id} · {s.summary}</div></td>
                <td className="small">{s.stages.filter((st) => st.matched).map((st) => st.name).join(" → ")}</td>
                <td className="muted small">{s.affected_asset_ids.join(", ") || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Top findings">
        {topFindings === null ? <NoAccess what="findings" /> : (
          <table>
            <thead><tr><th>Score</th><th>Control</th><th>Asset</th><th>Subject</th><th>Severity</th><th>Status</th><th>Lifecycle</th></tr></thead>
            <tbody>
              {topFindings.items.length === 0 && <EmptyRow colSpan={7}>No open risk findings.</EmptyRow>}
              {topFindings.items.map((f) => (
                <tr key={f.finding_id}>
                  <td><span className={`badge ${f.rating}`}>{f.score}</span></td>
                  <td>{f.control_id}<div className="muted small">{f.category}</div></td>
                  <td>{f.hostname ?? f.asset_id}</td>
                  <td className="muted small wrap">{f.subject_key || "—"}</td>
                  <td>{f.severity}</td>
                  <td>{f.status}</td>
                  <td className="muted">{f.lifecycle_state.replace("_", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}
