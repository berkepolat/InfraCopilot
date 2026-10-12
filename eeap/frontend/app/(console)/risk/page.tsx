import Link from "next/link";
import { FactorChips } from "@/components/FactorChips";
import { gatewayFetch, type Rating, type RiskSummary, type TopAsset, type TopFinding } from "@/lib/gateway";
import { exposureSummary, factorChips } from "@/lib/risk";
import { EmptyRow, NoAccess, PageHeader, Section, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

const RATINGS: Rating[] = ["Critical", "High", "Medium", "Low"];

export default async function RiskPage() {
  const [risk, topFindings, topAssets] = await Promise.all([
    optional(() => gatewayFetch<RiskSummary>("/api/v1/risk/summary")),
    optional(() => gatewayFetch<{ items: TopFinding[] }>("/api/v1/risk/top-findings?limit=100")),
    optional(() => gatewayFetch<{ items: TopAsset[] }>("/api/v1/risk/top-assets?limit=25")),
  ]);
  if (risk === null) return <><PageHeader title="Risks & findings" /><NoAccess what="risk scores" /></>;

  const byRating = risk.open_by_rating.finding;
  const exposure = risk.exposure_score;
  const assets = topAssets?.items.filter((a) => a.score > 0) ?? [];

  return (
    <>
      <PageHeader
        title="Risks & findings"
        description={`Prioritised by severity, asset criticality, exploitation evidence, network exposure and attack paths (scoring model ${risk.scoring_model}).`}
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

      <Section title="Assets by risk" link={{ href: "/assets", label: "Classify assets" }}>
        {topAssets === null ? <NoAccess what="asset scores" /> : (
          <table>
            <thead><tr><th>Score</th><th>Asset</th><th>Criticality</th><th>Network exposure</th><th>Open findings</th></tr></thead>
            <tbody>
              {assets.length === 0 && <EmptyRow colSpan={5}>No assets with open risk findings.</EmptyRow>}
              {assets.map((a) => (
                <tr key={a.asset_id}>
                  <td><span className={`badge ${a.rating}`}>{a.score}</span></td>
                  <td>{a.hostname ?? a.asset_id}<div className="muted small mono">{a.asset_id}</div></td>
                  <td>
                    {a.criticality ?? "—"}<div className="muted small">{a.tier ?? ""}</div>
                    {a.exposure?.suggested_criticality && a.criticality && rank(a.exposure.suggested_criticality) > rank(a.criticality) && (
                      <div className="small"><Link href="/assets">suggested {a.exposure.suggested_criticality}</Link></div>
                    )}
                  </td>
                  <td className="small">
                    {exposureSummary(a.exposure)}
                    {a.exposure && a.exposure.open_services > 0 && (
                      <div className="muted small">{a.exposure.services.map((s) => `${s.port}/${s.service}`).join(", ")}</div>
                    )}
                  </td>
                  <td>
                    {a.factors.open_findings ?? "—"}
                    {a.known_exploited > 0 && <div className="factors"><span className="factor hot">{a.known_exploited} actively exploited</span></div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="Top findings">
        {topFindings === null ? <NoAccess what="findings" /> : (
          <table>
            <thead><tr><th>Score</th><th>Control</th><th>Asset</th><th>Subject</th><th>Why</th><th>Severity</th><th>Lifecycle</th></tr></thead>
            <tbody>
              {topFindings.items.length === 0 && <EmptyRow colSpan={7}>No open risk findings.</EmptyRow>}
              {topFindings.items.map((f) => (
                <tr key={f.finding_id}>
                  <td><span className={`badge ${f.rating}`}>{f.score}</span></td>
                  <td>{f.control_id}<div className="muted small">{f.category}</div></td>
                  <td>{f.hostname ?? f.asset_id}</td>
                  <td className="muted small wrap">{f.subject_key || "—"}</td>
                  <td><FactorChips chips={factorChips(f.factors, f.known_exploited)} /></td>
                  <td>{f.severity}<div className="muted small">{f.status}</div></td>
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

function rank(level: string): number {
  return ["Low", "Medium", "High", "Critical"].indexOf(level);
}
