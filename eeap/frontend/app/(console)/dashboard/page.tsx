import Link from "next/link";
import {
  gatewayFetch,
  type Asset,
  type AssessmentRun,
  type NetworkService,
  type Page,
  type Rating,
  type RemediationItem,
  type RiskSummary,
} from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, Section, formatDate, optional, runModule, runSummary } from "@/lib/ui";

export const dynamic = "force-dynamic";

const RATINGS: Rating[] = ["Critical", "High", "Medium", "Low"];

export default async function Overview() {
  const [assets, risk, runs, roadmap, services] = await Promise.all([
    optional(() => gatewayFetch<Page<Asset>>("/api/v1/assets?limit=100")),
    optional(() => gatewayFetch<RiskSummary>("/api/v1/risk/summary")),
    optional(() => gatewayFetch<Page<AssessmentRun>>("/api/v1/assessments/runs?limit=5")),
    optional(() => gatewayFetch<{ items: RemediationItem[] }>("/api/v1/risk/remediation?limit=5")),
    optional(() => gatewayFetch<{ items: NetworkService[] }>("/api/v1/network-services?state=open&limit=1000")),
  ]);

  const exposure = risk?.exposure_score ?? null;
  const findingsByRating = risk?.open_by_rating.finding ?? {};
  const openFindings = RATINGS.reduce((sum, r) => sum + (findingsByRating[r] ?? 0), 0);
  const tier0 = assets?.items.filter((a) => a.tier === "Tier0").length ?? 0;
  const scenarios = risk?.top_scenarios?.slice(0, 5) ?? [];

  return (
    <>
      <PageHeader title="Overview" description="Current exposure across Active Directory and the scanned network." />

      <div className="cards">
        <Link href="/risk" className="card">
          <div className="label">Exposure score</div>
          <div className="value">
            {exposure ? <>{exposure.score} <span className={`badge ${exposure.rating}`}>{exposure.rating}</span></> : "—"}
          </div>
        </Link>
        <Link href="/risk" className="card">
          <div className="label">Open risk findings</div>
          <div className="value">{risk ? openFindings : "—"}</div>
          {risk && (
            <div className="ratings">
              {RATINGS.map((r) => <span key={r} className={`badge ${r}`}>{r[0]} {findingsByRating[r] ?? 0}</span>)}
            </div>
          )}
        </Link>
        <Link href="/risk" className="card">
          <div className="label">Active attack scenarios</div>
          <div className="value">{risk ? risk.active_scenarios : "—"}</div>
        </Link>
        <Link href="/assets" className="card">
          <div className="label">Assets</div>
          <div className="value">{assets?.items.length ?? "—"}</div>
          {assets && <div className="muted small">{tier0} Tier-0</div>}
        </Link>
        <Link href="/network" className="card">
          <div className="label">Open network services</div>
          <div className="value">{services?.items.length ?? "—"}</div>
          {services && <div className="muted small">{new Set(services.items.map((s) => s.ip)).size} hosts</div>}
        </Link>
      </div>

      <div className="two-col">
        <Section title="Top attack scenarios" link={{ href: "/risk", label: "All risks" }}>
          {risk === null ? <NoAccess what="risk scenarios" /> : (
            <table>
              <thead><tr><th>Score</th><th>Scenario</th></tr></thead>
              <tbody>
                {scenarios.length === 0 && <EmptyRow colSpan={2}>No correlated risk scenarios.</EmptyRow>}
                {scenarios.map((s) => (
                  <tr key={s.scenario_id}>
                    <td><span className={`badge ${s.rating}`}>{s.score}</span></td>
                    <td>{s.title}<div className="muted small">{s.affected_asset_ids.join(", ") || "—"}</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>

        <Section title="Next remediation actions" link={{ href: "/remediation", label: "Full roadmap" }}>
          {roadmap === null ? <NoAccess what="the remediation roadmap" /> : (
            <table>
              <thead><tr><th>#</th><th>Action</th><th>Reduction</th></tr></thead>
              <tbody>
                {roadmap.items.length === 0 && <EmptyRow colSpan={3}>No open remediation items.</EmptyRow>}
                {roadmap.items.map((i) => (
                  <tr key={i.item_id}>
                    <td>{i.priority}</td>
                    <td>{i.title}<div className="muted small">{i.roadmap_phase} · {i.effort} effort</div></td>
                    <td>{i.expected_risk_reduction}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      </div>

      <Section title="Recent assessments" link={{ href: "/assessments", label: "Run or view all" }}>
        {runs === null ? <NoAccess what="assessment runs" /> : (
          <table>
            <thead><tr><th>Started</th><th>Type</th><th>Status</th><th>Result</th></tr></thead>
            <tbody>
              {runs.items.length === 0 && <EmptyRow colSpan={4}>No assessment runs yet. Start one from Assessments.</EmptyRow>}
              {runs.items.map((r) => (
                <tr key={r.run_id}>
                  <td className="small">{formatDate(r.created_at)}</td>
                  <td>{runModule(r)}</td>
                  <td><span className={`status ${r.status}`}>{r.status.replace("_", " ")}</span></td>
                  <td className="muted small">{runSummary(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}
