import { redirect } from "next/navigation";
import {
  GatewayError,
  gatewayFetch,
  type Asset,
  type AssessmentRun,
  type Control,
  type Me,
  type Page,
  type Rating,
  type RiskSummary,
  type TopFinding,
} from "@/lib/gateway";
import { RunAssessment } from "./RunAssessment";
import { SignOut } from "./SignOut";

function runSummary(run: AssessmentRun): string {
  const s = run.stats;
  if (s.error) return s.error;
  if (run.trigger === "import") return `${s.accepted ?? 0} accepted, ${s.rejected ?? 0} rejected`;
  if (s.created === undefined) return "";
  if (s.module === "NET" || (s.targets && s.targets.length)) {
    const n = s.targets?.length ?? 0;
    return `NET · ${n} IP${n === 1 ? "" : "s"} · ${s.created} new, ${s.updated ?? 0} changed, ${s.resolved ?? 0} resolved`;
  }
  return `${s.domain ?? "AD"} · ${s.created} new, ${s.updated ?? 0} changed, ${s.resolved ?? 0} resolved`;
}

export const dynamic = "force-dynamic";

const RATINGS: Rating[] = ["Critical", "High", "Medium", "Low"];

async function optional<T>(load: () => Promise<T>): Promise<T | null> {
  try {
    return await load();
  } catch (error) {
    if (error instanceof GatewayError && error.status === 403) return null;
    throw error;
  }
}

export default async function Dashboard() {
  let me: Me;
  try {
    me = await gatewayFetch<Me>("/api/v1/auth/me");
  } catch (error) {
    if (error instanceof GatewayError && error.status === 401) redirect("/login");
    throw error;
  }

  const [assets, controls, risk, topFindings, runs] = await Promise.all([
    optional(() => gatewayFetch<Page<Asset>>("/api/v1/assets?limit=100")),
    optional(() => gatewayFetch<Control[]>("/api/v1/controls")),
    optional(() => gatewayFetch<RiskSummary>("/api/v1/risk/summary")),
    optional(() => gatewayFetch<{ items: TopFinding[] }>("/api/v1/risk/top-findings?limit=15")),
    optional(() => gatewayFetch<Page<AssessmentRun>>("/api/v1/assessments/runs?limit=5")),
  ]);
  const canRun = me.permissions.includes("assessments:run");

  const tier0 = assets?.items.filter((a) => a.tier === "Tier0").length ?? 0;
  const exposure = risk?.exposure_score ?? null;
  const findingsByRating = risk?.open_by_rating.finding ?? {};
  const openFindings = RATINGS.reduce((sum, r) => sum + (findingsByRating[r] ?? 0), 0);

  return (
    <>
      <header className="top">
        <strong>EEAP</strong>
        <span className="muted">
          {me.username} · {me.roles.join(", ")} · <SignOut />
        </span>
      </header>
      <main>
        <div className="cards">
          <div className="card">
            <div className="label">Exposure score</div>
            <div className="value">
              {exposure ? (
                <>
                  {exposure.score} <span className={`badge ${exposure.rating}`}>{exposure.rating}</span>
                </>
              ) : (
                "—"
              )}
            </div>
          </div>
          <div className="card">
            <div className="label">Open risk findings</div>
            <div className="value">{risk ? openFindings : "—"}</div>
            {risk && (
              <div className="ratings">
                {RATINGS.map((r) => (
                  <span key={r} className={`badge ${r}`}>
                    {r[0]} {findingsByRating[r] ?? 0}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="card"><div className="label">Assets</div><div className="value">{assets?.items.length ?? "—"}</div></div>
          <div className="card"><div className="label">Tier-0 assets</div><div className="value">{assets ? tier0 : "—"}</div></div>
        </div>

        <h2>Assessments</h2>
        {canRun && <RunAssessment />}
        {runs === null ? <p className="muted">You do not have permission to view assessment runs.</p> : (
          <table>
            <thead><tr><th>Started</th><th>Trigger</th><th>Status</th><th>Result</th></tr></thead>
            <tbody>
              {runs.items.length === 0 && <tr><td colSpan={4} className="muted">No assessment runs yet.</td></tr>}
              {runs.items.map((r) => (
                <tr key={r.run_id}>
                  <td className="small">{new Date(r.created_at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</td>
                  <td>{r.trigger}</td>
                  <td>{r.status.replace("_", " ")}</td>
                  <td className="muted small">{runSummary(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h2>Top risks</h2>
        {topFindings === null ? <p className="muted">You do not have permission to view risk scores.</p> : (
          <table>
            <thead><tr><th>Score</th><th>Control</th><th>Asset</th><th>Subject</th><th>Severity</th><th>Status</th><th>Lifecycle</th></tr></thead>
            <tbody>
              {topFindings.items.length === 0 && <tr><td colSpan={7} className="muted">No open risk findings. Import findings to get started.</td></tr>}
              {topFindings.items.map((f) => (
                <tr key={f.finding_id}>
                  <td><span className={`badge ${f.rating}`}>{f.score}</span></td>
                  <td>{f.control_id}<div className="muted small">{f.category}</div></td>
                  <td>{f.hostname ?? f.asset_id}</td>
                  <td className="muted small">{f.subject_key || "—"}</td>
                  <td>{f.severity}</td>
                  <td>{f.status}</td>
                  <td className="muted">{f.lifecycle_state.replace("_", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h2>Assets</h2>
        {assets === null ? <p className="muted">You do not have permission to view assets.</p> : (
          <table>
            <thead><tr><th>Asset ID</th><th>Hostname</th><th>Type</th><th>Criticality</th><th>Tier</th><th>Environment</th><th>Owner</th></tr></thead>
            <tbody>
              {assets.items.length === 0 && <tr><td colSpan={7} className="muted">No assets yet.</td></tr>}
              {assets.items.map((a) => (
                <tr key={a.asset_id}>
                  <td>{a.asset_id}</td><td>{a.hostname}</td><td>{a.asset_type}</td>
                  <td><span className={`badge ${a.criticality}`}>{a.criticality}</span></td>
                  <td>{a.tier}</td><td>{a.environment}</td><td>{a.owner ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h2>Control catalog</h2>
        {controls === null ? <p className="muted">You do not have permission to view controls.</p> : (
          <table>
            <thead><tr><th>Control</th><th>Name</th><th>Module</th><th>Category</th><th>Default severity</th><th>Collector</th></tr></thead>
            <tbody>
              {controls.map((c) => (
                <tr key={c.control_id}>
                  <td>{c.control_id}</td><td>{c.name}</td><td>{c.module}</td><td>{c.category}</td>
                  <td><span className={`badge ${c.default_severity}`}>{c.default_severity}</span></td>
                  <td className="muted">{c.enabled
                    ? (c.module === "AD" ? "LDAP (read-only)" : c.module === "NET" ? "IP probes (read-only)" : "Enabled")
                    : "Import only"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </main>
    </>
  );
}
