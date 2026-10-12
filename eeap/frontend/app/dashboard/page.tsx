import { redirect } from "next/navigation";
import {
  GatewayError,
  gatewayFetch,
  type Asset,
  type AssessmentRun,
  type ConcentrationArea,
  type Control,
  type GraphAnalysis,
  type Me,
  type MitreTechnique,
  type NetworkService,
  type Page,
  type Rating,
  type RemediationItem,
  type Report,
  type RiskSummary,
  type TopFinding,
} from "@/lib/gateway";
import { RequestReport } from "./RequestReport";
import { RunAssessment } from "./RunAssessment";
import { SignOut } from "./SignOut";

function runSummary(run: AssessmentRun): string {
  const s = run.stats;
  if (s.error) return s.error;
  if (run.trigger === "import") return `${s.accepted ?? 0} accepted, ${s.rejected ?? 0} rejected`;
  if (s.created === undefined) return "";
  if (s.module === "NET" || (s.targets && s.targets.length)) {
    const n = s.targets?.length ?? 0;
    const ports = s.open_ports !== undefined ? ` · ${s.open_ports} open port${s.open_ports === 1 ? "" : "s"}` : "";
    return `NET · ${n} IP${n === 1 ? "" : "s"}${ports} · ${s.created} new, ${s.updated ?? 0} changed, ${s.resolved ?? 0} resolved`;
  }
  const rels = s.relationships !== undefined ? ` · ${s.relationships} relationships` : "";
  return `${s.domain ?? "AD"} · ${s.created} new, ${s.updated ?? 0} changed, ${s.resolved ?? 0} resolved${rels}`;
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

  const [assets, controls, risk, topFindings, runs, graph, areas, roadmap, mitre, reports, services] = await Promise.all([
    optional(() => gatewayFetch<Page<Asset>>("/api/v1/assets?limit=100")),
    optional(() => gatewayFetch<Control[]>("/api/v1/controls")),
    optional(() => gatewayFetch<RiskSummary>("/api/v1/risk/summary")),
    optional(() => gatewayFetch<{ items: TopFinding[] }>("/api/v1/risk/top-findings?limit=15")),
    optional(() => gatewayFetch<Page<AssessmentRun>>("/api/v1/assessments/runs?limit=5")),
    optional(() => gatewayFetch<{ analysis: GraphAnalysis | null }>("/api/v1/graph/analysis/latest")),
    optional(() => gatewayFetch<{ items: ConcentrationArea[] }>("/api/v1/graph/concentration-areas?limit=10")),
    optional(() => gatewayFetch<{ items: RemediationItem[] }>("/api/v1/risk/remediation?limit=20")),
    optional(() => gatewayFetch<{ techniques: MitreTechnique[] }>("/api/v1/risk/mitre")),
    optional(() => gatewayFetch<Page<Report>>("/api/v1/reports?limit=10")),
    optional(() => gatewayFetch<{ items: NetworkService[] }>("/api/v1/network-services?state=open&limit=200")),
  ]);
  const analysis = graph?.analysis ?? null;
  const canRun = me.permissions.includes("assessments:run");
  const canReport = me.permissions.includes("reports:create");

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

        <h2>Risk scenarios{risk ? ` (${risk.active_scenarios} active)` : ""}</h2>
        {risk === null ? <p className="muted">You do not have permission to view risk scenarios.</p> : (
          <table>
            <thead><tr><th>Score</th><th>Scenario</th><th>Chain</th><th>Assets</th></tr></thead>
            <tbody>
              {(risk.top_scenarios?.length ?? 0) === 0 && <tr><td colSpan={4} className="muted">No correlated risk scenarios.</td></tr>}
              {risk.top_scenarios?.map((s) => (
                <tr key={s.scenario_id}>
                  <td><span className={`badge ${s.rating}`}>{s.score}</span></td>
                  <td>{s.title}<div className="muted small">{s.rule_id} · {s.summary}</div></td>
                  <td className="small">
                    {s.stages.filter((st) => st.matched).map((st) => st.name).join(" → ")}
                  </td>
                  <td className="muted small">{s.affected_asset_ids.join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h2>Remediation roadmap</h2>
        {roadmap === null ? <p className="muted">You do not have permission to view the remediation roadmap.</p> : (
          <table>
            <thead><tr><th>#</th><th>Phase</th><th>Action</th><th>Effort</th><th>Risk reduction</th><th>Breaks scenarios</th><th>Status</th></tr></thead>
            <tbody>
              {roadmap.items.length === 0 && <tr><td colSpan={7} className="muted">No open remediation items.</td></tr>}
              {roadmap.items.map((i) => (
                <tr key={i.item_id}>
                  <td>{i.priority}</td>
                  <td>{i.roadmap_phase}</td>
                  <td>
                    {i.title}
                    <div className="muted small">
                      {i.control_id} · {i.open_findings} open finding{i.open_findings === 1 ? "" : "s"}
                      {i.techniques.length > 0 && ` · ATT&CK ${i.techniques.map((t) => t.technique_id).join(", ")}`}
                    </div>
                  </td>
                  <td>{i.effort}</td>
                  <td>{i.expected_risk_reduction}%</td>
                  <td className="muted small">{i.scenarios.map((s) => s.title).join("; ") || "—"}</td>
                  <td>{i.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h2>MITRE ATT&amp;CK exposure</h2>
        {mitre === null ? <p className="muted">You do not have permission to view the ATT&amp;CK mapping.</p> : (
          <table>
            <thead><tr><th>Top score</th><th>Technique</th><th>Tactics</th><th>Open findings</th><th>Controls</th></tr></thead>
            <tbody>
              {mitre.techniques.length === 0 && <tr><td colSpan={5} className="muted">No open weaknesses mapped to ATT&amp;CK techniques.</td></tr>}
              {mitre.techniques.map((t) => (
                <tr key={t.technique_id}>
                  <td>{t.max_score}</td>
                  <td><a href={t.url} target="_blank" rel="noreferrer">{t.technique_id}</a> {t.name}</td>
                  <td className="muted small">{t.tactics.join(", ")}</td>
                  <td>{t.open_findings}</td>
                  <td className="muted small">{t.controls.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h2>Reports</h2>
        {canReport && <RequestReport />}
        {reports === null ? <p className="muted">You do not have permission to view reports.</p> : (
          <table>
            <thead><tr><th>Requested</th><th>Report</th><th>Data as of</th><th>Status</th><th>Download</th></tr></thead>
            <tbody>
              {reports.items.length === 0 && <tr><td colSpan={5} className="muted">No reports yet.</td></tr>}
              {reports.items.map((r) => (
                <tr key={r.report_id}>
                  <td className="small">{new Date(r.created_at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</td>
                  <td>{r.title}</td>
                  <td className="small">{new Date(r.snapshot_at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</td>
                  <td>{r.status}{r.error && <div className="muted small">{r.error}</div>}</td>
                  <td>
                    {r.available_formats.map((f) => (
                      <a key={f} href={`/api/reports/${r.report_id}/download/${f}`} className="small" style={{ marginRight: 8 }}>
                        {f.toUpperCase()}
                      </a>
                    ))}
                  </td>
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

        <h2>Exposure graph</h2>
        {graph === null ? <p className="muted">You do not have permission to view the exposure graph.</p> : !analysis ? (
          <p className="muted">No graph analysis yet. Run an AD assessment to collect relationships.</p>
        ) : (
          <>
            <div className="cards">
              <div className="card"><div className="label">Objects with a path to Tier 0</div><div className="value">{analysis.exposed_nodes}</div></div>
              <div className="card"><div className="label">One hop from Tier 0</div><div className="value">{analysis.one_hop_nodes}</div></div>
              <div className="card"><div className="label">Tier-0 objects</div><div className="value">{analysis.tier0_nodes}</div></div>
              <div className="card">
                <div className="label">Graph</div>
                <div className="value">{analysis.node_count}<span className="muted small"> nodes · {analysis.edge_count} edges</span></div>
              </div>
            </div>
            <table>
              <thead><tr><th>Score</th><th>Concentration</th><th>Anchor</th><th>Objects</th><th>Summary</th></tr></thead>
              <tbody>
                {(areas?.items.length ?? 0) === 0 && <tr><td colSpan={5} className="muted">No risk concentration areas.</td></tr>}
                {areas?.items.map((a) => (
                  <tr key={a.area_id}>
                    <td>{a.score.toFixed(2)}</td>
                    <td>{a.area_type.replaceAll("_", " ")}</td>
                    <td>{a.anchor_display_name}<div className="muted small">{a.anchor_node_type}</div></td>
                    <td>{a.member_count}</td>
                    <td className="muted small">{a.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted small">
              Analysed {new Date(analysis.completed_at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC.
            </p>
          </>
        )}

        <h2>Network services{services ? ` (${services.items.length} open)` : ""}</h2>
        {services === null ? <p className="muted">You do not have permission to view network services.</p> : (
          <table>
            <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>TLS</th><th>Last seen</th></tr></thead>
            <tbody>
              {services.items.length === 0 && <tr><td colSpan={6} className="muted">No open ports discovered. Run a network scan.</td></tr>}
              {services.items.map((s) => (
                <tr key={s.service_id}>
                  <td>{s.ip}<div className="muted small">{s.asset_id}</div></td>
                  <td>{s.port}/{s.transport}</td>
                  <td>{s.service}</td>
                  <td className="small">
                    {[s.product, s.version].filter(Boolean).join(" ") || "—"}
                    {typeof s.details.banner === "string" && <div className="muted small">{s.details.banner}</div>}
                  </td>
                  <td className="small">{s.tls_version ?? "—"}</td>
                  <td className="small">{new Date(s.last_seen_at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</td>
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
