import { gatewayFetch, type ConcentrationArea, type GraphAnalysis } from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, Section, formatDate, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

export default async function GraphPage() {
  const [graph, areas] = await Promise.all([
    optional(() => gatewayFetch<{ analysis: GraphAnalysis | null }>("/api/v1/graph/analysis/latest")),
    optional(() => gatewayFetch<{ items: ConcentrationArea[] }>("/api/v1/graph/concentration-areas?limit=25")),
  ]);
  const header = (
    <PageHeader
      title="Exposure graph"
      description="Privilege relationships collected from Active Directory and where they concentrate risk towards Tier 0."
    />
  );
  if (graph === null) return <>{header}<NoAccess what="the exposure graph" /></>;
  const analysis = graph.analysis;
  if (!analysis) return <>{header}<p className="muted empty">No graph analysis yet. Run an AD assessment to collect relationships.</p></>;

  return (
    <>
      {header}
      <div className="cards">
        <div className="card"><div className="label">Objects with a path to Tier 0</div><div className="value">{analysis.exposed_nodes}</div></div>
        <div className="card"><div className="label">One hop from Tier 0</div><div className="value">{analysis.one_hop_nodes}</div></div>
        <div className="card"><div className="label">Tier-0 objects</div><div className="value">{analysis.tier0_nodes}</div></div>
        <div className="card">
          <div className="label">Graph size</div>
          <div className="value">{analysis.node_count}<span className="muted small"> nodes · {analysis.edge_count} edges</span></div>
        </div>
      </div>
      <Section title="Risk concentration areas">
        <table>
          <thead><tr><th>Score</th><th>Concentration</th><th>Anchor</th><th>Objects</th><th>Summary</th></tr></thead>
          <tbody>
            {(areas?.items.length ?? 0) === 0 && <EmptyRow colSpan={5}>No risk concentration areas.</EmptyRow>}
            {areas?.items.map((a) => (
              <tr key={a.area_id}>
                <td>{a.score.toFixed(2)}</td>
                <td>{a.area_type.replaceAll("_", " ")}</td>
                <td>{a.anchor_display_name}<div className="muted small">{a.anchor_node_type}</div></td>
                <td>{a.member_count}</td>
                <td className="muted small wrap">{a.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
      <p className="muted small">Analysed {formatDate(analysis.completed_at)}.</p>
    </>
  );
}
