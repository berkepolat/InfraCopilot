import { gatewayFetch, type MitreTechnique } from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, Section, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

export default async function AttackPage() {
  const mitre = await optional(() => gatewayFetch<{ techniques: MitreTechnique[] }>("/api/v1/risk/mitre"));
  const header = (
    <PageHeader
      title="MITRE ATT&CK exposure"
      description="Techniques that current open weaknesses make easier, as defensive context for prioritization."
    />
  );
  if (mitre === null) return <>{header}<NoAccess what="the ATT&CK mapping" /></>;

  const tactics = new Map<string, number>();
  for (const t of mitre.techniques) for (const tactic of t.tactics) tactics.set(tactic, (tactics.get(tactic) ?? 0) + 1);

  return (
    <>
      {header}
      {tactics.size > 0 && (
        <div className="chips">
          {[...tactics.entries()].sort((a, b) => b[1] - a[1]).map(([tactic, n]) => (
            <span key={tactic} className="chip">{tactic.replaceAll("-", " ")} <span className="muted">{n}</span></span>
          ))}
        </div>
      )}
      <Section title="Techniques">
        <table>
          <thead><tr><th>Top score</th><th>Technique</th><th>Tactics</th><th>Open findings</th><th>Controls</th></tr></thead>
          <tbody>
            {mitre.techniques.length === 0 && <EmptyRow colSpan={5}>No open weaknesses mapped to ATT&amp;CK techniques.</EmptyRow>}
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
      </Section>
    </>
  );
}
