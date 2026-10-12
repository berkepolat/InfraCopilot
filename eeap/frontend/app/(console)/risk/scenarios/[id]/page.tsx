import Link from "next/link";
import { notFound } from "next/navigation";
import { Fragment } from "react";
import { GatewayError, gatewayFetch, type ScenarioDetail, type ScenarioFinding, type ScenarioStage } from "@/lib/gateway";
import { VerifyFix } from "@/components/VerifyFix";
import { EXPOSURE_CLASS_LABELS, TACTIC_LABELS } from "@/lib/risk";
import { EmptyRow, NoAccess, PageHeader, Section, formatDate, getMe, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHOWN_FINDINGS = 4;

async function load(id: string): Promise<ScenarioDetail | null> {
  try {
    return await optional(() => gatewayFetch<ScenarioDetail>(`/api/v1/risk/scenarios/${id}`));
  } catch (error) {
    if (error instanceof GatewayError && error.status === 404) notFound();
    throw error;
  }
}

export default async function ScenarioPage({ params }: { params: { id: string } }) {
  if (!UUID.test(params.id)) notFound();
  const [me, scenario] = await Promise.all([getMe(), load(params.id)]);
  const canVerify = me.permissions.includes("assessments:run");
  if (scenario === null) return <><PageHeader title="Attack scenario" /><NoAccess what="risk scenarios" /></>;

  const byId = new Map(scenario.findings.map((f) => [f.finding_id, f]));
  const assetName = (id: string | null) => (id ? scenario.asset_names[id] ?? id : "—");
  const breakers = scenario.stages.filter((s) => s.breaks_chain);

  return (
    <>
      <PageHeader
        title={scenario.title}
        description={scenario.summary}
        actions={<Link href="/risk" className="small">← All risks</Link>}
      />
      <div className="cards">
        <div className="card">
          <div className="label">Scenario score</div>
          <div className="value">{scenario.score} <span className={`badge ${scenario.rating}`}>{scenario.rating}</span></div>
        </div>
        <div className="card">
          <div className="label">Status</div>
          <div className="value small-value"><span className={`status ${scenario.status}`}>{scenario.status}</span></div>
        </div>
        <div className="card">
          <div className="label">Affected assets</div>
          <div className="value small-value">{scenario.affected_asset_ids.map((a) => assetName(a)).join(", ") || "—"}</div>
        </div>
        <div className="card">
          <div className="label">Detected</div>
          <div className="value small-value">{formatDate(scenario.first_detected_at)}</div>
          <div className="muted small">{scenario.rule_id} · evaluated {formatDate(scenario.last_evaluated_at)}</div>
        </div>
      </div>

      <Section title="Chain">
        <div className="chain">
          {scenario.stages.map((stage, i) => (
            <Fragment key={stage.order}>
              {i > 0 && <div className="chain-arrow" aria-hidden>→</div>}
              <StageCard stage={stage} findings={stage.finding_ids.map((id) => byId.get(id)).filter(isFinding)} assetName={assetName} />
            </Fragment>
          ))}
        </div>
        <p className="muted small">
          Stages come from open findings, the exposure graph and the latest port scan; the chain describes exposure,
          not a confirmed compromise. Score: highest stage finding score
          {scenario.factors?.max_stage_finding_score !== undefined ? ` (${scenario.factors.max_stage_finding_score})` : ""} plus
          5 per additional matched stage{scenario.factors?.stage_bonus ? ` (+${scenario.factors.stage_bonus})` : ""}.
        </p>
      </Section>

      <Section title="How to break the chain">
        {breakers.length === 0 ? (
          <p className="muted">No single stage ends this scenario; fixing stages lowers its score until fewer than the required stages remain.</p>
        ) : (
          <ol className="break-list">
            {breakers.map((stage) => (
              <li key={stage.order}>
                <strong>{stage.name}</strong>
                <BreakAdvice stage={stage} findings={stage.finding_ids.map((id) => byId.get(id)).filter(isFinding)} controls={scenario.controls} />
                {canVerify && stage.finding_ids.length > 0 && (
                  <VerifyFix findingIds={stage.finding_ids} label="Verify fixes for this stage" />
                )}
              </li>
            ))}
          </ol>
        )}
      </Section>

      <Section title="Supporting findings">
        <table>
          <thead><tr><th>Score</th><th>Stage</th><th>Control</th><th>Asset</th><th>Subject</th><th>ATT&amp;CK</th><th>Lifecycle</th></tr></thead>
          <tbody>
            {scenario.findings.length === 0 && <EmptyRow colSpan={7}>No findings are attached to this scenario.</EmptyRow>}
            {scenario.findings.map((f) => (
              <tr key={f.finding_id}>
                <td><span className={`badge ${f.rating}`}>{f.score}</span></td>
                <td className="small">{scenario.stages.find((s) => s.order === f.stage_order)?.name ?? f.stage_order}</td>
                <td>
                  {f.control_id ?? "—"}
                  {f.known_exploited && <div className="factors"><span className="factor hot">actively exploited</span></div>}
                </td>
                <td>{assetName(f.asset_id)}</td>
                <td className="muted small wrap">{f.subject_key || "—"}</td>
                <td className="small">
                  {(f.control_id ? scenario.controls[f.control_id]?.techniques ?? [] : []).map((t) => (
                    <div key={t.technique_id}><span className="mono">{t.technique_id}</span> {t.name}</div>
                  ))}
                </td>
                <td className="muted">{f.lifecycle_state?.replace("_", " ") ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </>
  );
}

function isFinding(f: ScenarioFinding | undefined): f is ScenarioFinding {
  return f !== undefined;
}

function StageCard({ stage, findings, assetName }: {
  stage: ScenarioStage; findings: ScenarioFinding[]; assetName: (id: string | null) => string;
}) {
  const classes = ["chain-stage", stage.derived ? "derived" : "", stage.matched ? "" : "absent", stage.breaks_chain ? "breaker" : ""];
  return (
    <div className={classes.filter(Boolean).join(" ")}>
      <div className="tactic">{stage.tactic ? TACTIC_LABELS[stage.tactic] ?? stage.tactic : stage.derived ? "Consequence" : "Stage"}</div>
      <div className="stage-name">{stage.order}. {stage.name}</div>
      {!stage.matched && <div className="muted small">Not present</div>}
      {stage.derived && <div className="muted small">Outcome if the chain is not broken</div>}
      {stage.exposure && (
        <div className="small">
          {stage.exposure.services.join(", ")}
          {stage.exposure.classes.length > 0 && (
            <div className="muted">{stage.exposure.classes.map((c) => EXPOSURE_CLASS_LABELS[c] ?? c).join(", ")}</div>
          )}
        </div>
      )}
      {stage.graph && (
        <div className="small">
          {stage.graph.is_tier0 ? "Tier-0 asset" : `${stage.graph.min_hops} relationship${stage.graph.min_hops === 1 ? "" : "s"} to Tier 0`}
        </div>
      )}
      {findings.length > 0 && (
        <ul className="stage-findings">
          {findings.slice(0, SHOWN_FINDINGS).map((f) => (
            <li key={f.finding_id}>
              <span className={`badge ${f.rating}`}>{f.score}</span> {f.control_id}
              {f.known_exploited && <> <span className="factor hot">KEV</span></>}
              <div className="muted wrap">{f.subject_key || assetName(f.asset_id)}</div>
            </li>
          ))}
          {findings.length > SHOWN_FINDINGS && <li className="muted">+{findings.length - SHOWN_FINDINGS} more</li>}
        </ul>
      )}
      {stage.breaks_chain && <div className="breaks">Fixing this stage breaks the chain</div>}
    </div>
  );
}

function BreakAdvice({ stage, findings, controls }: {
  stage: ScenarioStage; findings: ScenarioFinding[]; controls: ScenarioDetail["controls"];
}) {
  if (stage.exposure) {
    return (
      <p className="muted">
        Close or restrict {stage.exposure.services.join(", ")} to the management networks that need them (host or
        network firewall); the next port scan updates the exposure.
      </p>
    );
  }
  if (stage.graph) {
    return (
      <p className="muted">
        Remove the privileged relationships, sessions or group memberships that connect this object to Tier 0
        (see <Link href="/graph">Exposure graph</Link>).
      </p>
    );
  }
  const ids = [...new Set(findings.map((f) => f.control_id).filter((c): c is string => !!c))];
  return (
    <ul className="advice">
      {ids.map((id) => {
        const remediation = controls[id]?.remediation;
        const count = findings.filter((f) => f.control_id === id).length;
        return (
          <li key={id}>
            <span className="mono">{id}</span> ({count} finding{count === 1 ? "" : "s"})
            {remediation ? <>: {remediation.title} <span className="muted">· effort {remediation.effort}</span>
              <div className="muted small">{remediation.guidance}</div></> : null}
          </li>
        );
      })}
    </ul>
  );
}
