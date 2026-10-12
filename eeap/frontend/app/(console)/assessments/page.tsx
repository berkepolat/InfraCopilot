import { RunAssessment } from "@/components/RunAssessment";
import { gatewayFetch, type AssessmentRun, type Page } from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, Section, formatDate, getMe, optional, runModule, runSummary } from "@/lib/ui";

export const dynamic = "force-dynamic";

export default async function AssessmentsPage() {
  const [me, runs] = await Promise.all([
    getMe(),
    optional(() => gatewayFetch<Page<AssessmentRun>>("/api/v1/assessments/runs?limit=50")),
  ]);
  const canRun = me.permissions.includes("assessments:run");

  return (
    <>
      <PageHeader title="Assessments" description="Start read-only assessments and follow their results." />
      {canRun && <RunAssessment />}

      <Section title="Run history">
        {runs === null ? <NoAccess what="assessment runs" /> : (
          <table>
            <thead><tr><th>Started</th><th>Type</th><th>Trigger</th><th>Status</th><th>Result</th><th>Completed</th></tr></thead>
            <tbody>
              {runs.items.length === 0 && <EmptyRow colSpan={6}>No assessment runs yet.</EmptyRow>}
              {runs.items.map((r) => (
                <tr key={r.run_id}>
                  <td className="small">{formatDate(r.created_at)}</td>
                  <td>{runModule(r)}</td>
                  <td className="muted">{r.trigger}</td>
                  <td><span className={`status ${r.status}`}>{r.status.replace("_", " ")}</span></td>
                  <td className="muted small">{runSummary(r)}</td>
                  <td className="small">{formatDate(r.completed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}
