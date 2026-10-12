import { RequestReport } from "@/components/RequestReport";
import { gatewayFetch, type Page, type Report } from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, Section, formatDate, getMe, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

export default async function ReportsPage() {
  const [me, reports] = await Promise.all([
    getMe(),
    optional(() => gatewayFetch<Page<Report>>("/api/v1/reports?limit=50")),
  ]);
  const canReport = me.permissions.includes("reports:create");

  return (
    <>
      <PageHeader
        title="Reports"
        description="Executive, technical, remediation and ATT&CK reports from a point-in-time snapshot."
      />
      {canReport && <RequestReport />}
      <Section title="Generated reports">
        {reports === null ? <NoAccess what="reports" /> : (
          <table>
            <thead><tr><th>Requested</th><th>Report</th><th>Data as of</th><th>Status</th><th>Download</th></tr></thead>
            <tbody>
              {reports.items.length === 0 && <EmptyRow colSpan={5}>No reports yet.</EmptyRow>}
              {reports.items.map((r) => (
                <tr key={r.report_id}>
                  <td className="small">{formatDate(r.created_at)}</td>
                  <td>{r.title}</td>
                  <td className="small">{formatDate(r.snapshot_at)}</td>
                  <td><span className={`status ${r.status}`}>{r.status}</span>{r.error && <div className="muted small">{r.error}</div>}</td>
                  <td>
                    {r.available_formats.map((f) => (
                      <a key={f} href={`/api/reports/${r.report_id}/download/${f}`} className="download">{f.toUpperCase()}</a>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}
