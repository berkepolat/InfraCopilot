import Link from "next/link";
import { gatewayFetch, type Asset, type Page } from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

export default async function AssetsPage() {
  const assets = await optional(() => gatewayFetch<Page<Asset>>("/api/v1/assets?limit=200"));
  const header = <PageHeader title="Assets" description="Inventory built from AD, network scans and imports." />;
  if (assets === null) return <>{header}<NoAccess what="assets" /></>;

  return (
    <>
      {header}
      <table>
        <thead><tr><th>Asset ID</th><th>Hostname</th><th>Type</th><th>Criticality</th><th>Tier</th><th>Environment</th><th>Owner</th></tr></thead>
        <tbody>
          {assets.items.length === 0 && <EmptyRow colSpan={7}>No assets yet.</EmptyRow>}
          {assets.items.map((a) => (
            <tr key={a.asset_id}>
              <td className="mono small">{a.asset_id}</td>
              <td>
                {a.asset_id.startsWith("IP") ? <Link href={`/network?ip=${a.hostname}`}>{a.hostname}</Link> : a.hostname}
              </td>
              <td>{a.asset_type}</td>
              <td><span className={`badge ${a.criticality}`}>{a.criticality}</span></td>
              <td>{a.tier}</td>
              <td>{a.environment}</td>
              <td>{a.owner ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {assets.next_cursor && <p className="muted small">Showing the first {assets.items.length} assets.</p>}
    </>
  );
}
