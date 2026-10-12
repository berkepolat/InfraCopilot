import Link from "next/link";
import { AssetClassification } from "@/components/AssetClassification";
import { gatewayFetch, type Asset, type AssetExposure, type Page } from "@/lib/gateway";
import { exposureSummary } from "@/lib/risk";
import { EmptyRow, NoAccess, PageHeader, getMe, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

const LEVELS = ["Low", "Medium", "High", "Critical"];

export default async function AssetsPage() {
  const [me, assets, exposure] = await Promise.all([
    getMe(),
    optional(() => gatewayFetch<Page<Asset>>("/api/v1/assets?limit=200")),
    optional(() => gatewayFetch<{ items: AssetExposure[] }>("/api/v1/risk/exposure")),
  ]);
  const header = (
    <PageHeader
      title="Assets"
      description="Inventory built from AD, network scans and imports. Criticality and tier weigh into every risk score."
    />
  );
  if (assets === null) return <>{header}<NoAccess what="assets" /></>;
  const canEdit = me.permissions.includes("assets:write");
  const byAsset = new Map((exposure?.items ?? []).map((e) => [e.asset_id, e]));

  return (
    <>
      {header}
      <table>
        <thead>
          <tr>
            <th>Asset ID</th><th>Hostname</th><th>Type</th><th>Criticality / tier</th>
            {exposure !== null && <th>Network exposure</th>}<th>Environment</th><th>Owner</th>
          </tr>
        </thead>
        <tbody>
          {assets.items.length === 0 && <EmptyRow colSpan={7}>No assets yet.</EmptyRow>}
          {assets.items.map((a) => {
            const exp = byAsset.get(a.asset_id)?.exposure ?? null;
            const suggested = exp?.suggested_criticality ?? null;
            const raise = suggested && LEVELS.indexOf(suggested) > LEVELS.indexOf(a.criticality) ? suggested : null;
            return (
              <tr key={a.asset_id}>
                <td className="mono small">{a.asset_id}</td>
                <td>
                  {a.asset_id.startsWith("IP") ? <Link href={`/network?ip=${a.hostname}`}>{a.hostname}</Link> : a.hostname}
                </td>
                <td>{a.asset_type}</td>
                <td>
                  {canEdit ? (
                    <AssetClassification assetId={a.asset_id} criticality={a.criticality} tier={a.tier} suggested={raise} />
                  ) : (
                    <>
                      <span className={`badge ${a.criticality}`}>{a.criticality}</span> {a.tier}
                      {raise && <div className="muted small">suggested {raise}</div>}
                    </>
                  )}
                  {a.criticality_locked && <div className="muted small">set manually</div>}
                </td>
                {exposure !== null && (
                  <td className="small">
                    {byAsset.has(a.asset_id) ? exposureSummary(exp) : <span className="muted">not port scanned</span>}
                  </td>
                )}
                <td>{a.environment}</td>
                <td>{a.owner ?? "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {assets.next_cursor && <p className="muted small">Showing the first {assets.items.length} assets.</p>}
    </>
  );
}
