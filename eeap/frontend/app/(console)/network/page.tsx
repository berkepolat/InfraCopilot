import Link from "next/link";
import { gatewayFetch, type NetworkService } from "@/lib/gateway";
import { EmptyRow, NoAccess, PageHeader, formatDate, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

function detail(s: NetworkService): string | null {
  const d = s.details;
  if (d.nla_required === false) return "RDP without Network Level Authentication";
  if (d.nla_required === true) return "RDP requires NLA";
  if (typeof d.subject_cn === "string") return `certificate ${d.subject_cn}${d.self_signed ? " (self-signed)" : ""}`;
  if (typeof d.http_server === "string") return d.http_server;
  if (typeof d.banner === "string") return d.banner;
  return null;
}

export default async function NetworkPage({ searchParams }: { searchParams: { state?: string; ip?: string } }) {
  const state = searchParams.state === "closed" ? "closed" : "open";
  const query = new URLSearchParams({ state, limit: "1000" });
  if (searchParams.ip) query.set("ip", searchParams.ip);
  const services = await optional(() => gatewayFetch<{ items: NetworkService[] }>(`/api/v1/network-services?${query}`));

  const hosts = new Map<string, NetworkService[]>();
  for (const s of services?.items ?? []) hosts.set(s.ip, [...(hosts.get(s.ip) ?? []), s]);

  return (
    <>
      <PageHeader
        title="Network services"
        description="Open TCP ports and identified services from network scans (NET-006 … NET-009)."
      />
      <div className="tabs">
        <Link href="/network?state=open" className={state === "open" ? "tab active" : "tab"}>Open</Link>
        <Link href="/network?state=closed" className={state === "closed" ? "tab active" : "tab"}>Closed since last seen</Link>
        {searchParams.ip && <Link href={`/network?state=${state}`} className="tab">Clear host filter ({searchParams.ip}) ✕</Link>}
      </div>

      {services === null ? <NoAccess what="network services" /> : (
        <>
          {hosts.size > 0 && !searchParams.ip && (
            <div className="chips">
              {[...hosts.entries()].map(([ip, list]) => (
                <Link key={ip} href={`/network?state=${state}&ip=${ip}`} className="chip">
                  {ip} <span className="muted">{list.length}</span>
                </Link>
              ))}
            </div>
          )}
          <table>
            <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>TLS</th><th>Details</th><th>{state === "open" ? "Last seen" : "Closed"}</th></tr></thead>
            <tbody>
              {services.items.length === 0 && (
                <EmptyRow colSpan={7}>
                  {state === "open" ? "No open ports discovered. Run a network scan from Assessments." : "No closed services."}
                </EmptyRow>
              )}
              {services.items.map((s) => (
                <tr key={s.service_id}>
                  <td><Link href={`/network?state=${state}&ip=${s.ip}`}>{s.ip}</Link><div className="muted small">{s.asset_id}</div></td>
                  <td className="mono">{s.port}/{s.transport}</td>
                  <td>{s.service}</td>
                  <td className="small">{[s.product, s.version].filter(Boolean).join(" ") || "—"}</td>
                  <td className="small">{s.tls_version ?? "—"}</td>
                  <td className="muted small wrap">{detail(s) ?? "—"}</td>
                  <td className="small">{formatDate(state === "open" ? s.last_seen_at : s.closed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}
