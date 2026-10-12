import { gatewayFetch, type Control } from "@/lib/gateway";
import { NoAccess, PageHeader, Section, optional } from "@/lib/ui";

export const dynamic = "force-dynamic";

const MODULES: Record<string, string> = {
  AD: "Active Directory — LDAP (read-only)",
  NET: "Network — IP probes and port scan (read-only)",
  WIN: "Windows hosts",
  LINUX: "Linux hosts",
  CLOUD: "Cloud",
  IMPORT: "Imported findings",
};

export default async function ControlsPage() {
  const controls = await optional(() => gatewayFetch<Control[]>("/api/v1/controls"));
  const header = <PageHeader title="Control catalog" description="Checks the platform evaluates, grouped by module." />;
  if (controls === null) return <>{header}<NoAccess what="controls" /></>;

  const modules = [...new Set(controls.map((c) => c.module))];
  return (
    <>
      {header}
      {modules.map((module) => {
        const list = controls.filter((c) => c.module === module);
        return (
          <Section key={module} title={MODULES[module] ?? module}>
            <table>
              <thead><tr><th>Control</th><th>Name</th><th>Category</th><th>Default severity</th><th>Execution</th></tr></thead>
              <tbody>
                {list.map((c) => (
                  <tr key={c.control_id}>
                    <td className="mono">{c.control_id}</td>
                    <td>{c.name}</td>
                    <td className="muted">{c.category}</td>
                    <td><span className={`badge ${c.default_severity}`}>{c.default_severity}</span></td>
                    <td className="muted small">{c.enabled ? "Built-in collector" : "Import only"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
        );
      })}
    </>
  );
}
