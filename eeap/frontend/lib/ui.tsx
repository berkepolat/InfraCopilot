import Link from "next/link";
import { redirect } from "next/navigation";
import { cache, type ReactNode } from "react";
import { GatewayError, gatewayFetch, type AssessmentRun, type Me } from "@/lib/gateway";

/** The signed-in user, fetched once per request; redirects to the login page when the session expired. */
export const getMe = cache(async (): Promise<Me> => {
  try {
    return await gatewayFetch<Me>("/api/v1/auth/me");
  } catch (error) {
    if (error instanceof GatewayError && error.status === 401) redirect("/login");
    throw error;
  }
});

/** Loads data the user may not be allowed to see; null means "no permission". */
export async function optional<T>(load: () => Promise<T>): Promise<T | null> {
  try {
    return await load();
  } catch (error) {
    if (error instanceof GatewayError && error.status === 403) return null;
    throw error;
  }
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return `${new Date(iso).toLocaleString("en-GB", { timeZone: "UTC" })} UTC`;
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {description && <p className="muted">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function Section({ title, link, children }: { title: string; link?: { href: string; label: string }; children: ReactNode }) {
  return (
    <section className="section">
      <div className="section-header">
        <h2>{title}</h2>
        {link && <Link href={link.href} className="small">{link.label} →</Link>}
      </div>
      {children}
    </section>
  );
}

export function NoAccess({ what }: { what: string }) {
  return <p className="muted empty">You do not have permission to view {what}.</p>;
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return <tr><td colSpan={colSpan} className="muted empty">{children}</td></tr>;
}

export function runSummary(run: AssessmentRun): string {
  const s = run.stats;
  if (s.error) return s.error;
  if (run.trigger === "import") return `${s.accepted ?? 0} accepted, ${s.rejected ?? 0} rejected`;
  if (s.created === undefined) return "";
  const changes = `${s.created} new, ${s.updated ?? 0} changed, ${s.resolved ?? 0} resolved`;
  if (s.module === "NET" || (s.targets && s.targets.length)) {
    const n = s.targets?.length ?? 0;
    const ports = s.open_ports !== undefined ? ` · ${s.open_ports} open port${s.open_ports === 1 ? "" : "s"}` : "";
    return `${n} IP${n === 1 ? "" : "s"}${ports} · ${changes}`;
  }
  const rels = s.relationships !== undefined ? ` · ${s.relationships} relationships` : "";
  return `${s.domain ?? "AD"} · ${changes}${rels}`;
}

export function runModule(run: AssessmentRun): string {
  if (run.trigger === "import") return "Import";
  const module = run.stats.module === "NET" || run.scope?.ips?.length ? "Network" : "Active Directory";
  return run.trigger === "verification" ? `${module} · fix verification` : module;
}
