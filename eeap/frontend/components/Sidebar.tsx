"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

type NavItem = { href: string; label: string; permission?: string };

const NAV: { group: string; items: NavItem[] }[] = [
  { group: "", items: [{ href: "/dashboard", label: "Overview" }] },
  {
    group: "Assess",
    items: [
      { href: "/assessments", label: "Assessments", permission: "assessments:read" },
      { href: "/network", label: "Network services", permission: "assets:read" },
      { href: "/assets", label: "Assets", permission: "assets:read" },
      { href: "/controls", label: "Controls", permission: "controls:read" },
    ],
  },
  {
    group: "Analyze",
    items: [
      { href: "/risk", label: "Risks & findings", permission: "risk:read" },
      { href: "/remediation", label: "Remediation", permission: "risk:read" },
      { href: "/attack", label: "MITRE ATT&CK", permission: "risk:read" },
      { href: "/graph", label: "Exposure graph", permission: "graph:read" },
    ],
  },
  { group: "Report", items: [{ href: "/reports", label: "Reports", permission: "reports:read" }] },
];

export function Sidebar({ permissions }: { permissions: string[] }) {
  const pathname = usePathname();
  return (
    <nav className="sidebar">
      <Link href="/dashboard" className="brand">EEAP</Link>
      {NAV.map(({ group, items }) => {
        const visible = items.filter((i) => !i.permission || permissions.includes(i.permission));
        if (visible.length === 0) return null;
        return (
          <div key={group || "home"} className="nav-group">
            {group && <div className="nav-title">{group}</div>}
            {visible.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={pathname === item.href || pathname.startsWith(`${item.href}/`) ? "nav-link active" : "nav-link"}
              >
                {item.label}
              </Link>
            ))}
          </div>
        );
      })}
    </nav>
  );
}
