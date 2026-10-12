import type { ReactNode } from "react";
import { SignOut } from "@/components/SignOut";
import { Sidebar } from "@/components/Sidebar";
import { getMe } from "@/lib/ui";

export const dynamic = "force-dynamic";

export default async function ConsoleLayout({ children }: { children: ReactNode }) {
  const me = await getMe();
  return (
    <div className="shell">
      <Sidebar permissions={me.permissions} />
      <div className="content">
        <header className="top">
          <span className="muted small">Enterprise Exposure Assessment Platform</span>
          <span className="muted small">
            {me.username} · {me.roles.join(", ")} · <SignOut />
          </span>
        </header>
        <main>{children}</main>
      </div>
    </div>
  );
}
