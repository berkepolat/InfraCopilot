"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const POLL_INTERVAL_MS = 2000;
const POLL_ATTEMPTS = 20;

function splitList(raw: string): string[] {
  return raw
    .split(/[\s,;]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function RunAssessment() {
  const router = useRouter();
  const [busy, setBusy] = useState<"ad" | "net" | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [targets, setTargets] = useState("");
  const [ports, setPorts] = useState("");

  async function start(kind: "ad" | "net", body: Record<string, unknown>, label: string) {
    setBusy(kind);
    setMessage(null);
    const response = await fetch("/api/assessments/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      setMessage(payload.detail ?? `could not start the ${label}`);
      setBusy(null);
      return;
    }
    setMessage(`${label} queued — results appear below when it completes`);
    for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      router.refresh();
    }
    setBusy(null);
    setMessage(null);
  }

  async function startNet() {
    const ips = splitList(targets);
    if (ips.length === 0) {
      setMessage("enter one or more IP addresses to scan");
      return;
    }
    const extraPorts = splitList(ports);
    await start("net", extraPorts.length ? { targets: ips, ports: extraPorts } : { targets: ips }, "network scan");
  }

  return (
    <>
      <div className="panel-grid">
        <div className="panel">
          <h3>Active Directory</h3>
          <p className="muted small">
            Reads the domain configuration over LDAPS with the read-only service account: password policy,
            Kerberos delegation, privileged groups, LAPS and legacy systems (AD-001 … AD-010).
          </p>
          <button onClick={() => start("ad", {}, "AD assessment")} disabled={busy !== null}>
            {busy === "ad" ? "Running…" : "Run AD assessment"}
          </button>
        </div>
        <div className="panel">
          <h3>Network scan</h3>
          <p className="muted small">
            Probes the listed IPs (must be inside the authorized ranges): DNS, TLS, SMB, SNMP, NTP, a TCP port
            scan with service identification (NET-001 … NET-009) and Windows settings visible on the network:
            SMB signing, SMBv1, RDP NLA and WinRM listeners (WIN-001, 002, 006, 008). No credentials are used.
          </p>
          <label className="field-label" htmlFor="net-targets">Target IPs</label>
          <textarea
            id="net-targets"
            value={targets}
            onChange={(event) => setTargets(event.target.value)}
            placeholder={"10.0.0.10\n10.0.0.20"}
            rows={3}
            disabled={busy !== null}
          />
          <label className="field-label" htmlFor="net-ports">Extra TCP ports (optional)</label>
          <input
            id="net-ports"
            value={ports}
            onChange={(event) => setPorts(event.target.value)}
            placeholder="8081, 9000-9010"
            disabled={busy !== null}
          />
          <p className="muted small">Common enterprise ports (SSH, RDP, SMB, LDAP, databases, Docker, Kubernetes…) are always scanned.</p>
          <button onClick={startNet} disabled={busy !== null}>
            {busy === "net" ? "Running…" : "Scan IPs"}
          </button>
        </div>
      </div>
      {message && <div className="notice">{message}</div>}
    </>
  );
}
