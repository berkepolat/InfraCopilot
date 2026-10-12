"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const POLL_INTERVAL_MS = 2000;
const POLL_ATTEMPTS = 20;

function parseIpList(raw: string): string[] {
  return raw
    .split(/[\s,;]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function RunAssessment() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [targets, setTargets] = useState("");

  async function start(body: Record<string, unknown>, label: string) {
    setBusy(true);
    setMessage(null);
    const response = await fetch("/api/assessments/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      setMessage(payload.detail ?? `could not start the ${label}`);
      setBusy(false);
      return;
    }
    setMessage(`${label} queued`);
    for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      router.refresh();
    }
    setBusy(false);
    setMessage(null);
  }

  async function startAd() {
    await start({}, "AD assessment");
  }

  async function startNet() {
    const ips = parseIpList(targets);
    if (ips.length === 0) {
      setMessage("enter one or more IP addresses to scan");
      return;
    }
    await start({ targets: ips }, "network scan");
  }

  return (
    <div className="run-panel">
      <div className="run-row">
        <button onClick={startAd} disabled={busy}>
          {busy ? "Running…" : "Run AD assessment"}
        </button>
      </div>
      <div className="run-row net-scan">
        <label className="muted small" htmlFor="net-targets">
          Network scan targets (IP list)
        </label>
        <textarea
          id="net-targets"
          value={targets}
          onChange={(event) => setTargets(event.target.value)}
          placeholder={"10.0.0.10\n10.0.0.20"}
          rows={3}
          disabled={busy}
        />
        <button onClick={startNet} disabled={busy}>
          {busy ? "Running…" : "Scan IPs"}
        </button>
      </div>
      {message && <div className="muted small run-msg">{message}</div>}
    </div>
  );
}
