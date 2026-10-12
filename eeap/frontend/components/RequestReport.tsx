"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const POLL_INTERVAL_MS = 2000;
const POLL_ATTEMPTS = 10;

const REPORT_TYPES = [
  { id: "executive_summary", label: "Executive summary" },
  { id: "technical", label: "Technical findings" },
  { id: "remediation_roadmap", label: "Remediation roadmap" },
  { id: "mitre_mapping", label: "MITRE ATT&CK mapping" },
];
const FORMATS = ["pdf", "html", "json"];

export function RequestReport() {
  const router = useRouter();
  const [reportType, setReportType] = useState(REPORT_TYPES[0].id);
  const [formats, setFormats] = useState<string[]>(["pdf", "html"]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  function toggle(format: string) {
    setFormats((current) => (current.includes(format) ? current.filter((f) => f !== format) : [...current, format]));
  }

  async function request() {
    if (formats.length === 0) {
      setMessage("select at least one format");
      return;
    }
    setBusy(true);
    setMessage(null);
    const response = await fetch("/api/reports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report_type: reportType, formats }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      setMessage(payload.detail ?? "could not request the report");
      setBusy(false);
      return;
    }
    setMessage(payload.omitted?.length ? `report queued; omitted: ${payload.omitted.join(", ")}` : "report queued");
    for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      router.refresh();
    }
    setBusy(false);
  }

  return (
    <div className="panel">
      <h3>New report</h3>
      <div className="inline-form">
        <select value={reportType} onChange={(event) => setReportType(event.target.value)} disabled={busy}>
          {REPORT_TYPES.map((t) => (
            <option key={t.id} value={t.id}>{t.label}</option>
          ))}
        </select>
        {FORMATS.map((format) => (
          <label key={format} className="small">
            <input type="checkbox" checked={formats.includes(format)} onChange={() => toggle(format)} disabled={busy} />{" "}
            {format.toUpperCase()}
          </label>
        ))}
        <button onClick={request} disabled={busy}>
          {busy ? "Generating…" : "Generate report"}
        </button>
      </div>
      {message && <div className="notice">{message}</div>}
    </div>
  );
}
