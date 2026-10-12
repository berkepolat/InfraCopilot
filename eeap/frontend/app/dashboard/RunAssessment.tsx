"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const POLL_INTERVAL_MS = 2000;
const POLL_ATTEMPTS = 15;

export function RunAssessment() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setMessage(null);
    const response = await fetch("/api/assessments/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      setMessage(body.detail ?? "could not start the assessment");
      setBusy(false);
      return;
    }
    setMessage("Assessment queued");
    for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      router.refresh();
    }
    setBusy(false);
    setMessage(null);
  }

  return (
    <span>
      <button onClick={start} disabled={busy}>
        {busy ? "Running…" : "Run AD assessment"}
      </button>
      {message && <span className="muted small"> {message}</span>}
    </span>
  );
}
