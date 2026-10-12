"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const POLL_INTERVAL_MS = 3000;
const POLL_ATTEMPTS = 60;

type Verification = { status: "pending" | "verified" | "still_failing" | "inconclusive" | "failed" };

const LABELS: Record<Exclude<Verification["status"], "pending">, string> = {
  verified: "verified",
  still_failing: "still failing",
  inconclusive: "inconclusive",
  failed: "run failed",
};

function summarize(items: Verification[]): string {
  const counts = new Map<string, number>();
  for (const item of items) {
    if (item.status !== "pending") counts.set(LABELS[item.status], (counts.get(LABELS[item.status]) ?? 0) + 1);
  }
  return [...counts].map(([label, n]) => `${n} ${label}`).join(", ");
}

/** Starts a targeted reassessment of the findings and reports whether the fix is confirmed. */
export function VerifyFix({ findingIds, label = "Verify fix" }: { findingIds: string[]; label?: string }) {
  const router = useRouter();
  const [state, setState] = useState<"idle" | "running" | "done">("idle");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState(false);

  async function verify() {
    setState("running");
    setError(false);
    setMessage("reassessing…");
    const response = await fetch("/api/verifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_ids: findingIds.slice(0, 50) }),
    });
    const started = await response.json().catch(() => ({}));
    if (!response.ok) {
      setState("idle");
      setError(true);
      setMessage(started.detail ?? `could not start the verification (${response.status})`);
      return;
    }
    for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      const poll = await fetch(`/api/verifications?run_id=${started.run_id}`);
      if (!poll.ok) continue;
      const { items } = (await poll.json()) as { items: Verification[] };
      if (items.length > 0 && items.every((v) => v.status !== "pending")) {
        setState("done");
        setError(items.some((v) => v.status !== "verified"));
        setMessage(summarize(items));
        router.refresh();
        return;
      }
    }
    setState("done");
    setMessage("still running — see Assessments for the result");
  }

  return (
    <span className="verify">
      <button className="secondary" onClick={verify} disabled={state === "running" || findingIds.length === 0}
              title="Reassess only these findings' controls and hosts (read-only)">
        {state === "running" ? "Verifying…" : label}
      </button>
      {message && <span className={`small ${error ? "error-inline" : "muted"}`}> {message}</span>}
    </span>
  );
}
