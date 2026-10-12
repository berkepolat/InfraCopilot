"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const CRITICALITY = ["Critical", "High", "Medium", "Low"];
const TIERS = ["Tier0", "Tier1", "Tier2", "Unclassified"];

type Props = { assetId: string; criticality: string; tier: string; suggested: string | null };

/** Inline criticality/tier editor; saving locks the values against automatic classification rules. */
export function AssetClassification({ assetId, criticality, tier, suggested }: Props) {
  const router = useRouter();
  const [values, setValues] = useState({ criticality, tier });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirty = values.criticality !== criticality || values.tier !== tier;

  async function save(next: { criticality: string; tier: string }) {
    setSaving(true);
    setError(null);
    const response = await fetch(`/api/assets/${encodeURIComponent(assetId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(next),
    });
    setSaving(false);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      setError(body.detail ?? `save failed (${response.status})`);
      return;
    }
    router.refresh();
  }

  return (
    <div>
      <select value={values.criticality} disabled={saving} aria-label="Criticality"
              onChange={(e) => setValues({ ...values, criticality: e.target.value })}>
        {CRITICALITY.map((c) => <option key={c}>{c}</option>)}
      </select>{" "}
      <select value={values.tier} disabled={saving} aria-label="Tier"
              onChange={(e) => setValues({ ...values, tier: e.target.value })}>
        {TIERS.map((t) => <option key={t}>{t}</option>)}
      </select>{" "}
      {dirty && <button disabled={saving} onClick={() => save(values)}>Save</button>}
      {!dirty && suggested && suggested !== criticality && (
        <button className="link small" disabled={saving} title="Suggested from the exposed network services"
                onClick={() => save({ criticality: suggested, tier })}>
          apply suggested {suggested}
        </button>
      )}
      {error && <div className="error small">{error}</div>}
    </div>
  );
}
