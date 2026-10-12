import type { FactorChip } from "@/lib/risk";

export function FactorChips({ chips }: { chips: FactorChip[] }) {
  if (chips.length === 0) return <span className="muted small">—</span>;
  return (
    <div className="factors">
      {chips.map((c) => (
        <span key={c.label} className={`factor${c.hot ? " hot" : ""}`} title={c.title}>{c.label}</span>
      ))}
    </div>
  );
}
