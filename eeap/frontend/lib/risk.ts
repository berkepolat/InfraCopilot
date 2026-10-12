import type { Exposure, FindingFactors } from "@/lib/gateway";

export const EXPOSURE_CLASS_LABELS: Record<string, string> = {
  remote_admin: "remote admin",
  file_sharing: "file sharing",
  data_store: "data store",
  control_plane: "control plane",
  directory: "directory",
  cleartext_login: "cleartext login",
};

/** ATT&CK enterprise tactics in kill-chain order. */
export const TACTIC_LABELS: Record<string, string> = {
  "initial-access": "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access",
  discovery: "Discovery",
  "lateral-movement": "Lateral Movement",
  collection: "Collection",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

export type FactorChip = { label: string; hot: boolean; title: string };

/** Why a finding ranks where it does, from the stored factor breakdown (docs/architecture/08). */
export function factorChips(factors: FindingFactors, knownExploited?: boolean): FactorChip[] {
  const inputs = factors.inputs ?? {};
  const n = factors.normalized ?? {};
  const chips: FactorChip[] = [];
  if (knownExploited || inputs.known_exploited) {
    chips.push({ label: "actively exploited", hot: true, title: "A CVE of this finding is in the CISA KEV catalog" });
  } else if ((n.E ?? 0) >= 0.9) {
    chips.push({ label: "likely exploitable", hot: false, title: `Exploitability ${n.E}` });
  }
  if (inputs.is_tier0) chips.push({ label: "Tier-0", hot: true, title: "Tier-0 asset or privileged object" });
  if (inputs.criticality === "Critical" || inputs.criticality === "High") {
    chips.push({ label: `${inputs.criticality} asset`, hot: inputs.criticality === "Critical", title: "Asset criticality" });
  }
  if ((inputs.propagation ?? 0) >= 0.5) {
    chips.push({ label: "path to Tier-0", hot: true, title: `Propagation ${inputs.propagation}` });
  }
  if (inputs.exposure_source === "port_scan" && (n.X ?? 0) >= 0.5) {
    const classes = (inputs.exposed_classes ?? []).map((c) => EXPOSURE_CLASS_LABELS[c] ?? c).join(", ");
    chips.push({ label: "network exposed", hot: (n.X ?? 0) >= 0.8, title: `${inputs.open_services} open services${classes ? `: ${classes}` : ""}` });
  }
  if ((inputs.affected_count ?? 0) >= 10) {
    chips.push({ label: `widespread (${inputs.affected_count})`, hot: false, title: "Same control fails on many objects" });
  }
  if (factors.floor_applied) {
    chips.push({
      label: factors.floor === "known_exploited" ? "KEV floor" : "severity floor",
      hot: false,
      title: "Score raised to the model's minimum for this case",
    });
  }
  return chips;
}

export function exposureSummary(exposure: Exposure | null): string {
  if (!exposure) return "not port scanned";
  if (exposure.open_services === 0) return "no open services";
  const classes = exposure.classes.map((c) => EXPOSURE_CLASS_LABELS[c] ?? c).join(", ");
  return `${exposure.open_services} open${classes ? ` · ${classes}` : ""}`;
}
