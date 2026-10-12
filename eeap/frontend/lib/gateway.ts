import { cookies } from "next/headers";

export const SESSION_COOKIE = "eeap_session";

const GATEWAY_URL = process.env.GATEWAY_INTERNAL_URL ?? "http://api-gateway:8000";

export class GatewayError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function gatewayUrl(path: string): string {
  return `${GATEWAY_URL}${path}`;
}

/** Server-side call to the API Gateway using the access token from the HttpOnly session cookie. */
export async function gatewayFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = cookies().get(SESSION_COOKIE)?.value;
  if (!token) throw new GatewayError(401, "not signed in");
  const response = await fetch(gatewayUrl(path), {
    ...init,
    cache: "no-store",
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new GatewayError(response.status, body.detail ?? response.statusText);
  }
  return (await response.json()) as T;
}

/** Raw gateway response (for binary downloads); the caller checks the status. */
export async function gatewayRaw(path: string): Promise<Response> {
  const token = cookies().get(SESSION_COOKIE)?.value;
  if (!token) throw new GatewayError(401, "not signed in");
  return fetch(gatewayUrl(path), { cache: "no-store", headers: { Authorization: `Bearer ${token}` } });
}

export type Page<T> = { items: T[]; next_cursor: string | null };

export type Report = {
  report_id: string;
  report_type: string;
  title: string;
  formats: string[];
  available_formats: string[];
  status: "queued" | "rendering" | "completed" | "failed" | "expired";
  error: string | null;
  snapshot_at: string;
  created_at: string;
};

export type Asset = {
  asset_id: string;
  hostname: string;
  asset_type: string;
  criticality: string;
  tier: string;
  environment: string;
  owner: string | null;
  status: string;
};

export type Control = {
  control_id: string;
  name: string;
  module: string;
  category: string;
  default_severity: string;
  enabled: boolean;
};

export type Rating = "Critical" | "High" | "Medium" | "Low";

export type RiskSummary = {
  exposure_score: { score: number; rating: Rating; computed_at: string; factors: Record<string, unknown> } | null;
  open_by_rating: { finding: Partial<Record<Rating, number>>; asset: Partial<Record<Rating, number>> };
  active_scenarios: number;
  top_scenarios?: RiskScenario[];
  scoring_model: string;
};

export type RiskScenario = {
  scenario_id: string;
  rule_id: string;
  title: string;
  summary: string;
  score: number;
  rating: Rating;
  status: string;
  affected_asset_ids: string[];
  stages: { order: number; name: string; matched: boolean; finding_ids: string[]; derived?: boolean }[];
  first_detected_at: string;
};

export type RemediationItem = {
  item_id: string;
  control_id: string | null;
  title: string;
  guidance: string;
  effort: "Low" | "Medium" | "High";
  expected_risk_reduction: number;
  priority: number;
  roadmap_phase: "Immediate" | "Short-term" | "Medium-term" | "Long-term";
  status: "proposed" | "accepted" | "done" | "rejected";
  open_findings: number;
  scenarios: { scenario_id: string; title: string }[];
  techniques: { technique_id: string; name: string }[];
};

export type MitreTechnique = {
  technique_id: string;
  name: string;
  tactics: string[];
  url: string;
  controls: string[];
  open_findings: number;
  max_score: number;
};

export type TopFinding = {
  finding_id: string;
  score: number;
  rating: Rating;
  asset_id: string;
  hostname: string | null;
  control_id: string;
  category: string | null;
  severity: string;
  status: string;
  lifecycle_state: string;
  subject_key: string;
  factors: { floor_applied: boolean; normalized: Record<string, number> };
};

export type AssessmentRun = {
  run_id: string;
  trigger: string;
  status: string;
  control_ids: string[];
  scope?: { ips?: string[]; ports?: number[] };
  stats: {
    module?: string;
    domain?: string;
    targets?: string[];
    ports_scanned?: number;
    open_ports?: number;
    closed_ports?: number;
    error?: string;
    created?: number;
    updated?: number;
    resolved?: number;
    relationships?: number;
    accepted?: number;
    rejected?: number;
    by_severity?: Record<string, number>;
  };
  created_at: string;
  completed_at: string | null;
};

export type GraphAnalysis = {
  analysis_id: string;
  trigger: string;
  node_count: number;
  edge_count: number;
  completed_at: string;
  exposed_nodes: number;
  tier0_nodes: number;
  one_hop_nodes: number;
  areas: Record<string, number>;
};

export type ConcentrationArea = {
  area_id: string;
  area_type: string;
  score: number;
  member_count: number;
  summary: string;
  anchor_node_id: string;
  anchor_node_type: string;
  anchor_display_name: string;
};

export type NetworkService = {
  service_id: string;
  asset_id: string;
  ip: string;
  transport: string;
  port: number;
  state: "open" | "closed";
  service: string;
  product: string | null;
  version: string | null;
  tls_version: string | null;
  details: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  closed_at: string | null;
};

export type VulnerabilityFeeds = {
  ecosystems: {
    ecosystem: string;
    ranges: number;
    newest_modified: string | null;
    imported_at: string;
    feed_id: string;
    filename: string;
  }[];
  feeds: {
    feed_id: string;
    filename: string;
    sha256: string;
    size_bytes: number;
    status: "queued" | "importing" | "completed" | "failed";
    ecosystems: string[];
    records: number | null;
    ranges: number | null;
    newest_modified: string | null;
    error: string | null;
    uploaded_by: string;
    created_at: string;
    completed_at: string | null;
  }[];
};

export type Me = { user_id: string; username: string; roles: string[]; permissions: string[] };
