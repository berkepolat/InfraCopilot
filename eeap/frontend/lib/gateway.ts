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

export type Page<T> = { items: T[]; next_cursor: string | null };

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
  scoring_model: string;
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
  scope?: { ips?: string[] };
  stats: {
    module?: string;
    domain?: string;
    targets?: string[];
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

export type Me = { user_id: string; username: string; roles: string[]; permissions: string[] };
