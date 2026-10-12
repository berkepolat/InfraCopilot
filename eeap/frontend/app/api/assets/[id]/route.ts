import { GatewayError, gatewayFetch, type Asset } from "@/lib/gateway";

export const dynamic = "force-dynamic";

const CRITICALITY = ["Critical", "High", "Medium", "Low"];
const TIERS = ["Tier0", "Tier1", "Tier2", "Unclassified"];

/** Sets an asset's criticality and/or tier. Manual values are locked against discovery rules. */
export async function PATCH(request: Request, { params }: { params: { id: string } }) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ detail: "unsupported media type" }, { status: 415 });
  }
  const body = await request.json().catch(() => ({}));
  const payload: Record<string, unknown> = {};
  if (CRITICALITY.includes(body.criticality)) payload.criticality = body.criticality;
  if (TIERS.includes(body.tier)) payload.tier = body.tier;
  if (Object.keys(payload).length === 0) return Response.json({ detail: "nothing to update" }, { status: 422 });
  payload.criticality_locked = true;
  try {
    const asset = await gatewayFetch<Asset>(`/api/v1/assets/${encodeURIComponent(params.id)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return Response.json(asset);
  } catch (error) {
    if (error instanceof GatewayError) {
      return Response.json({ detail: error.message }, { status: error.status });
    }
    throw error;
  }
}
