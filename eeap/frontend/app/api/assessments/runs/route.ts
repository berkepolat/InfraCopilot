import { GatewayError, gatewayFetch } from "@/lib/gateway";

export const dynamic = "force-dynamic";

/** Starts an AD or NET assessment run through the gateway with the session's access token. */
export async function POST(request: Request) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ detail: "unsupported media type" }, { status: 415 });
  }
  const body = await request.json().catch(() => ({}));
  const payload: Record<string, unknown> = {};
  if (Array.isArray(body.control_ids)) payload.control_ids = body.control_ids;
  if (Array.isArray(body.targets)) payload.targets = body.targets;
  try {
    const run = await gatewayFetch<{ run_id: string; status: string }>("/api/v1/assessments/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return Response.json(run, { status: 202 });
  } catch (error) {
    if (error instanceof GatewayError) {
      return Response.json({ detail: error.message }, { status: error.status });
    }
    throw error;
  }
}
