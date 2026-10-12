import { GatewayError, gatewayFetch } from "@/lib/gateway";

export const dynamic = "force-dynamic";

/** Starts an AD configuration assessment run through the gateway with the session's access token. */
export async function POST(request: Request) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ detail: "unsupported media type" }, { status: 415 });
  }
  const { control_ids } = await request.json().catch(() => ({}));
  try {
    const run = await gatewayFetch<{ run_id: string; status: string }>("/api/v1/assessments/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Array.isArray(control_ids) ? { control_ids } : {}),
    });
    return Response.json(run, { status: 202 });
  } catch (error) {
    if (error instanceof GatewayError) {
      return Response.json({ detail: error.message }, { status: error.status });
    }
    throw error;
  }
}
