import { GatewayError, gatewayFetch } from "@/lib/gateway";

export const dynamic = "force-dynamic";

/** Requests a report through the gateway with the session's access token. */
export async function POST(request: Request) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ detail: "unsupported media type" }, { status: 415 });
  }
  const body = await request.json().catch(() => ({}));
  const payload: Record<string, unknown> = { report_type: body.report_type };
  if (Array.isArray(body.formats)) payload.formats = body.formats;
  try {
    const report = await gatewayFetch<{ report_id: string; status: string }>("/api/v1/reports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return Response.json(report, { status: 202 });
  } catch (error) {
    if (error instanceof GatewayError) {
      return Response.json({ detail: error.message }, { status: error.status });
    }
    throw error;
  }
}
