import { GatewayError, gatewayFetch } from "@/lib/gateway";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function failure(error: unknown): Response {
  if (error instanceof GatewayError) return Response.json({ detail: error.message }, { status: error.status });
  throw error;
}

/** Starts a fix verification (targeted reassessment) of up to 50 findings. */
export async function POST(request: Request) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ detail: "unsupported media type" }, { status: 415 });
  }
  const body = await request.json().catch(() => ({}));
  const ids: unknown[] = Array.isArray(body.finding_ids) ? body.finding_ids : [];
  if (ids.length === 0 || ids.length > 50 || !ids.every((id) => typeof id === "string" && UUID.test(id))) {
    return Response.json({ detail: "finding_ids must list 1 to 50 finding ids" }, { status: 422 });
  }
  const payload: Record<string, unknown> = { finding_ids: ids };
  if (typeof body.note === "string" && body.note.trim()) payload.note = body.note.trim().slice(0, 2000);
  try {
    const result = await gatewayFetch("/api/v1/assessments/verifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return Response.json(result, { status: 202 });
  } catch (error) {
    return failure(error);
  }
}

/** Verification results of one run (polled by the Verify fix button). */
export async function GET(request: Request) {
  const runId = new URL(request.url).searchParams.get("run_id") ?? "";
  if (!UUID.test(runId)) return Response.json({ detail: "run_id is required" }, { status: 422 });
  try {
    return Response.json(await gatewayFetch(`/api/v1/assessments/verifications?run_id=${runId}&limit=50`));
  } catch (error) {
    return failure(error);
  }
}
