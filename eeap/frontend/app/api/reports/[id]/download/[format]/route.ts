import { GatewayError, gatewayRaw } from "@/lib/gateway";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FORMATS = new Set(["json", "html", "pdf"]);

/** Streams a rendered report from the gateway; always delivered as an attachment. */
export async function GET(_: Request, { params }: { params: { id: string; format: string } }) {
  if (!UUID.test(params.id) || !FORMATS.has(params.format)) {
    return Response.json({ detail: "not found" }, { status: 404 });
  }
  try {
    const upstream = await gatewayRaw(`/api/v1/reports/${params.id}/download/${params.format}`);
    if (!upstream.ok) {
      const body = await upstream.json().catch(() => ({}));
      return Response.json({ detail: body.detail ?? upstream.statusText }, { status: upstream.status });
    }
    return new Response(upstream.body, {
      status: 200,
      headers: {
        "Content-Type": upstream.headers.get("content-type") ?? "application/octet-stream",
        "Content-Disposition": upstream.headers.get("content-disposition") ?? "attachment",
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (error) {
    if (error instanceof GatewayError) {
      return Response.json({ detail: error.message }, { status: error.status });
    }
    throw error;
  }
}
