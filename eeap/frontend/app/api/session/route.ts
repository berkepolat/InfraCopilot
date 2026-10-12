import { cookies } from "next/headers";
import { SESSION_COOKIE, gatewayUrl } from "@/lib/gateway";

export const dynamic = "force-dynamic";

/** Exchanges credentials for tokens at the gateway; the access token is stored only in an HttpOnly cookie. */
export async function POST(request: Request) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ detail: "unsupported media type" }, { status: 415 });
  }
  const { username, password } = await request.json();
  const response = await fetch(gatewayUrl("/api/v1/auth/login"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Real-IP": request.headers.get("x-real-ip") ?? "",
      "User-Agent": request.headers.get("user-agent") ?? "eeap-frontend",
    },
    body: JSON.stringify({ username, password }),
    cache: "no-store",
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    return Response.json({ detail: body.detail ?? "sign-in failed" }, { status: response.status });
  }
  cookies().set(SESSION_COOKIE, body.access_token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: body.expires_in,
  });
  return Response.json({ ok: true });
}

export async function DELETE() {
  const token = cookies().get(SESSION_COOKIE)?.value;
  if (token) {
    await fetch(gatewayUrl("/api/v1/auth/logout"), {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }).catch(() => undefined);
  }
  cookies().delete(SESSION_COOKIE);
  return new Response(null, { status: 204 });
}
