"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

export default function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const form = new FormData(event.currentTarget);
    const response = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: form.get("username"), password: form.get("password") }),
    });
    setBusy(false);
    if (response.ok) {
      router.replace("/dashboard");
      router.refresh();
      return;
    }
    const body = await response.json().catch(() => ({}));
    setError(response.status === 429 ? "Too many attempts. Try again shortly." : body.detail ?? "Sign-in failed");
  }

  return (
    <form className="login" onSubmit={onSubmit}>
      <h1>EEAP</h1>
      <p className="muted">Enterprise Exposure Assessment Platform</p>
      <label htmlFor="username">Username</label>
      <input id="username" name="username" autoComplete="username" required />
      <label htmlFor="password">Password</label>
      <input id="password" name="password" type="password" autoComplete="current-password" required />
      <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      {error && <div className="error">{error}</div>}
    </form>
  );
}
