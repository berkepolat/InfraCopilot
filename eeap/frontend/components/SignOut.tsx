"use client";

import { useRouter } from "next/navigation";

export function SignOut() {
  const router = useRouter();
  return (
    <button
      className="link"
      onClick={async () => {
        await fetch("/api/session", { method: "DELETE" });
        router.replace("/login");
      }}
    >
      Sign out
    </button>
  );
}
