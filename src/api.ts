export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** JSON over fetch. State-changing calls carry X-TheySpy, which the server requires (CSRF guard). */
export async function api<T>(method: "GET" | "POST" | "PUT" | "DELETE", url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...(method === "GET" ? {} : { "x-theyspy": "1" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(response.status, (data as { error?: string }).error ?? `Request failed (${response.status})`);
  return data as T;
}

export type Job = { id: number; kind: string; title: string; status: "queued" | "running" | "succeeded" | "failed" | "interrupted"; actor: string; created_at: string; started_at: string | null; finished_at: string | null; log?: string };
export type AuditEntry = { id: number; at: string; actor: string; action: string; target: string | null; detail: unknown };
