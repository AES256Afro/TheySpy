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

/** Polls a job until it finishes; returns it with its log. */
export async function waitForJob(id: number): Promise<Job> {
  for (let i = 0; i < 600; i += 1) {
    const { job } = await api<{ job: Job }>("GET", `/api/jobs/${id}`);
    if (job.status !== "queued" && job.status !== "running") return job;
    await new Promise((resolve) => setTimeout(resolve, 600));
  }
  throw new Error("The job is still running; see Activity.");
}

/** The last line a job logged, without its timestamp. */
export const lastLogLine = (job: Job) => job.log?.trim().split("\n").pop()?.replace(/^\S+ /, "") ?? "";

export type Job = { id: number; kind: string; title: string; status: "queued" | "running" | "succeeded" | "failed" | "interrupted"; actor: string; created_at: string; started_at: string | null; finished_at: string | null; log?: string };
export type AuditEntry = { id: number; at: string; actor: string; action: string; target: string | null; detail: unknown };
