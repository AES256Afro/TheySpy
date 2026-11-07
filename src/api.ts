import { useEffect, useRef } from "react";
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * Told when the session has gone, so the shell can put the sign-in screen back. Without this a tab
 * left open past the session's 14 days - or across a restart with a new TS_SESSION_SECRET - showed
 * "Sign in first" in every screen's error banner and the only way back was to reload the page.
 */
let onSessionEnded: () => void = () => {};
export const whenSessionEnds = (handler: () => void) => { onSessionEnded = handler; };

/** JSON over fetch. State-changing calls carry X-TheySpy, which the server requires (CSRF guard). */
export async function api<T>(method: "GET" | "POST" | "PUT" | "DELETE", url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...(method === "GET" ? {} : { "x-theyspy": "1" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  // Signing in is the one call whose 401 means "wrong password", not "your session has gone".
  if (response.status === 401 && url !== "/api/login") onSessionEnded();
  if (!response.ok) throw new ApiError(response.status, (data as { error?: string }).error ?? `Request failed (${response.status})`);
  return data as T;
}

/**
 * Polls a job until it finishes; returns it with its log. Pass `stopped` (an AbortSignal, or any
 * `{ aborted }`) from a screen that may go away, so the polling goes with it.
 */
/**
 * A flag a screen hands to waitForJob: set once the screen has gone, so the polling stops with it.
 * The object is stable for the component's life, so the same one can be passed to every wait.
 */
export function useStopped(): { aborted: boolean } {
  const ref = useRef({ aborted: false });
  useEffect(() => {
    const flag = ref.current;
    flag.aborted = false;
    return () => { flag.aborted = true; };
  }, []);
  return ref.current;
}

export async function waitForJob(id: number, stopped?: { aborted: boolean }): Promise<Job> {
  for (let i = 0; i < 600; i += 1) {
    if (stopped?.aborted) throw new ApiError(0, "Stopped watching the job; see Activity.");
    const { job } = await api<{ job: Job }>("GET", `/api/jobs/${id}`);
    if (job.status !== "queued" && job.status !== "running") return job;
    await new Promise((resolve) => setTimeout(resolve, 600));
  }
  throw new Error("The job is still running; see Activity.");
}

/** The last line a job logged, without its timestamp. */
export const lastLogLine = (job: Job) => job.log?.trim().split("\n").pop()?.replace(/^\S+ /, "") ?? "";

/** What a screen says when a job it waited for has ended: its last line, and where the whole log is when it failed. */
export function jobOutcome(job: Job): { tone: "good" | "bad"; text: string } {
  const line = lastLogLine(job) || job.status;
  return job.status === "succeeded" ? { tone: "good", text: line } : { tone: "bad", text: `${line} · the whole log is on Activity (job ${job.id})` };
}

export type Job = { id: number; kind: string; title: string; status: "queued" | "running" | "succeeded" | "failed" | "interrupted"; actor: string; created_at: string; started_at: string | null; finished_at: string | null; log?: string; result?: unknown };
export type AuditEntry = { id: number; at: string; actor: string; action: string; target: string | null; detail: unknown };

/**
 * A link from somewhere else - a blocklist directory's homepage, a research feed's article - is
 * only ever http(s). React renders whatever string it is given into href, so a "javascript:" URL
 * from a directory would be a click away from running as the owner. The CSP already refuses to run
 * it; this is so there is nothing to refuse.
 */
export function safeLink(url: unknown): string | null {
  if (typeof url !== "string") return null;
  try {
    return ["http:", "https:"].includes(new URL(url).protocol) ? url : null;
  } catch {
    return null;
  }
}
