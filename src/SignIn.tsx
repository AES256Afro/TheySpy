import { useState, type FormEvent } from "react";
import { api, ApiError } from "./api.ts";
import type { Appearance } from "./looks/looks.ts";
import { Brand } from "./Sidebar.tsx";

export function SignIn({ appearance, onSignedIn }: { appearance: Appearance; onSignedIn: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("POST", "/api/login", { password });
      onSignedIn();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : "Could not reach TheySpy.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="signin">
      <form className="card" onSubmit={submit}>
        <Brand appearance={appearance} />
        <label htmlFor="password"><h2>Owner password</h2></label>
        <input id="password" className="input" type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} required />
        {error && <div className="banner bad" role="alert"><span className="small">{error}</span></div>}
        <button className="btn primary" type="submit" disabled={busy || !password}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="muted small">On first start TheySpy prints a generated password to its log once. Set <code>TS_ADMIN_PASSWORD</code> to choose your own; in BoxPilot it is on the app’s card.</p>
      </form>
    </main>
  );
}
