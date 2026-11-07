// Scheduled work that runs outside the job log (a Pi-hole read every five minutes would fill it):
// one run at a time, its last failure kept in settings and shown on the screen that owns it, and
// cleared again by the next success (M18, B28 - before this the error was written and never read).

/**
 * @param {{ settings: ReturnType<typeof import("./db.mjs").createSettingsStore>, prefix: string, now?: () => Date }} deps
 */
export function createQuietRunner({ settings, prefix, now = () => new Date() }) {
  const key = (name) => `${prefix}_last_${name}_error`;
  return {
    /**
     * Wraps `work` so it runs once at a time; a throw is recorded under the name, a success clears it.
     * @param {string} name @param {() => Promise<unknown>} work
     */
    wrap(name, work) {
      let running = false;
      return async () => {
        if (running) return;
        running = true;
        try {
          await work();
          settings.delete(key(name));
        } catch (error) {
          settings.set(key(name), { at: now().toISOString(), error: error instanceof Error ? error.message : String(error) });
        } finally {
          running = false;
        }
      };
    },
    /** The failures still standing, by name. @param {string[]} names */
    errors(names) {
      return Object.fromEntries(names.map((name) => [name, settings.get(key(name)) ?? null]).filter(([, v]) => v));
    },
  };
}
