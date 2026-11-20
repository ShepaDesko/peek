import { useCallback, useEffect, useState } from "react";
import { ApiError, auth, type Me } from "./api";

/**
 * The signed-in state of this browser.
 *
 * One fetch of /auth/me answers everything the interface needs: whether there
 * is a session, whether it is stuck at the second factor, what the account may
 * do, and — on a fresh instance — whether the first account still has to be
 * created.
 */
export interface Session {
  me: Me | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<Me | null>;
  signOut: () => Promise<void>;
}

export function useSession(): Session {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const next = await auth.me();
      setMe(next);
      setError(null);
      return next;
    } catch (err) {
      setMe(null);
      // A 404 here means the account surface is not served on this listener,
      // which is the normal state of a public, recipient-only instance.
      if (err instanceof ApiError && err.status === 404) {
        setError(null);
      } else {
        setError(err instanceof Error ? err.message : "error");
      }
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const signOut = useCallback(async () => {
    try {
      await auth.logout();
    } finally {
      await refresh();
      navigate("/");
    }
  }, [refresh]);

  return { me, loading, error, refresh, signOut };
}

/** Client-side navigation, without pulling in a router. */
export function navigate(path: string): void {
  window.history.pushState(null, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

/** Replaces the current entry, for redirects that should not be "back". */
export function replace(path: string): void {
  window.history.replaceState(null, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}
