"use client";

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState
} from "react";
import { usePathname, useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import {
  fetchCurrentSession,
  logoutCurrentSession,
  type AuthSession
} from "../../lib/api";
import { AppShell } from "../layout/app-shell";
import { ToastProvider } from "../ui/toast";

type AuthState =
  | { status: "loading"; session: null }
  | { status: "unauthenticated"; session: null }
  | { status: "authenticated"; session: AuthSession };

type AuthContextValue = AuthState & {
  refreshSession: () => Promise<void>;
  logout: () => void;
};

const publicPaths = new Set([
  "/login",
  "/signup",
  "/forgot-password",
  "/reset-password",
  "/accept-invite"
]);

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [state, setState] = useState<AuthState>({
    status: "loading",
    session: null
  });

  async function refreshSession() {
    try {
      const response = await fetchCurrentSession();
      setState({ status: "authenticated", session: response.data });
    } catch {
      setState({ status: "unauthenticated", session: null });
    }
  }

  function logout() {
    void logoutCurrentSession().catch(() => undefined);
    setState({ status: "unauthenticated", session: null });
    router.replace("/login");
  }

  useEffect(() => {
    void refreshSession();
  }, []);

  useEffect(() => {
    if (state.status === "loading") {
      return;
    }

    const isPublicPath = publicPaths.has(pathname);

    if (state.status === "unauthenticated" && !isPublicPath) {
      router.replace("/login");
      return;
    }

    if (state.status === "authenticated" && isPublicPath) {
      router.replace("/");
    }
  }, [pathname, router, state.status]);

  const value = useMemo<AuthContextValue>(
    () => ({
      ...state,
      refreshSession,
      logout
    }),
    [state]
  );

  const isPublicPath = publicPaths.has(pathname);
  const showShell = state.status === "authenticated" && !isPublicPath;

  return (
    <AuthContext.Provider value={value}>
      <ToastProvider>
        {state.status === "loading" && !isPublicPath ? (
          <main
            role="status"
            aria-live="polite"
            className="flex min-h-screen items-center justify-center px-6"
          >
            <div className="flex items-center gap-2 rounded-md border border-border bg-card px-4 py-3 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Checking Cerebro-bound session…
            </div>
          </main>
        ) : showShell ? (
          <AppShell>{children}</AppShell>
        ) : (
          children
        )}
      </ToastProvider>
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthShell");
  }
  return context;
}
