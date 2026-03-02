import type { AppRouter } from "@amibeingpwned/api";
import { QueryClient } from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { createTRPCContext } from "@trpc/tanstack-react-query";
import superjson from "superjson";

// v11 API: createTRPCContext gives you TRPCProvider + useTRPC hook.
// Usage in components: const trpc = useTRPC(); useQuery(trpc.foo.queryOptions())
export const { TRPCProvider, useTRPC, useTRPCClient } =
  createTRPCContext<AppRouter>();

// ---------------------------------------------------------------------------
// God mode: admin org impersonation
// Module-level so the headers function always reads the latest value without
// needing to recreate the tRPC client.
// ---------------------------------------------------------------------------
const IMPERSONATE_KEY = "aibp_impersonate_org";

let _impersonateOrgId: string | null =
  typeof localStorage !== "undefined"
    ? localStorage.getItem(IMPERSONATE_KEY)
    : null;

export function setImpersonateOrgId(id: string | null) {
  _impersonateOrgId = id;
  if (id) localStorage.setItem(IMPERSONATE_KEY, id);
  else localStorage.removeItem(IMPERSONATE_KEY);
}

export function getImpersonateOrgId() {
  return _impersonateOrgId;
}

export function makeTRPCClient() {
  return createTRPCClient<AppRouter>({
    links: [
      httpBatchLink({
        url: "/api/trpc",
        transformer: superjson,
        headers: () =>
          _impersonateOrgId
            ? { "x-impersonate-org": _impersonateOrgId }
            : {},
      }),
    ],
  });
}

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 1000 * 60,
        refetchOnWindowFocus: false,
      },
    },
  });
}
