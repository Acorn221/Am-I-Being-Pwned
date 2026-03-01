/**
 * YOU PROBABLY DON'T NEED TO EDIT THIS FILE, UNLESS:
 * 1. You want to modify request context (see Part 1)
 * 2. You want to create a new middleware or type of procedure (see Part 3)
 *
 * tl;dr - this is where all the tRPC server stuff is created and plugged in.
 * The pieces you will need to use are documented accordingly near the end
 */
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import { z, ZodError } from "zod/v4";

import type { Auth } from "@amibeingpwned/auth";
import { db } from "@amibeingpwned/db/client";
import type { createEmailClient } from "@amibeingpwned/email";

import { fetchManagerMembership } from "./lib/org-membership";

/**
 * 1. CONTEXT
 *
 * This section defines the "contexts" that are available in the backend API.
 *
 * These allow you to access things when processing a request, like the database, the session, etc.
 *
 * This helper generates the "internals" for a tRPC context. The API handler and RSC clients each
 * wrap this and provides the required context.
 *
 * @see https://trpc.io/docs/server/context
 */

export const createTRPCContext = async (opts: {
  headers: Headers;
  auth: Auth;
  email: ReturnType<typeof createEmailClient> | null;
  appUrl: string;
}) => {
  const session = await opts.auth.api.getSession({
    headers: opts.headers,
  });
  return {
    session,
    db,
    email: opts.email,
    appUrl: opts.appUrl,
    headers: opts.headers,
  };
};
/**
 * 2. INITIALIZATION
 *
 * This is where the trpc api is initialized, connecting the context and
 * transformer
 */
// Exported so middleware files in this package can build on the same instance.
// Do not import `t` in application code — use the exported procedures instead.
export const t = initTRPC.context<typeof createTRPCContext>().create({
  transformer: superjson,
  errorFormatter: ({ shape, error }) => ({
    ...shape,
    data: {
      ...shape.data,
      zodError:
        error.cause instanceof ZodError
          ? z.flattenError(error.cause as ZodError<Record<string, unknown>>)
          : null,
    },
  }),
});

/**
 * 3. ROUTER & PROCEDURE (THE IMPORTANT BIT)
 *
 * These are the pieces you use to build your tRPC API. You should import these
 * a lot in the /src/server/api/routers folder
 */

/**
 * This is how you create new routers and subrouters in your tRPC API
 * @see https://trpc.io/docs/router
 */
export const createTRPCRouter = t.router;

/**
 * Middleware for timing procedure execution and adding an articifial delay in development.
 *
 * You can remove this if you don't like it, but it can help catch unwanted waterfalls by simulating
 * network latency that would occur in production but not in local development.
 */
const timingMiddleware = t.middleware(async ({ next, path }) => {
  const start = Date.now();

  if (t._config.isDev) {
    // artificial delay in dev 100-500ms
    const waitMs = Math.floor(Math.random() * 400) + 100;
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  }

  const result = await next();

  const end = Date.now();
  console.log(`[TRPC] ${path} took ${end - start}ms to execute`);

  return result;
});

/**
 * Public (unauthed) procedure
 *
 * This is the base piece you use to build new queries and mutations on your
 * tRPC API. It does not guarantee that a user querying is authorized, but you
 * can still access user session data if they are logged in
 */
export const publicProcedure = t.procedure.use(timingMiddleware);

/**
 * Protected (authenticated) procedure
 *
 * If you want a query or mutation to ONLY be accessible to logged in users, use this. It verifies
 * the session is valid and guarantees `ctx.session.user` is not null.
 *
 * @see https://trpc.io/docs/procedures
 */
export const protectedProcedure = t.procedure
  .use(timingMiddleware)
  .use(({ ctx, next }) => {
    if (!ctx.session?.user) {
      throw new TRPCError({ code: "UNAUTHORIZED" });
    }
    return next({
      ctx: {
        // infers the `session` as non-nullable
        session: { ...ctx.session, user: ctx.session.user },
      },
    });
  });

/**
 * Admin-only procedure
 *
 * Requires a valid session AND the user to have the "admin" role.
 * Used for managing the global extension threat DB, flagging extensions, etc.
 */
export const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.session.user.role !== "admin") {
    throw new TRPCError({ code: "FORBIDDEN" });
  }
  return next({ ctx });
});

/**
 * Manager procedure
 *
 * Requires a valid session AND membership in an org with role "owner" or "admin".
 * Attaches `ctx.org` (org row) and `ctx.orgRole` to context.
 * Throws UNAUTHORIZED if the user is not a manager of any org.
 */
export const managerProcedure = protectedProcedure.use(
  async ({ ctx, next }) => {
    const membership = await fetchManagerMembership(ctx.db, ctx.session.user.id);

    if (!membership) {
      throw new TRPCError({ code: "UNAUTHORIZED" });
    }

    if (membership.orgSuspendedAt) {
      throw new TRPCError({ code: "FORBIDDEN", message: "Organization is suspended" });
    }

    return next({
      ctx: {
        org: {
          id: membership.orgId,
          name: membership.orgName,
          plan: membership.orgPlan,
          suspendedAt: membership.orgSuspendedAt,
          lastWorkspaceSyncAt: membership.orgLastWorkspaceSyncAt,
        },
        orgRole: membership.orgRole as "owner" | "admin",
      },
    });
  },
);
