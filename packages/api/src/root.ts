import { adminRouter } from "./router/admin/index";
import { alertsRouter } from "./router/alerts";
import { authRouter } from "./router/auth";
import { devicesRouter } from "./router/devices";
import { fleetRouter } from "./router/fleet";
import { orgRouter } from "./router/org";
import { subscriptionRouter } from "./router/subscription";
import { webhooksRouter } from "./router/webhooks";
import { workspaceRouter } from "./router/workspace";
import { createTRPCRouter } from "./trpc";

export const appRouter = createTRPCRouter({
  admin: adminRouter,
  auth: authRouter,
  devices: devicesRouter,
  fleet: fleetRouter,
  org: orgRouter,
  alerts: alertsRouter,
  subscription: subscriptionRouter,
  webhooks: webhooksRouter,
  workspace: workspaceRouter,
});

// export type definition of API
export type AppRouter = typeof appRouter;
