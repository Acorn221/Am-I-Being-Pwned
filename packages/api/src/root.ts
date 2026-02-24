import { adminRouter } from "./router/admin/index";
import { alertsRouter } from "./router/alerts";
import { authRouter } from "./router/auth";
import { devicesRouter } from "./router/devices";
import { extensionsRouter } from "./router/extensions";
import { fleetRouter } from "./router/fleet";
import { postRouter } from "./router/post";
import { subscriptionRouter } from "./router/subscription";
import { createTRPCRouter } from "./trpc";

export const appRouter = createTRPCRouter({
  admin: adminRouter,
  auth: authRouter,
  devices: devicesRouter,
  fleet: fleetRouter,
  post: postRouter,
  alerts: alertsRouter,
  extensions: extensionsRouter,
  subscription: subscriptionRouter,
});

// export type definition of API
export type AppRouter = typeof appRouter;
