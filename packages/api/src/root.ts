import { adminRouter } from "./router/admin/index";
import { authRouter } from "./router/auth";
import { devicesRouter } from "./router/devices";
import { postRouter } from "./router/post";
import { createTRPCRouter } from "./trpc";

export const appRouter = createTRPCRouter({
  admin: adminRouter,
  auth: authRouter,
  devices: devicesRouter,
  post: postRouter,
});

// export type definition of API
export type AppRouter = typeof appRouter;
