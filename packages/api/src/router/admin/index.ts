import { createTRPCRouter } from "../../trpc";
import { adminDevicesRouter } from "./devices";
import { adminExtensionsRouter } from "./extensions";
import { adminOrgsRouter } from "./orgs";
import { adminScansRouter } from "./scans";
import { adminStatsRouter } from "./stats";
import { adminUsersRouter } from "./users";

export const adminRouter = createTRPCRouter({
  extensions: adminExtensionsRouter,
  orgs: adminOrgsRouter,
  users: adminUsersRouter,
  devices: adminDevicesRouter,
  scans: adminScansRouter,
  stats: adminStatsRouter,
});
