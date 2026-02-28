import { z } from "zod/v4";

// ---------------------------------------------------------------------------
// Extension ↔ Web App message schemas
// ---------------------------------------------------------------------------

/** Chrome extension IDs are 32 lowercase a-p characters */
const extensionIdSchema = z.string().regex(/^[a-p]{32}$/);

const pingRequest = z.object({
  type: z.literal("PING"),
  version: z.literal(1),
});

const getExtensionsRequest = z.object({
  type: z.literal("GET_EXTENSIONS"),
  version: z.literal(1),
});

const registerWithInviteRequest = z.object({
  type: z.literal("REGISTER_WITH_INVITE"),
  version: z.literal(1),
  token: z.string(),
});

/** Validates incoming messages from the web page */
export const ExtRequestSchema = z.discriminatedUnion("type", [
  pingRequest,
  getExtensionsRequest,
  registerWithInviteRequest,
]);

const installedExtensionInfoSchema = z.object({
  id: extensionIdSchema,
  name: z.string().max(256),
  enabled: z.boolean(),
});

const pongResponse = z.object({
  type: z.literal("PONG"),
  version: z.literal(1),
});

const extensionsResultResponse = z.object({
  type: z.literal("EXTENSIONS_RESULT"),
  version: z.literal(1),
  extensions: z.array(installedExtensionInfoSchema).max(500),
});

const inviteRegisteredResponse = z.object({
  type: z.literal("INVITE_REGISTERED"),
  version: z.literal(1),
  webSessionToken: z.string(),
});

const errorResponse = z.object({
  type: z.literal("ERROR"),
  version: z.literal(1),
  code: z.string().max(64),
  message: z.string().max(256),
});

/** Validates responses received by the web page */
export const ExtResponseSchema = z.discriminatedUnion("type", [
  pongResponse,
  extensionsResultResponse,
  inviteRegisteredResponse,
  errorResponse,
]);
