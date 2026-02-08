"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtResponseSchema = exports.ExtRequestSchema = void 0;
var v4_1 = require("zod/v4");
// ---------------------------------------------------------------------------
// Extension ↔ Web App message schemas
// ---------------------------------------------------------------------------
/** Chrome extension IDs are 32 lowercase a-p characters */
var extensionIdSchema = v4_1.z.string().regex(/^[a-p]{32}$/);
var pingRequest = v4_1.z.object({
    type: v4_1.z.literal("PING"),
    version: v4_1.z.literal(1),
});
var getExtensionsRequest = v4_1.z.object({
    type: v4_1.z.literal("GET_EXTENSIONS"),
    version: v4_1.z.literal(1),
});
/** Validates incoming messages from the web page */
exports.ExtRequestSchema = v4_1.z.discriminatedUnion("type", [
    pingRequest,
    getExtensionsRequest,
]);
var installedExtensionInfoSchema = v4_1.z.object({
    id: extensionIdSchema,
    name: v4_1.z.string().max(256),
    enabled: v4_1.z.boolean(),
});
var pongResponse = v4_1.z.object({
    type: v4_1.z.literal("PONG"),
    version: v4_1.z.literal(1),
});
var extensionsResultResponse = v4_1.z.object({
    type: v4_1.z.literal("EXTENSIONS_RESULT"),
    version: v4_1.z.literal(1),
    extensions: v4_1.z.array(installedExtensionInfoSchema).max(500),
});
var errorResponse = v4_1.z.object({
    type: v4_1.z.literal("ERROR"),
    version: v4_1.z.literal(1),
    code: v4_1.z.string().max(64),
    message: v4_1.z.string().max(256),
});
/** Validates responses received by the web page */
exports.ExtResponseSchema = v4_1.z.discriminatedUnion("type", [
    pongResponse,
    extensionsResultResponse,
    errorResponse,
]);
