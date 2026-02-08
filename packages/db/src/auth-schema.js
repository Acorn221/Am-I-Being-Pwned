"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verification = exports.account = exports.session = exports.user = void 0;
var pg_core_1 = require("drizzle-orm/pg-core");
exports.user = (0, pg_core_1.pgTable)("user", function (t) { return ({
    id: t.text().primaryKey(),
    name: t.text().notNull(),
    email: t.text().notNull().unique(),
    emailVerified: t.boolean().notNull(),
    image: t.text(),
    createdAt: t.timestamp().notNull(),
    updatedAt: t.timestamp().notNull(),
}); });
exports.session = (0, pg_core_1.pgTable)("session", function (t) { return ({
    id: t.text().primaryKey(),
    expiresAt: t.timestamp().notNull(),
    token: t.text().notNull().unique(),
    createdAt: t.timestamp().notNull(),
    updatedAt: t.timestamp().notNull(),
    ipAddress: t.text(),
    userAgent: t.text(),
    userId: t
        .text()
        .notNull()
        .references(function () { return exports.user.id; }, { onDelete: "cascade" }),
}); });
exports.account = (0, pg_core_1.pgTable)("account", function (t) { return ({
    id: t.text().primaryKey(),
    accountId: t.text().notNull(),
    providerId: t.text().notNull(),
    userId: t
        .text()
        .notNull()
        .references(function () { return exports.user.id; }, { onDelete: "cascade" }),
    accessToken: t.text(),
    refreshToken: t.text(),
    idToken: t.text(),
    accessTokenExpiresAt: t.timestamp(),
    refreshTokenExpiresAt: t.timestamp(),
    scope: t.text(),
    password: t.text(),
    createdAt: t.timestamp().notNull(),
    updatedAt: t.timestamp().notNull(),
}); });
exports.verification = (0, pg_core_1.pgTable)("verification", function (t) { return ({
    id: t.text().primaryKey(),
    identifier: t.text().notNull(),
    value: t.text().notNull(),
    expiresAt: t.timestamp().notNull(),
    createdAt: t.timestamp(),
    updatedAt: t.timestamp(),
}); });
