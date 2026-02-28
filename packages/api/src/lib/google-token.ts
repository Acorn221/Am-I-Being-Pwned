import { TRPCError } from "@trpc/server";
import { and, eq } from "drizzle-orm";

import { account } from "@amibeingpwned/db";
import type { db as DbType } from "@amibeingpwned/db/client";

/**
 * Returns a valid Google OAuth access token for the given user.
 * Automatically refreshes via the refresh token if the access token is expired.
 * Throws UNAUTHORIZED if no Google account is linked or refresh fails.
 */
export async function getGoogleAccessToken(
  db: typeof DbType,
  userId: string,
): Promise<string> {
  const [googleAccount] = await db
    .select({
      id: account.id,
      accessToken: account.accessToken,
      refreshToken: account.refreshToken,
      accessTokenExpiresAt: account.accessTokenExpiresAt,
    })
    .from(account)
    .where(and(eq(account.userId, userId), eq(account.providerId, "google")))
    .limit(1);

  if (!googleAccount?.accessToken) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "No Google account linked. Please sign in with Google.",
    });
  }

  // Still valid with a 60-second buffer
  if (
    googleAccount.accessTokenExpiresAt &&
    googleAccount.accessTokenExpiresAt.getTime() > Date.now() + 60_000
  ) {
    return googleAccount.accessToken;
  }

  // Expired — attempt refresh
  if (!googleAccount.refreshToken) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message:
        "Google access token expired and no refresh token is available. Please sign in again.",
    });
  }

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: googleAccount.refreshToken,
      client_id: process.env.AUTH_GOOGLE_ID ?? "",
      client_secret: process.env.AUTH_GOOGLE_SECRET ?? "",
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: `Google token refresh failed: ${errText}`,
    });
  }

  const data = (await res.json()) as {
    access_token: string;
    expires_in: number;
  };

  const newExpiresAt = new Date(Date.now() + data.expires_in * 1000);

  await db
    .update(account)
    .set({
      accessToken: data.access_token,
      accessTokenExpiresAt: newExpiresAt,
      updatedAt: new Date(),
    })
    .where(eq(account.id, googleAccount.id));

  return data.access_token;
}
