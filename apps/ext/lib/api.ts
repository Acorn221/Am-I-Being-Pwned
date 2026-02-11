import type { ExtensionDatabase, ExtensionReport } from "@amibeingpwned/types";
import { getCachedDb, setCachedDb } from "./storage";

export const API_BASE_URL = import.meta.env.DEV
  ? "http://localhost:3000"
  : "https://amibeingpwned.com";

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export async function fetchExtensionDatabase(): Promise<ExtensionDatabase> {
  const cached = await getCachedDb();
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.data;
  }

  const res = await fetch(`${API_BASE_URL}/extensions.json`);
  if (!res.ok) {
    throw new Error(`Failed to fetch extension database: ${res.status}`);
  }

  const data = (await res.json()) as ExtensionDatabase;
  await setCachedDb(data);
  return data;
}

export async function lookupExtension(
  id: string,
): Promise<ExtensionReport | null> {
  const db = await fetchExtensionDatabase();
  return db[id] ?? null;
}
