import type { ExtensionDatabase, RiskLevel } from "@amibeingpwned/types";

const DB_NAME = "aibp";
const DB_VERSION = 1;
const CACHE_STORE = "cache";
const NOTIFIED_STORE = "notified";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(CACHE_STORE)) {
        db.createObjectStore(CACHE_STORE);
      }
      if (!db.objectStoreNames.contains(NOTIFIED_STORE)) {
        db.createObjectStore(NOTIFIED_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(new Error("openDb failed", { cause: req.error }));
  });
}

function idbGet<T>(store: string, key: string): Promise<T | undefined> {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readonly");
        const req = tx.objectStore(store).get(key);
        req.onsuccess = () => resolve(req.result as T | undefined);
        req.onerror = () => reject(new Error("idbGet failed", { cause: req.error }));
      }),
  );
}

function idbPut<T>(store: string, key: string, value: T): Promise<void> {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readwrite");
        const req = tx.objectStore(store).put(value, key);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(new Error("idbPut failed", { cause: req.error }));
      }),
  );
}

// ---------------------------------------------------------------------------
// Extension database cache
// ---------------------------------------------------------------------------

interface DbCache {
  data: ExtensionDatabase;
  fetchedAt: number;
}

export async function getCachedDb(): Promise<DbCache | undefined> {
  return idbGet<DbCache>(CACHE_STORE, "extensionDb");
}

export async function setCachedDb(data: ExtensionDatabase): Promise<void> {
  return idbPut<DbCache>(CACHE_STORE, "extensionDb", {
    data,
    fetchedAt: Date.now(),
  });
}

// ---------------------------------------------------------------------------
// Notification dedup — tracks last notified risk per extension
// ---------------------------------------------------------------------------

export async function getNotifiedRisk(
  extensionId: string,
): Promise<RiskLevel | undefined> {
  return idbGet<RiskLevel>(NOTIFIED_STORE, extensionId);
}

export async function setNotifiedRisk(
  extensionId: string,
  risk: RiskLevel,
): Promise<void> {
  return idbPut<RiskLevel>(NOTIFIED_STORE, extensionId, risk);
}
