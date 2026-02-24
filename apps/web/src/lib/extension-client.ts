import type { ExtRequest, ExtResponse } from "@amibeingpwned/types";
import { ExtResponseSchema } from "@amibeingpwned/validators";

export class ExtensionClient {
  private static readonly KNOWN_ID = "amibeingpndbmhcmnjdekhljpjcbjnpl";

  private extensionId: string | null = null;

  /** The resolved extension ID, or null if not yet detected */
  get id() {
    return this.extensionId;
  }

  /**
   * Detect the extension - tries the known ID first (fast), then falls back
   * to content script discovery (for dev builds with unstable IDs).
   * Stores the ID internally on success.
   */
  async detect(): Promise<string | null> {
    console.log("[AIBP] detect: trying known ID", ExtensionClient.KNOWN_ID);
    const known = await this.ping(ExtensionClient.KNOWN_ID);
    if (known) {
      console.log("[AIBP] detect: known ID responded, extension connected");
      this.extensionId = known;
      return known;
    }
    console.log("[AIBP] detect: known ID did not respond, falling back to content script discovery");
    const discovered = await this.listenForContentScript();
    if (discovered) {
      console.log("[AIBP] detect: discovered ID via content script:", discovered);
      this.extensionId = discovered;
    } else {
      console.log("[AIBP] detect: content script discovery timed out — extension not installed");
    }
    return discovered;
  }

  /**
   * Send a validated message to the extension via chrome.runtime.sendMessage.
   * Returns the parsed response or throws on timeout / validation failure.
   */
  send(request: ExtRequest, timeoutMs = 5000): Promise<ExtResponse> {
    const id = this.extensionId;
    if (!id) {
      return Promise.reject(
        new Error("Extension not detected - call detect() first"),
      );
    }

    return new Promise((resolve, reject) => {
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      if (!chrome?.runtime?.sendMessage) {
        reject(new Error("chrome.runtime.sendMessage not available"));
        return;
      }

      const timer = setTimeout(() => {
        reject(new Error("Extension response timed out"));
      }, timeoutMs);

      chrome.runtime.sendMessage(id, request, (response: unknown) => {
        clearTimeout(timer);

        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        const parsed = ExtResponseSchema.safeParse(response);
        if (!parsed.success) {
          reject(new Error("Invalid response from extension"));
          return;
        }

        resolve(parsed.data);
      });
    });
  }

  /**
   * Try to PING the extension at a given ID. Returns the ID if it responds,
   * null otherwise.
   */
  private async ping(id: string): Promise<string | null> {
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (!chrome?.runtime?.sendMessage) {
      console.log("[AIBP] ping: chrome.runtime.sendMessage not available");
      return null;
    }

    const prev = this.extensionId;
    this.extensionId = id;
    try {
      const resp = await this.send({ type: "PING", version: 1 }, 1000);
      const ok = resp.type === "PONG";
      console.log("[AIBP] ping", id, "→", ok ? "PONG ✓" : `unexpected response:`, ok ? null : resp);
      return ok ? id : null;
    } catch (err) {
      console.log("[AIBP] ping", id, "→ failed:", err instanceof Error ? err.message : err);
      return null;
    } finally {
      this.extensionId = prev;
    }
  }

  /**
   * Parse a postMessage data payload as a bridge ready message.
   * Returns the extension ID if valid, null otherwise.
   */
  private static parseBridgeMessage(data: unknown): string | null {
    const d = data as Record<string, unknown> | null;
    if (
      d?.channel === "AIBP_BRIDGE" &&
      d.type === "AIBP_EXTENSION_READY" &&
      typeof d.extensionId === "string"
    ) {
      return d.extensionId;
    }
    return null;
  }

  /**
   * Listen for the content script's AIBP_EXTENSION_READY postMessage
   * to discover the extension's runtime ID.
   */
  private listenForContentScript(timeoutMs = 2000): Promise<string | null> {
    return new Promise((resolve) => {
      let settled = false;

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          window.removeEventListener("message", handler);
          console.log("[AIBP] content script discovery timed out after", timeoutMs, "ms");
          resolve(null);
        }
      }, timeoutMs);

      function handler(event: MessageEvent<unknown>) {
        if (event.source !== window) return;
        const extId = ExtensionClient.parseBridgeMessage(event.data);
        if (!extId) return;

        if (!settled) {
          settled = true;
          clearTimeout(timer);
          window.removeEventListener("message", handler);
          console.log("[AIBP] received AIBP_EXTENSION_READY, ext ID:", extId);
          resolve(extId);
        }
      }

      window.addEventListener("message", handler);

      // Trigger the content script to re-broadcast (handles the case where
      // the initial AIBP_EXTENSION_READY fired before React mounted)
      console.log("[AIBP] sending AIBP_REQUEST_ID to content script");
      window.postMessage(
        { channel: "AIBP_BRIDGE", type: "AIBP_REQUEST_ID" },
        location.origin,
      );
    });
  }
}

/** Singleton instance for use across the app */
export const extensionClient = new ExtensionClient();
