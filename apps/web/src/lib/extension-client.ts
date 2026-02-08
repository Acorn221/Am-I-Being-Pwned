import type { ExtRequest, ExtResponse } from "@acme/types";
import { ExtResponseSchema } from "@acme/validators";

/**
 * Listen for the content script's AIBP_EXTENSION_READY postMessage
 * to discover the extension's runtime ID. Returns null if not detected
 * within the timeout.
 */
export function detectExtension(timeoutMs = 2000): Promise<string | null> {
  return new Promise((resolve) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        window.removeEventListener("message", handler);
        resolve(null);
      }
    }, timeoutMs);

    function handler(event: MessageEvent) {
      if (
        event.source !== window ||
        event.data?.channel !== "AIBP_BRIDGE" ||
        event.data?.type !== "AIBP_EXTENSION_READY" ||
        typeof event.data?.extensionId !== "string"
      ) {
        return;
      }
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        window.removeEventListener("message", handler);
        resolve(event.data.extensionId as string);
      }
    }

    window.addEventListener("message", handler);
  });
}

/**
 * Send a validated message to the extension via chrome.runtime.sendMessage.
 * Returns the parsed response or throws on timeout / validation failure.
 */
export function sendToExtension(
  extensionId: string,
  request: ExtRequest,
  timeoutMs = 5000,
): Promise<ExtResponse> {
  return new Promise((resolve, reject) => {
    // chrome.runtime.sendMessage is only available on pages that an extension
    // has declared in externally_connectable
    if (!chrome?.runtime?.sendMessage) {
      reject(new Error("chrome.runtime.sendMessage not available"));
      return;
    }

    const timer = setTimeout(() => {
      reject(new Error("Extension response timed out"));
    }, timeoutMs);

    chrome.runtime.sendMessage(extensionId, request, (response: unknown) => {
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
