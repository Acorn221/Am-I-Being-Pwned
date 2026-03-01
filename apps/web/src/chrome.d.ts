/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_EXTENSION_ID?: string;
}

/**
 * Minimal type declarations for chrome.runtime APIs available to web pages
 * via the externally_connectable manifest key.
 */
declare namespace chrome {
  namespace runtime {
    const lastError: { message?: string } | undefined;
    function sendMessage(
      extensionId: string,
      message: unknown,
      callback: (response: unknown) => void,
    ): void;
  }
}
