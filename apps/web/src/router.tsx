import { useSyncExternalStore } from "react";

import App from "~/App";
import { ReportPage } from "~/components/report-page";

function getHash() {
  return window.location.hash;
}

function subscribe(callback: () => void) {
  window.addEventListener("hashchange", callback);
  return () => window.removeEventListener("hashchange", callback);
}

function useHash() {
  return useSyncExternalStore(subscribe, getHash);
}

export function Router() {
  const hash = useHash();

  const reportMatch = hash.match(/^#\/report\/([a-p]{32})$/);
  if (reportMatch?.[1]) {
    return <ReportPage extensionId={reportMatch[1]} />;
  }

  return <App />;
}
