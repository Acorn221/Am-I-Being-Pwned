import { useSyncExternalStore } from "react";

import App from "~/App";
import { ReportPage } from "~/components/report-page";
import { useExtensionDatabase } from "~/hooks/use-extension-database";

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
  const { reports } = useExtensionDatabase();

  const reportMatch = hash.match(/^#\/report\/([a-p]{32})$/);
  if (reportMatch?.[1]) {
    return (
      <ReportPage
        extensionId={reportMatch[1]}
        ext={reports.get(reportMatch[1])}
      />
    );
  }

  return <App reports={reports} />;
}
