import { useLayoutEffect, useRef, useSyncExternalStore } from "react";

import App from "~/App";
import { ReportPage } from "~/components/report-page";
import { useExtensionDatabase } from "~/hooks/use-extension-database";

const REPORT_RE = /^#\/report\/([a-p]{32})$/;

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
  const scrollYRef = useRef(0);
  const prevExtIdRef = useRef<string | undefined>(undefined);

  const reportMatch = hash.match(REPORT_RE);
  const extensionId = reportMatch?.[1];

  // Capture scroll position during render (before DOM mutations)
  if (extensionId && !prevExtIdRef.current) {
    scrollYRef.current = window.scrollY;
  }
  prevExtIdRef.current = extensionId;

  // Scroll after DOM commits but before browser paints
  useLayoutEffect(() => {
    window.scrollTo(0, extensionId ? 0 : scrollYRef.current);
  }, [extensionId]);

  return (
    <>
      <div hidden={!!extensionId}>
        <App reports={reports} />
      </div>
      {extensionId && (
        <ReportPage
          extensionId={extensionId}
          ext={reports.get(extensionId)}
        />
      )}
    </>
  );
}
