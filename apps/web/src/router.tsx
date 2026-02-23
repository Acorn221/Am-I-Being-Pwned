import { useLayoutEffect, useRef, useSyncExternalStore } from "react";

import App from "~/App";
import { FaqPage } from "~/components/faq-page";
import { Footer } from "~/components/footer";
import { Navbar } from "~/components/navbar";
import { ReportPage } from "~/components/report-page";
import { useExtensionDatabase } from "~/hooks/use-extension-database";

const REPORT_RE = /^\/report\/([a-p]{32})$/;

function getPath() {
  return window.location.pathname;
}

function subscribe(callback: () => void) {
  window.addEventListener("popstate", callback);
  return () => window.removeEventListener("popstate", callback);
}

function usePath() {
  return useSyncExternalStore(subscribe, getPath);
}

/** Navigate without a full page reload. */
export function navigate(to: string) {
  window.history.pushState(null, "", to);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function Router() {
  const path = usePath();
  const { reports } = useExtensionDatabase();
  const scrollYRef = useRef(0);
  const prevExtIdRef = useRef<string | undefined>(undefined);

  const reportMatch = path.match(REPORT_RE);
  const extensionId = reportMatch?.[1];
  const isFaq = path === "/faq";
  const isSubPage = !!extensionId || isFaq;

  // Capture scroll position during render (before DOM mutations)
  if (isSubPage && !prevExtIdRef.current) {
    scrollYRef.current = window.scrollY;
  }
  prevExtIdRef.current = extensionId;

  // Scroll after DOM commits but before browser paints
  useLayoutEffect(() => {
    window.scrollTo(0, isSubPage ? 0 : scrollYRef.current);
  }, [isSubPage]);

  return (
    <>
      <div hidden={isSubPage}>
        <App reports={reports} />
      </div>
      {extensionId && (
        <div className="bg-background min-h-screen">
          <Navbar />
          <ReportPage
            extensionId={extensionId}
            ext={reports.get(extensionId)}
          />
          <Footer />
        </div>
      )}
      {isFaq && (
        <div className="bg-background min-h-screen">
          <Navbar />
          <FaqPage />
          <Footer />
        </div>
      )}
    </>
  );
}
