import { useLayoutEffect, useRef, useSyncExternalStore } from "react";

import App from "~/App";
import { AdminLayout } from "~/components/admin/layout";
import { OrgDetailPage } from "~/components/admin/org-detail-page";
import { OrgsPage } from "~/components/admin/orgs-page";
import { DashboardPage } from "~/components/dashboard/dashboard-page";
import { FaqPage } from "~/components/faq-page";
import { Footer } from "~/components/footer";
import { LoginPage } from "~/components/login-page";
import { Navbar } from "~/components/navbar";
import { ReportPage } from "~/components/report-page";
import { useExtensionDatabase } from "~/hooks/use-extension-database";
import { authClient } from "~/lib/auth-client";

const REPORT_RE = /^\/report\/([a-p]{32})$/;
const ADMIN_ORG_RE = /^\/admin\/orgs\/([^/]+)$/;

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
  const { data: session, isPending } = authClient.useSession();
  const scrollYRef = useRef(0);
  const prevExtIdRef = useRef<string | undefined>(undefined);

  const reportMatch = path.match(REPORT_RE);
  const adminOrgMatch = path.match(ADMIN_ORG_RE);

  const extensionId = reportMatch?.[1];
  const isFaq = path === "/faq";
  const isLogin = path === "/login";
  const isDashboard = path === "/dashboard";
  const isAdmin = path.startsWith("/admin");

  const isSubPage = !!extensionId || isFaq || isLogin || isDashboard || isAdmin;

  // Capture scroll position during render (before DOM mutations)
  if (isSubPage && !prevExtIdRef.current) {
    scrollYRef.current = window.scrollY;
  }
  prevExtIdRef.current = extensionId;

  // Scroll after DOM commits but before browser paints
  useLayoutEffect(() => {
    window.scrollTo(0, isSubPage ? 0 : scrollYRef.current);
  }, [isSubPage]);

  // Redirect /admin → /admin/orgs
  useLayoutEffect(() => {
    if (path === "/admin") navigate("/admin/orgs");
  }, [path]);

  // Auth guards (skip while session is loading)
  useLayoutEffect(() => {
    if (isPending) return;
    if ((isDashboard || isAdmin) && !session) {
      navigate("/login");
      return;
    }
    if (isAdmin && session?.user.role !== "admin") {
      navigate("/dashboard");
    }
  }, [isPending, session, isDashboard, isAdmin]);

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

      {isLogin && <LoginPage />}

      {isDashboard && session && <DashboardPage />}

      {isAdmin && session?.user.role === "admin" && (
        <AdminLayout path={path}>
          {adminOrgMatch ? (
            <OrgDetailPage orgId={adminOrgMatch[1]!} />
          ) : (
            <OrgsPage />
          )}
        </AdminLayout>
      )}
    </>
  );
}
