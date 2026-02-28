import { lazy, Suspense, useLayoutEffect, useSyncExternalStore } from "react";

import { Footer } from "~/components/footer";
import { Navbar } from "~/components/navbar";
import { useExtensionDatabase } from "~/hooks/use-extension-database";
import { authClient } from "~/lib/auth-client";

const App = lazy(() => import("~/App"));
const AdminLayout = lazy(() => import("~/components/admin/layout").then(m => ({ default: m.AdminLayout })));
const OrgDetailPage = lazy(() => import("~/components/admin/org-detail-page").then(m => ({ default: m.OrgDetailPage })));
const OrgsPage = lazy(() => import("~/components/admin/orgs-page").then(m => ({ default: m.OrgsPage })));
const DashboardPage = lazy(() => import("~/components/dashboard/dashboard-page").then(m => ({ default: m.DashboardPage })));
const FaqPage = lazy(() => import("~/components/faq-page").then(m => ({ default: m.FaqPage })));
const LoginPage = lazy(() => import("~/components/login-page").then(m => ({ default: m.LoginPage })));
const ReportPage = lazy(() => import("~/components/report-page").then(m => ({ default: m.ReportPage })));

// Module-level so it survives App unmounting
let savedHomeScroll = 0;

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

  const reportMatch = REPORT_RE.exec(path);
  const adminOrgMatch = ADMIN_ORG_RE.exec(path);

  const extensionId = reportMatch?.[1];
  const isFaq = path === "/faq";
  const isLogin = path === "/login";
  const isDashboard = path === "/dashboard";
  const isAdmin = path.startsWith("/admin");

  const isSubPage = !!extensionId || isFaq || isLogin || isDashboard || isAdmin;

  useLayoutEffect(() => {
    if (isSubPage) {
      savedHomeScroll = window.scrollY;
      window.scrollTo(0, 0);
    } else {
      window.scrollTo(0, savedHomeScroll);
    }
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
    <Suspense>
      {!isSubPage && <App reports={reports} />}

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
            <OrgDetailPage orgId={adminOrgMatch[1] ?? ""} />
          ) : (
            <OrgsPage />
          )}
        </AdminLayout>
      )}
    </Suspense>
  );
}
