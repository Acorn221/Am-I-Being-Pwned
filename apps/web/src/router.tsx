import { lazy, Suspense, useLayoutEffect, useSyncExternalStore, useState } from "react";

import { Footer } from "~/components/footer";
import { Navbar } from "~/components/navbar";
import { useExtensionDatabase } from "~/hooks/use-extension-database";
import { authClient } from "~/lib/auth-client";

const App = lazy(() => import("~/App"));
const AdminLayout = lazy(() => import("~/components/admin/layout").then(m => ({ default: m.AdminLayout })));
const DemoLinksPage = lazy(() => import("~/components/admin/demo-links-page").then(m => ({ default: m.DemoLinksPage })));
const OrgDetailPage = lazy(() => import("~/components/admin/org-detail-page").then(m => ({ default: m.OrgDetailPage })));
const OrgsPage = lazy(() => import("~/components/admin/orgs-page").then(m => ({ default: m.OrgsPage })));
const DashboardPage = lazy(() => import("~/components/dashboard/dashboard-page").then(m => ({ default: m.DashboardPage })));
const DemoPage = lazy(() => import("~/components/demo/demo-page").then(m => ({ default: m.DemoPage })));
const DeviceDashboard = lazy(() => import("~/components/device-dashboard").then(m => ({ default: m.DeviceDashboard })));
const FaqPage = lazy(() => import("~/components/faq-page").then(m => ({ default: m.FaqPage })));
const JoinPage = lazy(() => import("~/components/join-page").then(m => ({ default: m.JoinPage })));
const LoginPage = lazy(() => import("~/components/login-page").then(m => ({ default: m.LoginPage })));
const ReportPage = lazy(() => import("~/components/report-page").then(m => ({ default: m.ReportPage })));
const SignupPage = lazy(() => import("~/components/signup-page").then(m => ({ default: m.SignupPage })));

const WEB_SESSION_KEY = "aibp_web_session";

// Module-level so it survives App unmounting
let savedHomeScroll = 0;

const REPORT_RE = /^\/report\/([a-p]{32})$/;
const ADMIN_ORG_RE = /^\/admin\/orgs\/([^/]+)$/;
const JOIN_RE = /^\/join\/([^/]+)$/;
const DEMO_RE = /^\/demo\/([^/]+)$/;

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

  // Device web session - from ?wst= query param or localStorage
  const [deviceToken] = useState<string | null>(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("wst") ?? localStorage.getItem(WEB_SESSION_KEY);
  });

  const reportMatch = REPORT_RE.exec(path);
  const adminOrgMatch = ADMIN_ORG_RE.exec(path);
  const joinMatch = JOIN_RE.exec(path);
  const demoMatch = DEMO_RE.exec(path);

  const extensionId = reportMatch?.[1];
  const joinToken = joinMatch?.[1];
  const demoToken = demoMatch?.[1];
  const isFaq = path === "/faq";
  const isLogin = path === "/login";
  const isSignup = path === "/signup";
  const isDashboard = path === "/dashboard" || path.startsWith("/dashboard/");
  const isAdmin = path.startsWith("/admin");
  const isJoin = !!joinToken;
  const isDemo = !!demoToken;

  const isSubPage = !!extensionId || isFaq || isLogin || isSignup || isDashboard || isAdmin || isJoin || isDemo;

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
    // Allow device-enrolled users to access /dashboard via web session token
    if (isDashboard && !session && deviceToken) return;
    if ((isDashboard || isAdmin) && !session) {
      navigate("/login");
      return;
    }
    if (isAdmin && session?.user.role !== "admin") {
      navigate("/dashboard");
    }
  }, [isPending, session, isDashboard, isAdmin, deviceToken]);

  return (
    <Suspense>
      {!isSubPage && <App />}

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

      {isJoin && joinToken && <JoinPage token={joinToken} />}

      {isDemo && demoToken && <DemoPage token={demoToken} />}

      {isLogin && <LoginPage />}

      {isSignup && <SignupPage />}

      {isDashboard && session && <DashboardPage />}
      {isDashboard && !session && deviceToken && <DeviceDashboard token={deviceToken} />}

      {isAdmin && session?.user.role === "admin" && (
        <AdminLayout path={path}>
          {adminOrgMatch ? (
            <OrgDetailPage orgId={adminOrgMatch[1] ?? ""} />
          ) : path === "/admin/demo" ? (
            <DemoLinksPage />
          ) : (
            <OrgsPage />
          )}
        </AdminLayout>
      )}
    </Suspense>
  );
}
