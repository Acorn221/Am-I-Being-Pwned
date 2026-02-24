import { Button } from "@amibeingpwned/ui/button";
import {
  Building2,
  ChevronRight,
  LayoutDashboard,
  LogOut,
  Monitor,
  Puzzle,
  Shield,
} from "lucide-react";

import { authClient } from "~/lib/auth-client";
import { navigate } from "~/router";

interface NavItem {
  label: string;
  icon: React.ReactNode;
  href: string;
  match: (path: string) => boolean;
}

const NAV_ITEMS: NavItem[] = [
  {
    label: "Overview",
    icon: <LayoutDashboard className="h-4 w-4" />,
    href: "/admin",
    match: (p) => p === "/admin",
  },
  {
    label: "Organisations",
    icon: <Building2 className="h-4 w-4" />,
    href: "/admin/orgs",
    match: (p) => p.startsWith("/admin/orgs"),
  },
  {
    label: "Devices",
    icon: <Monitor className="h-4 w-4" />,
    href: "/admin/devices",
    match: (p) => p.startsWith("/admin/devices"),
  },
  {
    label: "Extensions",
    icon: <Puzzle className="h-4 w-4" />,
    href: "/admin/extensions",
    match: (p) => p.startsWith("/admin/extensions"),
  },
];

interface AdminLayoutProps {
  children: React.ReactNode;
  path: string;
}

export function AdminLayout({ children, path }: AdminLayoutProps) {
  async function handleSignOut() {
    await authClient.signOut();
    navigate("/");
  }

  return (
    <div className="bg-background flex min-h-screen">
      {/* Sidebar */}
      <aside className="border-border flex w-56 shrink-0 flex-col border-r">
        <div className="flex h-14 items-center gap-2 border-b px-4">
          <Shield className="text-primary h-5 w-5 shrink-0" />
          <span className="text-foreground text-sm font-semibold">
            AIBP Admin
          </span>
        </div>

        <nav className="flex flex-1 flex-col gap-1 p-2">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.href}
              onClick={() => navigate(item.href)}
              className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors ${
                item.match(path)
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>

        <div className="border-t p-2">
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground w-full justify-start gap-2"
            onClick={() => void handleSignOut()}
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </Button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex flex-1 flex-col overflow-auto">{children}</main>
    </div>
  );
}

interface PageHeaderProps {
  breadcrumbs: { label: string; href?: string }[];
  actions?: React.ReactNode;
}

export function PageHeader({ breadcrumbs, actions }: PageHeaderProps) {
  return (
    <div className="border-border flex h-14 items-center justify-between border-b px-6">
      <div className="flex items-center gap-1.5 text-sm">
        {breadcrumbs.map((crumb, i) => (
          <span key={i} className="flex items-center gap-1.5">
            {i > 0 && (
              <ChevronRight className="text-muted-foreground h-3.5 w-3.5" />
            )}
            {crumb.href ? (
              <button
                onClick={() => navigate(crumb.href!)}
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                {crumb.label}
              </button>
            ) : (
              <span className="text-foreground font-medium">{crumb.label}</span>
            )}
          </span>
        ))}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
