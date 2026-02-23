import { navigate } from "~/router";

const LINKS = [
  { label: "FAQ", href: "/faq", onClick: () => navigate("/faq") },
  { label: "Privacy Policy", href: "#" },
  { label: "Terms of Service", href: "#" },
  { label: "Contact", href: "mailto:hello@amibeingpwned.com" },
] as const;

export function Footer() {
  return (
    <footer className="border-border/50 border-t">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <div className="flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-foreground mb-1 text-sm font-semibold">
              Am I Being Pwned?
            </p>
            <p className="text-muted-foreground text-xs">
              Protecting organizations from malicious browser extensions.
            </p>
            <p className="text-muted-foreground mt-3 text-xs">
              &copy; {new Date().getFullYear()} J4A Industries. All rights
              reserved.
            </p>
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-2">
            {LINKS.map((link) => (
              <a
                key={link.label}
                href={link.href}
                onClick={
                  "onClick" in link
                    ? (e) => {
                        e.preventDefault();
                        link.onClick();
                      }
                    : undefined
                }
                className="text-muted-foreground hover:text-foreground text-sm transition-colors"
              >
                {link.label}
              </a>
            ))}
          </div>
        </div>
      </div>
    </footer>
  );
}
