import { useEffect, useRef } from "react";

declare global {
  interface Window {
    turnstile?: {
      render: (
        container: HTMLElement,
        options: {
          sitekey: string;
          execution?: "render" | "execute";
          appearance?: "always" | "interaction-only";
          callback: (token: string) => void;
          "expired-callback": () => void;
          "error-callback": () => void;
        },
      ) => string;
      execute: (widgetId: string) => void;
      remove: (widgetId: string) => void;
    };
  }
}

interface TurnstileWidgetProps {
  siteKey: string;
  /** When true, widget waits for a manual .execute() call before verifying. */
  deferred?: boolean;
  onVerify: (token: string) => void;
  onExpire: () => void;
  className?: string;
}

export function TurnstileWidget({
  siteKey,
  deferred = false,
  onVerify,
  onExpire,
  className,
}: TurnstileWidgetProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<string | null>(null);
  const onVerifyRef = useRef(onVerify);
  const onExpireRef = useRef(onExpire);

  useEffect(() => { onVerifyRef.current = onVerify; }, [onVerify]);
  useEffect(() => { onExpireRef.current = onExpire; }, [onExpire]);

  useEffect(() => {
    let removed = false;

    function mount() {
      if (removed || !containerRef.current || !window.turnstile) return;
      widgetIdRef.current = window.turnstile.render(containerRef.current, {
        sitekey: siteKey,
        execution: deferred ? "execute" : "render",
        appearance: "interaction-only",
        callback: (token) => onVerifyRef.current(token),
        "expired-callback": () => onExpireRef.current(),
        "error-callback": () => onExpireRef.current(),
      });
      // If deferred, start immediately after mount - the widget will only show
      // UI if Cloudflare decides an interaction is required.
      if (deferred && widgetIdRef.current) {
        window.turnstile.execute(widgetIdRef.current);
      }
    }

    if (window.turnstile) {
      mount();
    } else if (!document.getElementById("cf-turnstile-script")) {
      const script = document.createElement("script");
      script.id = "cf-turnstile-script";
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.async = true;
      script.defer = true;
      script.addEventListener("load", mount);
      document.head.appendChild(script);
    } else {
      const check = setInterval(() => {
        if (window.turnstile) { clearInterval(check); mount(); }
      }, 50);
      return () => clearInterval(check);
    }

    return () => {
      removed = true;
      if (widgetIdRef.current != null && window.turnstile) {
        window.turnstile.remove(widgetIdRef.current);
        widgetIdRef.current = null;
      }
    };
  }, [siteKey, deferred]);

  return <div ref={containerRef} className={className} />;
}
