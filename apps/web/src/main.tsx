import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./index.css";

import { ThemeProvider } from "@amibeingpwned/ui/theme";
import { Toaster } from "@amibeingpwned/ui/toast";

import { TRPCProvider } from "./lib/TRPCProvider";
import { Router } from "./router";

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <TRPCProvider>
        <Router />
        <Toaster richColors position="bottom-right" />
      </TRPCProvider>
    </ThemeProvider>
  </StrictMode>,
);
