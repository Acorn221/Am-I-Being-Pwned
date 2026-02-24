import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./index.css";

import { TRPCProvider } from "./lib/TRPCProvider";
import { Router } from "./router";

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <TRPCProvider>
      <Router />
    </TRPCProvider>
  </StrictMode>,
);
