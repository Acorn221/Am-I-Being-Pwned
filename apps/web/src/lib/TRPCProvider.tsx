import { QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

import { TRPCProvider as TRPCProviderInner, makeQueryClient, makeTRPCClient } from "./trpc";

export function TRPCProvider({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => makeQueryClient());
  const [trpcClient] = useState(() => makeTRPCClient());

  return (
    <QueryClientProvider client={queryClient}>
      <TRPCProviderInner trpcClient={trpcClient} queryClient={queryClient}>
        {children}
      </TRPCProviderInner>
    </QueryClientProvider>
  );
}
