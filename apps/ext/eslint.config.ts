import { defineConfig } from "eslint/config";

import { baseConfig } from "@amibeingpwned/eslint-config/base";
import { reactConfig } from "@amibeingpwned/eslint-config/react";

export default defineConfig(
  {
    ignores: [".wxt/**", ".output/**"],
  },
  baseConfig,
  reactConfig,
  {
    rules: {
      // DEV, PROD, MODE etc. are Vite built-ins, not custom env vars
      "turbo/no-undeclared-env-vars": [
        "error",
        { allowList: ["^DEV$", "^PROD$", "^MODE$"] },
      ],
    },
  },
);
