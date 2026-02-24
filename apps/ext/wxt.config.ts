import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "wxt";

// See https://wxt.dev/api/config.html
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: ({ mode }) => ({
    name: "Am I Being Pwned",
    short_name: "Am I Pwned?",
    description: "Scan your installed extensions for data harvesting, session hijacking, and other threats.",
    action: {
      default_popup: "popup/index.html",
    },
    permissions: ["alarms", "management", "notifications", "storage"],
    host_permissions: [
      "https://amibeingpwned.com/*",
      ...(mode === "development" ? ["http://localhost/*"] : []),
    ],
    externally_connectable: {
      matches: [
        "https://amibeingpwned.com/*",
        ...(mode === "development" ? ["http://localhost/*"] : []),
      ],
    },
    // id = amibeingpndbmhcmnjdekhljpjcbjnpl
    ...(mode === "development" ? {
      "key": "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBWvvsi01+e+dBPidQbGFSJl+5NkOOZzvXjfG2YzeDpDPiY+smMVcYCu6gKqXzZXmKc2cz6m5K2yDnE2YdyYNq8plwzEMdA1uoOlRydD/ad/gJaxkY2Wyi6V0vUac3KZLQ8EJEMmKeVHNJT7rnCYoBG2xNER8cWGTs2KIGq1870zqEnvNNCaP8+hfduZUYiU4eyZXjgxYEcNX7zb2rcUX+rvUAAD4qg38BFuW7F2Sc3jACPZGS0r4b1J+M5R7x2ZOoCmeGpuwXg4iCH5ZA3Et3cqvVgebLARZF3H2abnRXmyhDP0oNOmAh29kkjLu0aTEJeBrrmH1toB7xqWcfLHFKRAgMBAAE="
    } : {}),
  }),
  vite: () => ({
    plugins: [tailwindcss()],
    server: { port: 3002 },
  }),
  dev: {
    server: {
      port: 3001
    }
  },
  runner: {
    disabled: true,
  },
});
