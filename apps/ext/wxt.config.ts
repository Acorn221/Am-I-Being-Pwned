import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "wxt";

// See https://wxt.dev/api/config.html
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: ({ mode }) => ({
    name: "Am I Being Pwned",
    short_name: "Am I Pwned?",
    description: "Scan your installed extensions for data harvesting, session hijacking, and other threats.",
    action: {},
    permissions: ["management"],
    externally_connectable: {
      matches: [
        "https://amibeingpwned.com/*",
        ...(mode === "development" ? ["http://localhost/*"] : []),
      ],
    },
    // id = ddialdjfnnjlobnkgbfnboaadhghibah
    key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7MJwZypGpoYLHd8BS0OMCcU6bxD/kStylSLmMiXn+g+obA48pKspGC8VElJ5G8G3dQBVtmjKWoom/z05+K8f6PemCk6heeZG6hqDmTjfnxCKRR57lXuTUvyKWZ+/FfySM/lsQqcbhsvkWsJCkeyGloGyw+13MvdoYigg0lTfESpGuwIWqE2pupvwAr54kYDEYlC9L+2YMCoB2zPvqF6OnBYjrETA/kyOqO3fiZ+5vXFJiiyLxYFg+afQY0ZrRkwxfJ99TpUnsUnUq2LatHxpCHTLBG/+urVPcNbr/tAqZx0+MZ4g/hEKpwmIyUN2iUj2LLYJ5FUgw21c4Z4GPHxdeQIDAQAB",
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
