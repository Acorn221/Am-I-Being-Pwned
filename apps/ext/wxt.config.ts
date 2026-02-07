import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "wxt";

// See https://wxt.dev/api/config.html
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    permissions: ["management"],
  },
  vite: () => ({
    plugins: [tailwindcss()],
  }),
  runner: {
    disabled: true,
  },
});
