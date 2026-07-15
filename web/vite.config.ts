/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "node:path";

// The SPA is embedded into the `vault-console` binary (rust-embed of `dist/`). In dev it
// proxies `/api` to a locally-running console backend (default :8203). Override via
// VITE_API_PROXY.
export default defineConfig({
  // Served under a path prefix behind the Beast/Kalista gateway
  // (`VITE_BASE=/apps/vesta/`); defaults to "/" for the standalone
  // vault-console binary so existing behavior is unchanged. Router basename and
  // the API client base derive from `import.meta.env.BASE_URL` — never hardcode
  // the prefix. See beast/docs/contracts/03-ui-shell.md.
  base: process.env.VITE_BASE ?? "/",
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  server: {
    port: 5273,
    proxy: {
      "/api": {
        target: process.env.VITE_API_PROXY ?? "http://127.0.0.1:8203",
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: { outDir: "dist", sourcemap: true },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
