/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import { federation } from "@module-federation/vite";
import path from "node:path";

// Dual-mode build (M5). Standalone: `pnpm build` → the SPA embedded in the
// vault-console binary (rust-embed of `dist/`), own login + full chrome. Remote:
// `VITE_FEDERATED=1 VITE_BASE=/apps/vesta/ pnpm build` → additionally emits
// `remoteEntry.js` exposing `./Module`, loaded chrome-less by the beast-shell
// host at runtime. Both are served by THIS service under `/apps/vesta/` (the MF
// entry + chunks are just more static assets). See
// beast/docs/contracts/09-module-federation.md.
const FEDERATED = process.env.VITE_FEDERATED === "1";

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
  plugins: [
    react(),
    ...(FEDERATED
      ? [
          federation({
            name: "vesta",
            filename: "remoteEntry.js",
            exposes: { "./Module": "./src/federation/module.tsx" },
            shared: {
              react: { singleton: true, requiredVersion: "^19.0.0" },
              "react-dom": { singleton: true, requiredVersion: "^19.0.0" },
            },
          }),
        ]
      : []),
  ],
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
  // module-federation needs esnext (top-level await in the generated runtime).
  build: { outDir: "dist", sourcemap: true, target: FEDERATED ? "esnext" : "modules" },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
