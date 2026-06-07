import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "node:path";

// The SPA is embedded into the `vault-console` binary (rust-embed of `dist/`). In dev it
// proxies `/api` to a locally-running console backend (default :8203). Override via
// VITE_API_PROXY.
export default defineConfig({
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
});
