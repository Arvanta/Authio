import { defineConfig } from "vite";

// Tauri expects a fixed dev port and a relative dist path for the frontendDist bundle.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    target: "es2021",
    minify: "esbuild",
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
});
