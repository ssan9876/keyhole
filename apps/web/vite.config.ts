import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Go server owns /api. Proxying rather than enabling CORS keeps the browser
// on one origin, which is what production looks like behind the tunnel — so the
// dev setup cannot pass while a same-origin assumption is broken.
export default defineConfig({
  plugins: [react()],
  build: {
    // Straight into the Go embed directory: a copy step is one more thing to
    // forget, and forgetting it ships a binary serving the placeholder.
    outDir: "../../internal/webui/dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8477",
        changeOrigin: false,
      },
    },
  },
});
