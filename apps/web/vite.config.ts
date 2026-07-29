import { fileURLToPath } from "node:url";
import { build, defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { buildPrecacheList } from "./src/sw/precache";

// Emits the service worker as a build artifact, and only as a build artifact.
//
// The precache list is derived from the REAL emitted bundle (generateBundle's
// `bundle` keys), never hand-maintained — a hand-written list goes stale on the
// first rebuild and precaches a filename that now 404s, failing install. The SW
// is then compiled from src/sw/sw.ts in a nested build with that list injected,
// so the shipped sw.js contains the same route/handler code the unit tests
// exercise.
//
// `apply: "build"` plus using only build-phase hooks means dev (`vite`) and the
// vitest run (which loads vitest.config.ts, not this plugin) never touch the
// SW: a dev/test session is byte-for-byte what it was before this existed.
function swPrecachePlugin(): Plugin {
  let precacheList: string[] = [];
  let outDir = "";
  return {
    name: "keyhole-sw-precache",
    apply: "build",
    configResolved(config) {
      outDir = config.build.outDir;
    },
    generateBundle(_options, bundle) {
      precacheList = buildPrecacheList(Object.keys(bundle));
    },
    async closeBundle() {
      await build({
        configFile: false,
        logLevel: "warn",
        // Replaced verbatim in sw.ts; JSON.stringify so it injects an array
        // literal, per Vite's define contract.
        define: { __PRECACHE__: JSON.stringify(precacheList) },
        build: {
          outDir,
          // The main build already wrote index.html and the assets here; do not
          // wipe them.
          emptyOutDir: false,
          lib: {
            entry: fileURLToPath(new URL("./src/sw/sw.ts", import.meta.url)),
            // A classic self-contained worker script: one file, no imports to
            // resolve at runtime.
            formats: ["iife"],
            name: "keyholeServiceWorker",
            fileName: () => "sw.js",
          },
        },
      });
    },
  };
}

// The Go server owns /api. Proxying rather than enabling CORS keeps the browser
// on one origin, which is what production looks like behind the tunnel — so the
// dev setup cannot pass while a same-origin assumption is broken.
export default defineConfig({
  plugins: [react(), swPrecachePlugin()],
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
