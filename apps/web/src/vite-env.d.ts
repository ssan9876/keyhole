/// <reference types="vite/client" />

// Pulls in Vite's ambient types for `import.meta.env` (PROD, DEV, MODE, …). The
// web tsconfig sets an explicit `types` array, which suppresses automatic
// inclusion of ambient packages; this triple-slash reference re-adds exactly
// this one, so registerServiceWorker's `import.meta.env.PROD` guard typechecks.
