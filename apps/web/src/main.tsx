import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./ui/App.js";
import { registerServiceWorker } from "./sw/register.js";
import "./ui/tokens.css";

const root = document.getElementById("root");
if (root === null) throw new Error("No #root element");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

// Production only, and self-guarded (see registerServiceWorker): dev and the
// vitest run never reach navigator.serviceWorker.register, so their behaviour is
// unchanged. A failure to register is logged and swallowed there — the app runs
// without the service worker.
registerServiceWorker();
