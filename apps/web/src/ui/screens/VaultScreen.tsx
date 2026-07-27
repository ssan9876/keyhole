// apps/web/src/ui/screens/VaultScreen.tsx — replaced in Task 8
import type { ApiClient } from "../../vault/api.js";
import type { Session } from "../../vault/session.js";
import type { VaultStore } from "../../vault/store.js";

export function VaultScreen(_props: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
}) {
  return <main>Vault</main>;
}
