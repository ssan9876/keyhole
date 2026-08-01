// The one line in this module: it exists so that src/ui/** never has a reason
// to import @keyhole/crypto directly.
//
// eslint.config.js bans `@keyhole/crypto` from src/ui/** with no-restricted-
// imports — a mechanised form of design spec 6.3's "decrypted keys in memory
// only" gate. That rule fires on type-only imports too, not just value
// imports, so a UI file that writes `import type { LoginItem } from
// "@keyhole/crypto"` is rejected exactly like one that imports a function from
// it. Re-exporting the plaintext shapes here gives the UI layer the types it
// needs to render a form without ever naming the crypto package itself.
export type { ItemPlaintext, LoginItem, NoteItem } from "@keyhole/crypto";
