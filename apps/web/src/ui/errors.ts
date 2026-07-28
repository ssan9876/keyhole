import { ApiError, NetworkError } from "../vault/api.js";

/**
 * Turns a thrown failure into copy a user can act on, per design spec §9: a
 * network blip must never read as a wrong password, and a wrong password
 * must not read as a server fault. `ApiError.message` is already the
 * server's own human-readable explanation (internal/httpapi/errors.go) --
 * codes are for branching, never for display -- so both branches below show
 * it verbatim; only `NetworkError` gets copy of its own, because nothing
 * reached the server to explain itself.
 *
 * Previously copied verbatim into SettingsScreen.tsx and AdminScreen.tsx,
 * with a third, weaker inline form in CollectionsScreen.tsx
 * (`failure instanceof Error ? failure.message : ...`) that produced the
 * same output only because both ApiError and NetworkError happen to extend
 * Error -- a distinction that held by coincidence, not by construction.
 * Extracted here and used by all three screens so design spec §9's
 * requirement is structural: a bare `Error` (or anything else that is not
 * one of these two types) always falls through to `fallback`, never gets
 * shown verbatim.
 */
export function describeFailure(failure: unknown, fallback: string): string {
  if (failure instanceof NetworkError) return failure.message;
  if (failure instanceof ApiError) return failure.message;
  return fallback;
}
