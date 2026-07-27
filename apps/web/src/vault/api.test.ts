import { describe, expect, it, vi } from "vitest";
import { ApiError, NetworkError, createApiClient } from "./api.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function clientWith(fetchImpl: typeof fetch, token: string | null = "tok") {
  return createApiClient({
    getAccessToken: () => token,
    onUnauthorized: async () => false,
    fetchImpl,
  });
}

describe("createApiClient", () => {
  it("sends the bearer token and parses a successful body", async () => {
    const fetchImpl = vi.fn(async (_url, init) => {
      expect((init?.headers as Record<string, string>).Authorization).toBe(
        "Bearer tok",
      );
      return jsonResponse(200, { revision: 7, items: [] });
    }) as unknown as typeof fetch;

    const api = clientWith(fetchImpl);
    await expect(api.get<{ revision: number }>("/api/sync")).resolves.toEqual({
      revision: 7,
      items: [],
    });
  });

  it("sends no Authorization header when there is no token", async () => {
    // Prelogin and enrolment are unauthenticated. Sending "Bearer null" would
    // be rejected as a malformed credential rather than treated as absent.
    const fetchImpl = vi.fn(async (_url, init) => {
      expect((init?.headers as Record<string, string>).Authorization).toBeUndefined();
      return jsonResponse(200, {});
    }) as unknown as typeof fetch;

    await clientWith(fetchImpl, null).post("/api/auth/prelogin", { email: "a@b.c" });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("turns an error envelope into an ApiError carrying the code", async () => {
    const fetchImpl = (async () =>
      jsonResponse(404, {
        error: { code: "not_found", message: "not found" },
      })) as unknown as typeof fetch;

    const error = await clientWith(fetchImpl)
      .get("/api/items/abc")
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    // The UI branches on code, never message: errors.go states codes are
    // stable and messages are for humans and may change.
    expect((error as ApiError).code).toBe("not_found");
    expect((error as ApiError).status).toBe(404);
  });

  it("keeps the whole body on a conflict so the winning item survives", async () => {
    const winner = { id: "abc", ciphertext: "winner", revision: 9 };
    const fetchImpl = (async () =>
      jsonResponse(409, {
        error: { code: "conflict", message: "changed" },
        item: winner,
      })) as unknown as typeof fetch;

    const error = (await clientWith(fetchImpl)
      .put("/api/items/abc", {})
      .catch((e: unknown) => e)) as ApiError;

    // Without the sibling `item` the client has nothing to reconcile against
    // and its only option is to discard one of the two edits.
    expect(error.code).toBe("conflict");
    expect((error.body as { item: unknown }).item).toEqual(winner);
  });

  it("reports an unreachable server as a NetworkError, not an auth failure", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;

    // Design spec 9: a network blip must never read as a wrong password.
    await expect(clientWith(fetchImpl).get("/api/sync")).rejects.toBeInstanceOf(
      NetworkError,
    );
  });

  it("retries once after a successful refresh, and only once", async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls += 1;
      if (calls === 1) {
        return jsonResponse(401, {
          error: { code: "unauthorized", message: "nope" },
        });
      }
      return jsonResponse(200, { ok: true });
    }) as unknown as typeof fetch;

    const onUnauthorized = vi.fn(async () => true);
    const api = createApiClient({
      getAccessToken: () => "tok",
      onUnauthorized,
      fetchImpl,
    });

    await expect(api.get<{ ok: boolean }>("/api/sync")).resolves.toEqual({ ok: true });
    expect(calls).toBe(2);
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("does not loop when the refresh itself fails", async () => {
    // A refresh token is single-use server-side (RotateSession replaces the
    // hash), so retrying in a loop burns the session and produces a cascade.
    let calls = 0;
    const fetchImpl = (async () => {
      calls += 1;
      return jsonResponse(401, {
        error: { code: "unauthorized", message: "nope" },
      });
    }) as unknown as typeof fetch;

    const api = createApiClient({
      getAccessToken: () => "tok",
      onUnauthorized: async () => false,
      fetchImpl,
    });

    await expect(api.get("/api/sync")).rejects.toBeInstanceOf(ApiError);
    expect(calls).toBe(1);
  });

  it("treats a 204 as an empty success rather than a parse failure", async () => {
    const fetchImpl = (async () =>
      new Response(null, { status: 204 })) as unknown as typeof fetch;
    await expect(clientWith(fetchImpl).del("/api/items/abc")).resolves.toBeNull();
  });
});
