import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ApiClient } from "../vault/api.js";
import type { VaultState, VaultStore } from "../vault/store.js";
import { fakeApi, openSession } from "../vault/test-helpers.js";
import { AUTO_LOCK_STORAGE_KEY, DEFAULT_AUTO_LOCK } from "../vault/autolock.js";
import { changeMasterPassword, regenerateRecoveryCode } from "../vault/account.js";
import { useSettingsPanel } from "./useSettingsPanel.js";

// changeMasterPassword and regenerateRecoveryCode each drive a real Argon2id
// pass (account.test.ts already covers their crypto end to end, at ~0.5s a
// call). This hook's own job is narrower -- supplying the signed-in user's
// email and returning whatever the vault layer produced -- so those two are
// stubbed here; listSessions and revokeSession stay real, since they are
// plain fetch wrappers with nothing to stub.
vi.mock("../vault/account.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../vault/account.js")>();
  return {
    ...actual,
    changeMasterPassword: vi.fn().mockResolvedValue(undefined),
    regenerateRecoveryCode: vi.fn().mockResolvedValue("ABCDE-FGHJK-MNPQR-STVWX-YZ234"),
  };
});

function fakeStore(): VaultStore {
  const state: VaultState = { revision: 0, items: [], collections: [], status: "ready", error: null };
  return {
    getState: () => state,
    subscribe: () => () => undefined,
    async load() {},
    async resync() {},
    upsert() {},
    remove() {},
    clear: vi.fn(),
  };
}

describe("useSettingsPanel", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  it("does not fetch the session list until the Settings tab is active", async () => {
    const session = openSession();
    const store = fakeStore();
    let sessionsCalls = 0;
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/account/sessions") {
          sessionsCalls += 1;
          return {
            sessions: [
              { id: "s1", deviceLabel: "Laptop", createdAt: "x", lastSeenAt: "y", current: true },
            ],
          };
        }
        throw new Error(`unexpected GET ${path}`);
      },
    });

    const { result, rerender } = renderHook(
      ({ active }: { active: boolean }) =>
        useSettingsPanel({ api, session, store, active, autoLock: DEFAULT_AUTO_LOCK, onAutoLockChange: vi.fn() }),
      { initialProps: { active: false } },
    );

    expect(sessionsCalls).toBe(0);
    expect(result.current.sessions).toEqual([]);

    rerender({ active: true });

    await waitFor(() => expect(result.current.sessions).toHaveLength(1));
    expect(sessionsCalls).toBe(1);
  });

  it("supplies the signed-in user's email to changeMasterPassword", async () => {
    const session = openSession(); // "a@example.com", per test-helpers.ts
    const store = fakeStore();
    const { result } = renderHook(() =>
      useSettingsPanel({
        api: fakeApi(),
        session,
        store,
        active: false,
        autoLock: DEFAULT_AUTO_LOCK,
        onAutoLockChange: vi.fn(),
      }),
    );

    await act(async () => {
      await result.current.onChangePassword({ currentPassword: "old-password", newPassword: "new-password" });
    });

    expect(changeMasterPassword).toHaveBeenCalledWith(expect.anything(), {
      email: "a@example.com",
      currentPassword: "old-password",
      newPassword: "new-password",
    });
  });

  it("supplies the signed-in user's email to regenerateRecoveryCode", async () => {
    const session = openSession();
    const store = fakeStore();
    const { result } = renderHook(() =>
      useSettingsPanel({
        api: fakeApi(),
        session,
        store,
        active: false,
        autoLock: DEFAULT_AUTO_LOCK,
        onAutoLockChange: vi.fn(),
      }),
    );

    const code = await act(async () => result.current.onRegenerateRecoveryCode("old-password"));

    expect(regenerateRecoveryCode).toHaveBeenCalledWith(expect.anything(), {
      email: "a@example.com",
      currentPassword: "old-password",
    });
    expect(code).toBe("ABCDE-FGHJK-MNPQR-STVWX-YZ234");
  });

  it("drops a revoked session from its own list rather than re-fetching all of them", async () => {
    const session = openSession();
    const store = fakeStore();
    const delCalls: string[] = [];
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/account/sessions") {
          return {
            sessions: [
              { id: "s1", deviceLabel: "Laptop", createdAt: "x", lastSeenAt: "y", current: true },
              { id: "s2", deviceLabel: "Phone", createdAt: "x", lastSeenAt: "y", current: false },
            ],
          };
        }
        throw new Error(`unexpected GET ${path}`);
      },
      del: async (path) => {
        delCalls.push(path);
        return null;
      },
    });

    const { result } = renderHook(() =>
      useSettingsPanel({ api, session, store, active: true, autoLock: DEFAULT_AUTO_LOCK, onAutoLockChange: vi.fn() }),
    );

    await waitFor(() => expect(result.current.sessions).toHaveLength(2));

    await act(async () => {
      await result.current.onRevokeSession("s2");
    });

    expect(delCalls).toEqual(["/api/account/sessions/s2"]);
    expect(result.current.sessions.map((s) => s.id)).toEqual(["s1"]);
  });

  it("persists a changed auto-lock setting to localStorage and forwards it to the caller's setter", () => {
    const session = openSession();
    const store = fakeStore();
    const onAutoLockChange = vi.fn();
    const { result } = renderHook(() =>
      useSettingsPanel({
        api: fakeApi(),
        session,
        store,
        active: false,
        autoLock: DEFAULT_AUTO_LOCK,
        onAutoLockChange,
      }),
    );

    act(() => {
      result.current.onAutoLockChange(30);
    });

    // Written immediately, not left for the caller to persist -- a reload
    // before any other save must not revert the choice.
    expect(localStorage.getItem(AUTO_LOCK_STORAGE_KEY)).toBe("30");
    expect(onAutoLockChange).toHaveBeenCalledWith(30);
  });

  it("clears the store and locks the session when onLock is called", () => {
    const session = openSession();
    const store = fakeStore();
    const { result } = renderHook(() =>
      useSettingsPanel({
        api: fakeApi(),
        session,
        store,
        active: false,
        autoLock: DEFAULT_AUTO_LOCK,
        onAutoLockChange: vi.fn(),
      }),
    );

    result.current.onLock();

    expect(store.clear).toHaveBeenCalledOnce();
    expect(session.isUnlocked).toBe(false);
  });
});
