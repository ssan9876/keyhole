import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { ApiError } from "../vault/api.js";
import { createSession, type Session } from "../vault/session.js";
import { fakeApi } from "../vault/test-helpers.js";
import type { VaultState, VaultStore } from "../vault/store.js";
import { completeRecovery, recoverAccount, type RecoverySession } from "../vault/recover.js";
import { unlock } from "../vault/unlock.js";
import { useRecoverScreen } from "./useRecoverScreen.js";

// recoverAccount and completeRecovery each drive real Argon2id passes at 64
// MiB (~0.5s each, and completeRecovery does two), and recover.test.ts already
// covers their crypto and their server contract end to end. This hook's own
// job is narrower -- carrying one session between two calls, signing in
// afterwards, and making sure the recovered keys do not outlive the screen --
// so the vault layer is stubbed here. unlock() is stubbed for the same reason
// App.test.tsx stubs it: it is another full prelogin/login round trip.
vi.mock("../vault/recover.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../vault/recover.js")>()),
  recoverAccount: vi.fn(),
  completeRecovery: vi.fn(),
}));
vi.mock("../vault/unlock.js", () => ({ unlock: vi.fn() }));

const NEW_CODE = "ABCDE-FGHJK-MNPQR-STVWX-YZ234";
/** completeRecovery's answer when the server acknowledged the rotation. */
const ROTATED = { recoveryCode: NEW_CODE, confirmed: true };
/** And when it did not: the request was sent, nothing came back, and the
 *  rotation may or may not have committed. */
const UNCONFIRMED = { recoveryCode: NEW_CODE, confirmed: false };

/** A stand-in for what recoverAccount returns, with a spy for `destroy`. */
function fakeRecoverySession(email = "a@example.com"): RecoverySession & { destroy: ReturnType<typeof vi.fn> } {
  return {
    email,
    userKey: new Uint8Array(32).fill(7),
    privateKey: new Uint8Array(32).fill(8),
    recoveryToken: "rt_token",
    expiresIn: 600,
    destroy: vi.fn(),
  };
}

function fakeStore(): VaultStore {
  const state: VaultState = { revision: 0, items: [], folders: [], collections: [], status: "ready", error: null };
  return {
    getState: () => state,
    subscribe: () => () => undefined,
    load: vi.fn(async () => {}),
    async resync() {},
    upsert() {},
    remove() {},
    clear: vi.fn(),
  };
}

function setup(overrides: { session?: Session; store?: VaultStore; onExit?: () => void } = {}) {
  const session = overrides.session ?? createSession();
  const store = overrides.store ?? fakeStore();
  const onExit = overrides.onExit ?? vi.fn();
  const { result } = renderHook(() =>
    useRecoverScreen({
      api: fakeApi(),
      session,
      store,
      deviceLabel: "Web",
      rememberedEmail: null,
      onExit,
    }),
  );
  return { result, session, store, onExit };
}

describe("useRecoverScreen", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("carries the session recoverAccount opened into completeRecovery", async () => {
    const recovery = fakeRecoverySession();
    vi.mocked(recoverAccount).mockResolvedValue(recovery);
    vi.mocked(completeRecovery).mockResolvedValue(ROTATED);
    const { result } = setup();

    await act(async () => {
      await result.current.onRedeemCode({ email: "a@example.com", recoveryCode: "CODE" });
    });
    const issued = await act(async () => result.current.onSetNewPassword("a new master password"));

    // The one thing only this hook can get wrong: completeRecovery must be
    // handed the *same* session object, because that is where the userKey the
    // rotation re-wraps lives. A second recoverAccount call, or a fresh object,
    // would rotate the account onto a key nothing in the vault is encrypted to.
    expect(recoverAccount).toHaveBeenCalledWith(expect.anything(), {
      email: "a@example.com",
      recoveryCode: "CODE",
    });
    expect(completeRecovery).toHaveBeenCalledWith(
      expect.anything(),
      recovery,
      "a new master password",
    );
    expect(issued.recoveryCode).toBe(NEW_CODE);
  });

  it("signs in with the new master password so the user lands in the vault", async () => {
    const recovery = fakeRecoverySession("recovered@example.com");
    vi.mocked(recoverAccount).mockResolvedValue(recovery);
    vi.mocked(completeRecovery).mockResolvedValue(ROTATED);
    vi.mocked(unlock).mockImplementation(async (deps: { session: Session }) => {
      deps.session.open({
        tokens: { accessToken: "at", refreshToken: "rt" },
        user: { id: "u1", email: "recovered@example.com", name: "R", role: "member" },
        userKey: new Uint8Array(32),
        privateKey: new Uint8Array(32),
      });
    });
    const { result, session, store } = setup();

    await act(async () => {
      await result.current.onRedeemCode({ email: "recovered@example.com", recoveryCode: "CODE" });
    });
    const issued = await act(async () => result.current.onSetNewPassword("a new master password"));

    // The other half of the pair below: reported true only when the sign-in
    // actually opened the session, so the screen's "you will have to sign in
    // again" line stays off the happy path.
    expect(issued.signedIn).toBe(true);
    // POST /api/auth/recover/complete answers 204 and revokes every session,
    // including any this device might have had -- there are no tokens in that
    // response to open a vault with. Without this login the user would be sent
    // back to the unlock screen to type the password they just set.
    expect(unlock).toHaveBeenCalledWith(expect.anything(), {
      email: "recovered@example.com",
      masterPassword: "a new master password",
      deviceLabel: "Web",
    });
    expect(store.load).toHaveBeenCalledOnce();
    expect(session.isUnlocked).toBe(true);
  });

  it("still returns the new recovery code when the post-recovery sign-in fails", async () => {
    const recovery = fakeRecoverySession();
    vi.mocked(recoverAccount).mockResolvedValue(recovery);
    vi.mocked(completeRecovery).mockResolvedValue(ROTATED);
    vi.mocked(unlock).mockRejectedValue(new Error("network blip"));
    const { result, session } = setup();

    await act(async () => {
      await result.current.onRedeemCode({ email: "a@example.com", recoveryCode: "CODE" });
    });

    // The rotation already landed: the account's password and recovery blob
    // are the new ones whatever happens next. A rejected promise here would
    // land the screen in its catch block, showing an error where the only copy
    // of the new code should be -- the same failure App.tsx's handleEnrol had
    // to be fixed for.
    const issued = await act(async () => result.current.onSetNewPassword("a new master password"));

    expect(issued.recoveryCode).toBe(NEW_CODE);
    expect(session.isUnlocked).toBe(false);
    // Swallowing the failure is right; hiding it is not. The screen shows the
    // code and then hands the user to an unlock form asking for the password
    // they set seconds ago, and without this flag it has nothing to say about
    // why.
    expect(issued.signedIn).toBe(false);
  });

  it("keeps the recovery usable when the server refuses to complete it, so it can be retried", async () => {
    const recovery = fakeRecoverySession();
    vi.mocked(recoverAccount).mockResolvedValue(recovery);
    // A 4xx, which is the whole retryable class now: completeRecovery throws
    // only when the server read the request and declined it (or when nothing
    // was sent at all), so a throw here means the account is untouched and the
    // ten-minute token is still worth spending.
    vi.mocked(completeRecovery).mockRejectedValueOnce(
      new ApiError("bad_request", 400, "field \"kdfSalt\" is required", null),
    );
    vi.mocked(completeRecovery).mockResolvedValue(ROTATED);
    const { result } = setup();

    await act(async () => {
      await result.current.onRedeemCode({ email: "a@example.com", recoveryCode: "CODE" });
    });
    await expect(result.current.onSetNewPassword("a new master password")).rejects.toThrow(
      /kdfSalt/,
    );

    // The token is good for ten minutes server-side. Destroying the session on
    // a refused attempt would turn one bad request into a dead end that only a
    // second recovery code could get out of.
    expect(recovery.destroy).not.toHaveBeenCalled();
    const issued = await act(async () => result.current.onSetNewPassword("a new master password"));
    expect(issued.recoveryCode).toBe(NEW_CODE);
  });

  it("hands back an unconfirmed rotation's code instead of retrying it", async () => {
    const recovery = fakeRecoverySession();
    vi.mocked(recoverAccount).mockResolvedValue(recovery);
    vi.mocked(completeRecovery).mockResolvedValue(UNCONFIRMED);
    // The rotation is not known to have failed, so the new password is the one
    // to try -- and if it did land, this succeeds and the user is simply in.
    vi.mocked(unlock).mockRejectedValue(new Error("network blip"));
    const { result } = setup();

    await act(async () => {
      await result.current.onRedeemCode({ email: "a@example.com", recoveryCode: "CODE" });
    });
    const issued = await act(async () => result.current.onSetNewPassword("a new master password"));

    // The code reaches the caller with its uncertainty attached, so the screen
    // can say the change may already have been applied.
    expect(issued.recoveryCode).toBe(NEW_CODE);
    expect(issued.confirmed).toBe(false);
    // And the recovery is over: offering a retry here would send a token the
    // server has very likely already spent, and the 401 that came back would
    // tell the user the recovery failed when it had succeeded.
    expect(recovery.destroy).toHaveBeenCalled();
    await expect(result.current.onSetNewPassword("a new master password")).rejects.toThrow(
      /no recovery in progress/i,
    );
  });

  it("destroys the recovered keys once the rotation has landed", async () => {
    const recovery = fakeRecoverySession();
    vi.mocked(recoverAccount).mockResolvedValue(recovery);
    vi.mocked(completeRecovery).mockResolvedValue(ROTATED);
    vi.mocked(unlock).mockResolvedValue(undefined);
    const { result } = setup();

    await act(async () => {
      await result.current.onRedeemCode({ email: "a@example.com", recoveryCode: "CODE" });
    });
    await act(async () => result.current.onSetNewPassword("a new master password"));

    // src/ui/** cannot import @keyhole/crypto, so destroy() is the only way a
    // screen can clear what recoverAccount handed it. The keys the code opened
    // have no further use the moment the new password is in place.
    expect(recovery.destroy).toHaveBeenCalled();
  });

  it("destroys the recovered keys when the user abandons the screen", async () => {
    const recovery = fakeRecoverySession();
    vi.mocked(recoverAccount).mockResolvedValue(recovery);
    const onExit = vi.fn();
    const { result } = setup({ onExit });

    await act(async () => {
      await result.current.onRedeemCode({ email: "a@example.com", recoveryCode: "CODE" });
    });
    act(() => {
      result.current.onCancel();
    });

    expect(recovery.destroy).toHaveBeenCalledOnce();
    expect(onExit).toHaveBeenCalledOnce();
  });

  it("destroys a still-open recovery when the screen unmounts", async () => {
    const recovery = fakeRecoverySession();
    vi.mocked(recoverAccount).mockResolvedValue(recovery);
    const store = fakeStore();
    const session = createSession();
    const { result, unmount } = renderHook(() =>
      useRecoverScreen({
        api: fakeApi(),
        session,
        store,
        deviceLabel: "Web",
        rememberedEmail: null,
        onExit: vi.fn(),
      }),
    );

    await act(async () => {
      await result.current.onRedeemCode({ email: "a@example.com", recoveryCode: "CODE" });
    });
    // Nothing else holds a reference to these keys: an unmount without this
    // (a reload-free navigation, an error boundary) would leave a userKey and a
    // privateKey live in the heap for the life of the tab.
    unmount();

    expect(recovery.destroy).toHaveBeenCalledOnce();
  });

  it("replaces the keys from an earlier attempt rather than leaking them", async () => {
    const first = fakeRecoverySession();
    const second = fakeRecoverySession();
    vi.mocked(recoverAccount).mockResolvedValueOnce(first);
    vi.mocked(recoverAccount).mockResolvedValueOnce(second);
    const { result } = setup();

    await act(async () => {
      await result.current.onRedeemCode({ email: "a@example.com", recoveryCode: "CODE" });
    });
    // Reachable: a user who mistypes the email gets a refusal, corrects it, and
    // submits again. Overwriting the ref without clearing it first would strand
    // the first attempt's keys with nothing left pointing at them.
    await act(async () => {
      await result.current.onRedeemCode({ email: "b@example.com", recoveryCode: "CODE" });
    });

    expect(first.destroy).toHaveBeenCalledOnce();
    expect(second.destroy).not.toHaveBeenCalled();
  });

  it("refuses to set a password when no code has been redeemed", async () => {
    const { result } = setup();

    // Unreachable from the screen, which only renders the password step after
    // onRedeemCode resolves. It is a hard failure rather than a silent no-op
    // because the alternative is a caller believing a rotation happened.
    await expect(result.current.onSetNewPassword("a new master password")).rejects.toThrow(
      /no recovery in progress/i,
    );
    expect(completeRecovery).not.toHaveBeenCalled();
  });
});
