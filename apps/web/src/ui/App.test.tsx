import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App, inviteTokenFromPath } from "./App.js";
import type { Session } from "../vault/session.js";

// Real enrol() drives a Go build's worth of server contract plus an Argon2id
// pass — that is what the e2e journey is for. This test only needs to reach
// App's own onFinish handler, so the vault-layer enrol() is replaced with a
// stub that mimics the one observable side effect App depends on
// (session.open) without doing any crypto or hitting the network. Nothing
// here touches App.tsx's own onFinish body, so it cannot mask a regression in
// it.
vi.mock("../vault/enroll.js", () => ({
  enroll: vi.fn(async (deps: { session: Session }) => {
    deps.session.open({
      tokens: { accessToken: "test-access-token", refreshToken: "test-refresh-token" },
      user: { id: "user-1", email: "a@b.c", name: "Test User", role: "member" },
      userKey: new Uint8Array(32),
      privateKey: new Uint8Array(32),
    });
    return { recoveryCode: "ABCD-EFGH-IJKL-MNOP-QRST", loggedIn: true };
  }),
}));

// Same reasoning as the enroll.js mock above: the auto-lock wiring test
// below only needs App to reach an unlocked state, not to drive a real
// prelogin/login round trip through Argon2id.
vi.mock("../vault/unlock.js", () => ({
  unlock: vi.fn(async (deps: { session: Session }) => {
    deps.session.open({
      tokens: { accessToken: "test-access-token", refreshToken: "test-refresh-token" },
      user: { id: "user-1", email: "a@b.c", name: "Test User", role: "member" },
      userKey: new Uint8Array(32),
      privateKey: new Uint8Array(32),
    });
  }),
}));

describe("inviteTokenFromPath", () => {
  it("extracts the token from a setup link", () => {
    // This is the shape keyhole admin create prints, so it is the shape a real
    // invite arrives in.
    expect(inviteTokenFromPath("/enroll/bgeu3hr9bRZJ6tHrG9iPcrOeInVFkZHiQvM")).toBe(
      "bgeu3hr9bRZJ6tHrG9iPcrOeInVFkZHiQvM",
    );
  });

  it("decodes a percent-encoded token", () => {
    expect(inviteTokenFromPath("/enroll/a%2Fb")).toBe("a/b");
  });

  it("returns null for every other path", () => {
    for (const path of ["/", "/vault", "/enroll", "/enroll/", "/enroll/a/b"]) {
      expect(inviteTokenFromPath(path)).toBeNull();
    }
  });
});

describe("App", () => {
  it("clears the /enroll path from the address bar once enrolment finishes", async () => {
    // Without this, a hard reload re-derives the stale invite token from
    // window.location.pathname (App.tsx's inviteToken is a useMemo over it)
    // and shows the enrolment screen again, even though the invite was
    // already consumed. See App.tsx's onFinish comment.
    const originalPathname = window.location.pathname;
    window.history.replaceState(null, "", "/enroll/test-invite-token");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        // Answers App's post-enrol store.load() sync call. Only /api/sync is
        // ever hit here, because enroll() itself is stubbed above.
        new Response(JSON.stringify({ revision: 0, items: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    try {
      render(<App />);

      await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
      await userEvent.type(screen.getByLabelText(/^master password/i), "correct horse");
      await userEvent.type(screen.getByLabelText(/confirm/i), "correct horse");
      await userEvent.click(screen.getByRole("button", { name: /set master password/i }));

      await waitFor(() => screen.getByText("ABCD-EFGH-IJKL-MNOP-QRST"));

      // Sanity check that the assertion below is meaningful: still on the
      // invite path right up until the user finishes the recovery-code step.
      expect(window.location.pathname).toBe("/enroll/test-invite-token");

      await userEvent.click(screen.getByLabelText(/saved/i));
      await userEvent.click(screen.getByRole("button", { name: /continue/i }));

      await waitFor(() => {
        expect(window.location.pathname).toBe("/");
      });
    } finally {
      vi.unstubAllGlobals();
      window.history.replaceState(null, "", originalPathname);
    }
  });

  it("still shows the recovery code when the post-enrolment sync fails", async () => {
    // Regression for App.tsx's handleEnrol: it used to `await store.load(...)`
    // after enroll() and before returning the outcome. enroll() here succeeds
    // (loggedIn: true, per the module mock above) exactly as it would after a
    // real POST /api/enroll/:token 200, but the store's own /api/sync call —
    // the "post-enrolment sync" — fails. That must not cost the user their
    // recovery code: it is shown once and is unrecoverable afterwards, by
    // anyone, including an administrator (enroll.ts's own doc comment).
    const originalPathname = window.location.pathname;
    window.history.replaceState(null, "", "/enroll/test-invite-token");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network blip");
      }),
    );

    try {
      render(<App />);

      await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
      await userEvent.type(screen.getByLabelText(/^master password/i), "correct horse");
      await userEvent.type(screen.getByLabelText(/confirm/i), "correct horse");
      await userEvent.click(screen.getByRole("button", { name: /set master password/i }));

      // The failed sync must not turn into a rejected onEnrol promise: that
      // would land EnrolScreen back in its catch block, showing a form with
      // the code nowhere to be found instead of the recovery-code screen.
      await waitFor(() => {
        expect(screen.getByText("ABCD-EFGH-IJKL-MNOP-QRST")).toBeInTheDocument();
      });
    } finally {
      vi.unstubAllGlobals();
      window.history.replaceState(null, "", originalPathname);
    }
  });
});

describe("App secure-context guard", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("explains that an insecure origin cannot work, instead of showing the unlock form", () => {
    // jsdom defaults isSecureContext to true; this is the http:// case where
    // the browser never exposed crypto.subtle to begin with.
    vi.stubGlobal("isSecureContext", false);

    render(<App />);

    expect(screen.getByRole("alert")).toHaveTextContent(/https/i);
    expect(screen.queryByLabelText("Master password")).not.toBeInTheDocument();
  });

  it("explains that an insecure origin cannot work when isSecureContext is true but crypto.subtle is missing", () => {
    // This is Mutation B's covering case: an old browser can report a secure
    // context (window.isSecureContext true) while still lacking the
    // SubtleCrypto interface entirely. A guard that only checks
    // isSecureContext would show the unlock form here and every encrypt call
    // would throw "Cannot read properties of undefined" the instant the user
    // submitted a password.
    // `subtle` is a getter inherited from Crypto.prototype in Node's
    // WebCrypto implementation, not an own property of globalThis.crypto --
    // `delete globalThis.crypto.subtle` is a silent no-op against it (the
    // inherited getter is untouched), so shadow it with an own property
    // instead to actually make the lookup return undefined.
    const originalSubtle = globalThis.crypto.subtle;
    Object.defineProperty(globalThis.crypto, "subtle", {
      value: undefined,
      configurable: true,
    });

    try {
      render(<App />);

      expect(screen.getByRole("alert")).toHaveTextContent(/https/i);
      expect(screen.queryByLabelText("Master password")).not.toBeInTheDocument();
    } finally {
      Object.defineProperty(globalThis.crypto, "subtle", {
        value: originalSubtle,
        configurable: true,
        writable: true,
      });
    }
  });

  it("shows the unlock form on a secure origin", () => {
    // The control case: jsdom's defaults (isSecureContext true, crypto.subtle
    // present) must not trip the guard, or every other test in this file
    // that renders <App /> and expects real screens would be dead code.
    render(<App />);

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Master password")).toBeInTheDocument();
  });
});

describe("App auto-lock wiring", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("applies a changed auto-lock setting immediately, not just after the next reload", async () => {
    // Answers store.load's GET /api/sync (App's post-unlock sync) and
    // useSettingsPanel's GET /api/account/sessions -- unlock() itself is
    // mocked above, so nothing else ever reaches fetch.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = typeof input === "string" ? input : input.toString();
        const body = url.includes("/api/account/sessions") ? { sessions: [] } : { revision: 0, items: [] };
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );

    render(<App />);

    await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
    await userEvent.type(screen.getByLabelText("Master password"), "correct horse");
    await userEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

    await userEvent.click(await screen.findByRole("button", { name: "Settings" }));

    // Fake timers only from here: the select change below is what restarts
    // App's auto-lock effect, and it is that *new* timer this test needs to
    // fast-forward.
    vi.useFakeTimers();

    fireEvent.change(screen.getByLabelText("Auto-lock"), { target: { value: "1" } });

    // If `autoLock` ever drops out of App.tsx's effect dependency array
    // (Mutation C), this timer is still the one the effect scheduled on
    // mount under the default 15-minute setting, and one extra minute of
    // idle time changes nothing -- the assertion below is what catches that.
    act(() => {
      vi.advanceTimersByTime(61_000);
    });

    expect(screen.getByRole("heading", { name: /unlock your vault/i })).toBeInTheDocument();
  });
});
