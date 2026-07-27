import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
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
    return { recoveryCode: "ABCD-EFGH-IJKL-MNOP-QRST" };
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
});
