import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NetworkError } from "../../vault/api.js";
import { UnlockScreen } from "./UnlockScreen.js";

/**
 * Forces navigator.onLine and returns a restore. jsdom reports onLine via a
 * getter on the Navigator prototype, so shadow it with an own property to make
 * the read return the value we want, then delete the shadow to restore.
 */
function withOnLine(value: boolean): () => void {
  const previous = Object.getOwnPropertyDescriptor(navigator, "onLine");
  Object.defineProperty(navigator, "onLine", { value, configurable: true });
  return () => {
    if (previous) Object.defineProperty(navigator, "onLine", previous);
    else Reflect.deleteProperty(navigator, "onLine");
  };
}

describe("UnlockScreen", () => {
  it("asks for an email when none is remembered", () => {
    render(<UnlockScreen rememberedEmail={null} onUnlock={vi.fn()} onForgotPassword={vi.fn()} />);
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/master password/i)).toBeInTheDocument();
  });

  it("asks only for the password when an email is remembered", () => {
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={vi.fn()} onForgotPassword={vi.fn()} />);
    // The whole benefit of persisting the email is this screen.
    expect(screen.queryByLabelText(/email/i)).not.toBeInTheDocument();
    expect(screen.getByText("a@b.c")).toBeInTheDocument();
  });

  it("shows a wrong-password message that does not blame the network", async () => {
    const onUnlock = vi.fn().mockRejectedValue(new Error("Wrong master password"));
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} onForgotPassword={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/master password/i), "nope");
    await userEvent.click(screen.getByRole("button", { name: /unlock/i }));

    // Design spec 9 requires these to read differently. A user who mistypes a
    // password and is told the server is unreachable will go looking in
    // entirely the wrong place.
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/wrong master password/i);
    });
  });

  it("shows an unreachable-server message that does not blame the password", async () => {
    // Design spec 9 requires a wrong password, an unreachable server, and an
    // expired session to read differently. Only the wrong-password case above
    // was ever asserted; nothing checked what renders for a network failure,
    // so a regression collapsing the two messages into one would have passed
    // silently. The vault layer's own NetworkError (src/vault/api.ts) carries
    // exactly this message, distinct from "Wrong master password".
    const onUnlock = vi.fn().mockRejectedValue(new Error("Could not reach the server"));
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} onForgotPassword={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/master password/i), "correct horse");
    await userEvent.click(screen.getByRole("button", { name: /unlock/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/could not reach the server/i);
    });
    expect(screen.getByRole("alert")).not.toHaveTextContent(/wrong master password/i);
  });

  it("shows an offline message when an unlock attempt fails with a NetworkError, not a wrong-password or server-error one", async () => {
    // The vault layer's own NetworkError comes back when the prelogin request
    // could not reach the server at all. Keyed on the error type, not on
    // navigator.onLine — so it fires even when the browser insists it is online
    // (which it can, over a connection that does not actually reach the server;
    // it is also exactly what Playwright's offline emulation reports). Design
    // spec §9 requires this to read as "reconnect" — never as a wrong password
    // or a server fault, which would send the user looking in the wrong place.
    const restore = withOnLine(true);
    const onUnlock = vi.fn().mockRejectedValue(new NetworkError(new Error("unreachable")));
    try {
      render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} onForgotPassword={vi.fn()} />);
      await userEvent.type(screen.getByLabelText(/master password/i), "correct horse");
      await userEvent.click(screen.getByRole("button", { name: /^unlock$/i }));

      // Asserted on the alert — the attempt's own result.
      await waitFor(() => {
        expect(screen.getByRole("alert")).toHaveTextContent(
          /you're offline\. connect to load your vault\./i,
        );
      });
      const alert = screen.getByRole("alert");
      expect(alert).not.toHaveTextContent(/wrong master password/i);
      // "server" catches both the generic "The server returned an error" and the
      // NetworkError's own "Could not reach the server": offline is neither.
      expect(alert).not.toHaveTextContent(/server/i);
    } finally {
      restore();
    }
  });

  it("says the connection is needed before an attempt is even made when the browser is offline", async () => {
    // The unlock screen can be honest before it spends an Argon2id pass on a
    // request that cannot leave the device: a cold offline load reaches this
    // screen (the service worker serves the shell), and telling the user why
    // the vault will not open is kinder than letting them guess a password
    // against no network.
    const restore = withOnLine(false);
    try {
      render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={vi.fn()} onForgotPassword={vi.fn()} />);
      expect(screen.getByRole("status")).toHaveTextContent(
        /you're offline\. connect to load your vault\./i,
      );
    } finally {
      restore();
    }
  });

  it("shows no offline notice when the browser reports a connection", () => {
    // The control case: the banner must not sit there permanently. jsdom's
    // default navigator.onLine is true, so nothing offline should render.
    const restore = withOnLine(true);
    try {
      render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={vi.fn()} onForgotPassword={vi.fn()} />);
      expect(screen.queryByRole("status")).not.toBeInTheDocument();
      expect(screen.queryByText(/you're offline/i)).not.toBeInTheDocument();
    } finally {
      restore();
    }
  });

  it("offers a way out for a forgotten master password", async () => {
    // The recovery code is only a way back in if the person holding it can
    // find the screen that redeems it, and this is where they are standing
    // when they discover they need it.
    const onForgotPassword = vi.fn();
    render(
      <UnlockScreen rememberedEmail="a@b.c" onUnlock={vi.fn()} onForgotPassword={onForgotPassword} />,
    );

    await userEvent.click(screen.getByRole("button", { name: /forgot your master password/i }));

    expect(onForgotPassword).toHaveBeenCalledOnce();
  });

  it("disables the button while unlocking so one press is one attempt", async () => {
    let release: (() => void) | undefined;
    const onUnlock = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} onForgotPassword={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/master password/i), "pw");
    await userEvent.click(screen.getByRole("button", { name: /unlock/i }));

    // Argon2id takes about a second. Without this, an impatient double-click
    // spends two of the five free login attempts before the rate limiter starts
    // adding delay.
    expect(screen.getByRole("button", { name: /unlocking/i })).toBeDisabled();
    release?.();
    await waitFor(() => expect(onUnlock).toHaveBeenCalledOnce());
  });
});
