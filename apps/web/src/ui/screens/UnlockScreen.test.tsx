import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { UnlockScreen } from "./UnlockScreen.js";

describe("UnlockScreen", () => {
  it("asks for an email when none is remembered", () => {
    render(<UnlockScreen rememberedEmail={null} onUnlock={vi.fn()} />);
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/master password/i)).toBeInTheDocument();
  });

  it("asks only for the password when an email is remembered", () => {
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={vi.fn()} />);
    // The whole benefit of persisting the email is this screen.
    expect(screen.queryByLabelText(/email/i)).not.toBeInTheDocument();
    expect(screen.getByText("a@b.c")).toBeInTheDocument();
  });

  it("shows a wrong-password message that does not blame the network", async () => {
    const onUnlock = vi.fn().mockRejectedValue(new Error("Wrong master password"));
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} />);

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
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} />);

    await userEvent.type(screen.getByLabelText(/master password/i), "correct horse");
    await userEvent.click(screen.getByRole("button", { name: /unlock/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/could not reach the server/i);
    });
    expect(screen.getByRole("alert")).not.toHaveTextContent(/wrong master password/i);
  });

  it("disables the button while unlocking so one press is one attempt", async () => {
    let release: (() => void) | undefined;
    const onUnlock = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    render(<UnlockScreen rememberedEmail="a@b.c" onUnlock={onUnlock} />);

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
