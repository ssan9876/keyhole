import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError, NetworkError } from "../../vault/api.js";
import { WrongRecoveryCodeError } from "../../vault/recover.js";
import { RecoverScreen, type RecoverScreenProps } from "./RecoverScreen.js";

/**
 * Every label rendered by this screen, per step:
 *
 *   step 1: "Email", "Recovery code"
 *   step 2: "New master password", "Confirm new master password"
 *   step 3: "I have saved this code somewhere safe" (the acknowledgement)
 *
 * So `getByLabelText(/code/i)` matches two of them and `/password/i` matches
 * two more. Every query below uses an exact string (Testing Library matches a
 * string against the whole normalized label, not a substring) for exactly that
 * reason -- an ambiguous query throws, and a screen that renamed a field would
 * be caught by the query it belongs to rather than by whichever one happened to
 * match first.
 */
const NEW_CODE = "ABCDE-FGHJK-MNPQR-STVWX-YZ234";

function renderScreen(overrides: Partial<RecoverScreenProps> = {}): RecoverScreenProps {
  const props: RecoverScreenProps = {
    rememberedEmail: null,
    onRedeemCode: vi.fn().mockResolvedValue(undefined),
    onSetNewPassword: vi
      .fn()
      .mockResolvedValue({ recoveryCode: NEW_CODE, confirmed: true, signedIn: true }),
    onFinish: vi.fn(),
    onCancel: vi.fn(),
    ...overrides,
  };
  render(<RecoverScreen {...props} />);
  return props;
}

/** Step 1: email + code, submitted. */
async function submitCode(): Promise<void> {
  await userEvent.type(screen.getByLabelText("Email"), "a@b.c");
  await userEvent.type(screen.getByLabelText("Recovery code"), "ABCDE-FGHJK-MNPQR-STVWX-YZ234");
  await userEvent.click(screen.getByRole("button", { name: "Continue" }));
}

/** Step 2: a new master password, twice, submitted. */
async function submitNewPassword(password: string, confirmation = password): Promise<void> {
  await userEvent.type(screen.getByLabelText("New master password"), password);
  await userEvent.type(screen.getByLabelText("Confirm new master password"), confirmation);
  await userEvent.click(screen.getByRole("button", { name: "Set new master password" }));
}

describe("RecoverScreen", () => {
  it("says up front that recovery replaces the master password and signs out every other device", () => {
    renderScreen();

    // Both consequences are irreversible and neither is guessable from a form
    // asking for a code. store.CompleteRecovery revokes every session with an
    // empty keepSessionID (internal/store/account.go's writePasswordCredential),
    // so a user who does this from a borrowed laptop signs out their phone.
    expect(screen.getByText(/replaces your master password/i)).toBeInTheDocument();
    expect(screen.getByText(/signs out every other device/i)).toBeInTheDocument();
  });

  it("says that a refusal cannot be told apart from an account with no recovery code", () => {
    renderScreen();

    // handleRecover answers an unknown address, a wrong code, a disabled
    // account and a pre-auth-hash blob with one message, one code and one
    // status (internal/httpapi/recover.go's recoveryRefused). A user staring
    // at that refusal deserves to know it is deliberate rather than a bug.
    expect(screen.getByText(/answered identically/i)).toBeInTheDocument();
  });

  it("prefills the remembered email but still lets it be changed", async () => {
    renderScreen({ rememberedEmail: "remembered@example.com" });

    // Unlike UnlockScreen, which replaces the field with static text: recovery
    // is the screen most likely to be reached from a device that is not the
    // one whose localStorage remembered anything.
    const email = screen.getByLabelText("Email");
    expect(email).toHaveValue("remembered@example.com");
    await userEvent.clear(email);
    await userEvent.type(email, "other@example.com");
    expect(email).toHaveValue("other@example.com");
  });

  it("reports a wrong code as a wrong code, and stays on the code step", async () => {
    const props = renderScreen({
      onRedeemCode: vi.fn().mockRejectedValue(new WrongRecoveryCodeError()),
    });

    await submitCode();

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/did not match an account/i);
    });
    expect(screen.getByRole("alert")).not.toHaveTextContent(/reach the server/i);
    // A refused code must not advance the user to a password form that cannot
    // possibly be submitted -- there is no recovery session behind it.
    expect(screen.queryByLabelText("New master password")).not.toBeInTheDocument();
    expect(props.onSetNewPassword).not.toHaveBeenCalled();
  });

  it("reports an unreachable server without mentioning the code or a password", async () => {
    renderScreen({
      onRedeemCode: vi.fn().mockRejectedValue(new NetworkError(new Error("connect ECONNREFUSED"))),
    });

    await submitCode();

    // Design spec 9: a network blip must never read as a wrong code. Someone
    // told their code is wrong will go and hunt for the piece of paper; someone
    // told the server is unreachable will check their connection.
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/could not reach the server/i);
    });
    expect(screen.getByRole("alert")).not.toHaveTextContent(/code/i);
    expect(screen.getByRole("alert")).not.toHaveTextContent(/password/i);
  });

  it("shows a server fault in the server's own words rather than as a wrong code", async () => {
    renderScreen({
      onRedeemCode: vi
        .fn()
        .mockRejectedValue(new ApiError("internal", 500, "could not process the request", null)),
    });

    await submitCode();

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/could not process the request/i);
    });
    expect(screen.getByRole("alert")).not.toHaveTextContent(/did not match an account/i);
  });

  it("refuses a mismatched confirmation before paying for a key derivation", async () => {
    const props = renderScreen();

    await submitCode();
    await waitFor(() => expect(screen.getByLabelText("New master password")).toBeInTheDocument());
    await submitNewPassword("correct horse battery staple", "correct hoarse battery staple");

    // completeRecovery derives two Argon2id hashes at ~0.5s each by design.
    // Making someone wait out both to be told they mistyped the confirmation
    // is gratuitous, and this assertion is what keeps the check ahead of them.
    expect(props.onSetNewPassword).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(/do not match/i);
  });

  it("shows the new recovery code and will not continue until it is acknowledged", async () => {
    const props = renderScreen();

    await submitCode();
    await waitFor(() => expect(screen.getByLabelText("New master password")).toBeInTheDocument());
    await submitNewPassword("correct horse battery staple");

    await waitFor(() => expect(screen.getByText(NEW_CODE)).toBeInTheDocument());
    expect(props.onSetNewPassword).toHaveBeenCalledWith("correct horse battery staple");

    const continueButton = screen.getByRole("button", { name: "Continue to my vault" });
    expect(continueButton).toBeDisabled();
    await userEvent.click(screen.getByLabelText(/saved/i));
    expect(continueButton).toBeEnabled();
    await userEvent.click(continueButton);
    expect(props.onFinish).toHaveBeenCalledOnce();
  });

  it("says the change may already have been applied when the server never answered", async () => {
    renderScreen({
      onSetNewPassword: vi
        .fn()
        .mockResolvedValue({ recoveryCode: NEW_CODE, confirmed: false, signedIn: false }),
    });

    await submitCode();
    await waitFor(() => expect(screen.getByLabelText("New master password")).toBeInTheDocument());
    await submitNewPassword("correct horse battery staple");

    // The code is the point. completeRecovery resolves this way only after the
    // request was sent and no answer came back, which means the rotation may
    // already have committed -- and if it has, this string is the account's
    // only second way in and exists nowhere else.
    await waitFor(() => expect(screen.getByText(NEW_CODE)).toBeInTheDocument());
    const notice = screen.getByText(/may already have been applied/i);
    // A live region, not a paragraph the eye has to find: the screen has just
    // swapped under a user who pressed a button expecting either success or an
    // error, and this is neither.
    expect(notice).toHaveAttribute("role", "status");
    expect(notice).toHaveTextContent(/new master password/i);
    // And the certainty the confirmed path states must not be stated here: the
    // old code may well be the one that still works.
    expect(screen.queryByText(/your old code no longer works/i)).not.toBeInTheDocument();
  });

  it("states plainly that the old code is dead once the server has confirmed", async () => {
    renderScreen();

    await submitCode();
    await waitFor(() => expect(screen.getByLabelText("New master password")).toBeInTheDocument());
    await submitNewPassword("correct horse battery staple");

    // The other half of the pair. Without this assertion the screen could show
    // the hedged copy unconditionally and the test above would still pass,
    // leaving every successful recovery reading like a failure.
    await waitFor(() => expect(screen.getByText(NEW_CODE)).toBeInTheDocument());
    expect(screen.getByText(/your old code no longer works/i)).toBeInTheDocument();
    expect(screen.queryByText(/may already have been applied/i)).not.toBeInTheDocument();
  });

  it("explains why a sign-in is being asked for right after a successful recovery", async () => {
    renderScreen({
      onSetNewPassword: vi
        .fn()
        .mockResolvedValue({ recoveryCode: NEW_CODE, confirmed: true, signedIn: false }),
    });

    await submitCode();
    await waitFor(() => expect(screen.getByLabelText("New master password")).toBeInTheDocument());
    await submitNewPassword("correct horse battery staple");

    await waitFor(() => expect(screen.getByText(NEW_CODE)).toBeInTheDocument());
    // The controller swallows a failed post-recovery sign-in on purpose, so
    // that the code -- shown once, unrecoverable afterwards by anyone -- still
    // reaches the user. Unexplained, the unlock form that follows reads as the
    // recovery having failed, which is the one conclusion that is wrong.
    const notice = screen.getByText(/could not sign in/i);
    expect(notice).toHaveAttribute("role", "status");
    expect(notice).toHaveTextContent(/recovery worked/i);
    expect(notice).toHaveTextContent(/new password/i);
  });

  it("says nothing about signing in again when the sign-in worked", async () => {
    renderScreen();

    await submitCode();
    await waitFor(() => expect(screen.getByLabelText("New master password")).toBeInTheDocument());
    await submitNewPassword("correct horse battery staple");

    // Without this, the notice could render unconditionally and the test above
    // would still pass -- telling every recovered user they must sign in again
    // as they are being dropped straight into their unlocked vault.
    await waitFor(() => expect(screen.getByText(NEW_CODE)).toBeInTheDocument());
    expect(screen.queryByText(/could not sign in/i)).not.toBeInTheDocument();
  });

  it("clears the new recovery code from its own state on acknowledgement", async () => {
    // onFinish is a no-op here, so this component stays mounted: the code
    // disappearing is this screen clearing its own state, not a parent
    // unmounting it. EnrolScreen shipped that exact bug once already.
    renderScreen();

    await submitCode();
    await waitFor(() => expect(screen.getByLabelText("New master password")).toBeInTheDocument());
    await submitNewPassword("correct horse battery staple");
    await waitFor(() => expect(screen.getByText(NEW_CODE)).toBeInTheDocument());

    await userEvent.click(screen.getByLabelText(/saved/i));
    await userEvent.click(screen.getByRole("button", { name: "Continue to my vault" }));

    expect(screen.queryByText(NEW_CODE)).not.toBeInTheDocument();
  });

  it("leaves without redeeming anything when the user goes back to unlocking", async () => {
    const props = renderScreen();

    await userEvent.click(screen.getByRole("button", { name: "Back to unlocking" }));

    expect(props.onCancel).toHaveBeenCalledOnce();
    expect(props.onRedeemCode).not.toHaveBeenCalled();
  });

  it("disables the submit button while the code is being checked", async () => {
    let release: (() => void) | undefined;
    renderScreen({
      onRedeemCode: vi.fn(
        () =>
          new Promise<void>((resolve) => {
            release = resolve;
          }),
      ),
    });

    await userEvent.type(screen.getByLabelText("Email"), "a@b.c");
    await userEvent.type(screen.getByLabelText("Recovery code"), NEW_CODE);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    // One press is one attempt: the redemption endpoint shares its rate-limit
    // budget with login (internal/httpapi/recover.go), so a double-click spends
    // two of the five free attempts belonging to someone who has already lost
    // their password today.
    expect(screen.getByRole("button", { name: /checking/i })).toBeDisabled();
    release?.();
    await waitFor(() => expect(screen.getByLabelText("New master password")).toBeInTheDocument());
  });
});
