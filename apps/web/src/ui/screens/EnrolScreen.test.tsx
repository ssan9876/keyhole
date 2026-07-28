import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EnrolScreen } from "./EnrolScreen.js";

describe("EnrolScreen", () => {
  it("refuses to submit when the confirmation does not match", async () => {
    const onEnrol = vi.fn();
    render(<EnrolScreen inviteToken="tok" onEnrol={onEnrol} onFinish={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
    await userEvent.type(screen.getByLabelText(/^master password/i), "correct horse");
    await userEvent.type(screen.getByLabelText(/confirm/i), "corrent horse");
    await userEvent.click(screen.getByRole("button", { name: /set master password/i }));

    // A typo here is unrecoverable: the vault would be encrypted under a
    // password nobody knows, and the server cannot help by design.
    expect(onEnrol).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(/do not match/i);
  });

  it("shows the recovery code and will not continue until it is acknowledged", async () => {
    const onEnrol = vi.fn().mockResolvedValue({ recoveryCode: "ABCD-EFGH-IJKL" });
    const onFinish = vi.fn();
    render(<EnrolScreen inviteToken="tok" onEnrol={onEnrol} onFinish={onFinish} />);

    await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
    await userEvent.type(screen.getByLabelText(/^master password/i), "correct horse");
    await userEvent.type(screen.getByLabelText(/confirm/i), "correct horse");
    await userEvent.click(screen.getByRole("button", { name: /set master password/i }));

    await waitFor(() => {
      expect(screen.getByText("ABCD-EFGH-IJKL")).toBeInTheDocument();
    });

    // The code cannot be recovered afterwards by anyone. Letting the user click
    // past it is handing them a vault with no second way in, silently.
    const continueButton = screen.getByRole("button", { name: /continue/i });
    expect(continueButton).toBeDisabled();

    await userEvent.click(screen.getByLabelText(/saved/i));
    expect(continueButton).toBeEnabled();
    await userEvent.click(continueButton);
    expect(onFinish).toHaveBeenCalledOnce();
  });

  it("no longer says redemption is unbuilt, and says what redeeming actually does", async () => {
    // This screen used to carry "redeeming this code is not built yet", which
    // was true while POST /api/account/recovery — a rotation for an already-
    // authenticated user — was the only recovery-related endpoint. There is now
    // a redemption path (POST /api/auth/recover/prelogin, /recover,
    // /recover/complete, driven by RecoverScreen), so that sentence has become
    // the lie it was written to avoid.
    const onEnrol = vi.fn().mockResolvedValue({ recoveryCode: "ABCD-EFGH-IJKL" });
    render(<EnrolScreen inviteToken="tok" onEnrol={onEnrol} onFinish={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
    await userEvent.type(screen.getByLabelText(/^master password/i), "correct horse");
    await userEvent.type(screen.getByLabelText(/confirm/i), "correct horse");
    await userEvent.click(screen.getByRole("button", { name: /set master password/i }));

    await waitFor(() => {
      expect(screen.getByText("ABCD-EFGH-IJKL")).toBeInTheDocument();
    });

    expect(screen.queryByText(/not built yet/i)).not.toBeInTheDocument();
    // The two consequences a user has to know before they rely on it, both
    // verified against internal/store/recovery.go's CompleteRecovery: every
    // session is revoked, and the userKey inside the blob is unchanged, so no
    // item is re-encrypted or lost.
    expect(screen.getByText(/signs out every other device/i)).toBeInTheDocument();
    expect(screen.getByText(/exactly as it is/i)).toBeInTheDocument();
  });

  it("never shows the recovery code again after it is acknowledged", async () => {
    const onEnrol = vi.fn().mockResolvedValue({ recoveryCode: "ABCD-EFGH-IJKL" });
    render(<EnrolScreen inviteToken="tok" onEnrol={onEnrol} onFinish={vi.fn()} />);

    await userEvent.type(screen.getByLabelText(/email/i), "a@b.c");
    await userEvent.type(screen.getByLabelText(/^master password/i), "pw");
    await userEvent.type(screen.getByLabelText(/confirm/i), "pw");
    await userEvent.click(screen.getByRole("button", { name: /set master password/i }));
    await waitFor(() => screen.getByText("ABCD-EFGH-IJKL"));

    await userEvent.click(screen.getByLabelText(/saved/i));
    await userEvent.click(screen.getByRole("button", { name: /continue/i }));

    expect(screen.queryByText("ABCD-EFGH-IJKL")).not.toBeInTheDocument();
  });
});
