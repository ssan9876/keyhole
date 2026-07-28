import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError, NetworkError } from "../../vault/api.js";
import type { DeviceSession } from "../../vault/account.js";
import type { AutoLockSetting } from "../../vault/autolock.js";
import { SettingsScreen, type SettingsScreenProps } from "./SettingsScreen.js";

const SESSIONS: DeviceSession[] = [
  {
    id: "s1",
    deviceLabel: "This laptop",
    createdAt: "2026-01-01T00:00:00Z",
    lastSeenAt: "2026-07-27T00:00:00Z",
    current: true,
  },
  {
    id: "s2",
    deviceLabel: "Phone",
    createdAt: "2026-02-01T00:00:00Z",
    lastSeenAt: "2026-07-20T00:00:00Z",
    current: false,
  },
];

function baseProps(overrides: Partial<SettingsScreenProps> = {}): SettingsScreenProps {
  return {
    autoLock: 15,
    onAutoLockChange: vi.fn(),
    onChangePassword: vi.fn().mockResolvedValue(undefined),
    sessions: SESSIONS,
    onRevokeSession: vi.fn().mockResolvedValue(undefined),
    onLock: vi.fn(),
    onRegenerateRecoveryCode: vi.fn().mockResolvedValue("ABCDE-FGHJK-MNPQR-STVWX-YZ234"),
    ...overrides,
  };
}

/**
 * `SettingsScreen` is presentational -- `autoLock` and `onAutoLockChange` are
 * owned by the caller, exactly as App.tsx owns them for real. Any test that
 * needs the "never" warning (or anything else gated on `autoLock`) to react
 * to a select change needs a controlled parent, the same way App.tsx and
 * useSettingsPanel are the controlled parent in production -- otherwise the
 * test would just be asserting that the onChange handler fired, not that the
 * screen renders the right thing when the value it's given actually changes.
 */
function ControlledSettingsScreen(
  props: Omit<SettingsScreenProps, "autoLock" | "onAutoLockChange"> & {
    initialAutoLock: AutoLockSetting;
  },
) {
  const { initialAutoLock, ...rest } = props;
  const [autoLock, setAutoLock] = useState<AutoLockSetting>(initialAutoLock);
  return <SettingsScreen {...rest} autoLock={autoLock} onAutoLockChange={setAutoLock} />;
}

async function fillPasswordForm(
  current: string,
  next: string,
  confirm: string,
): Promise<void> {
  await userEvent.type(screen.getByLabelText("Current master password"), current);
  await userEvent.type(screen.getByLabelText("New master password"), next);
  await userEvent.type(screen.getByLabelText("Confirm new master password"), confirm);
  await userEvent.click(screen.getByRole("button", { name: "Change master password" }));
}

describe("SettingsScreen auto-lock", () => {
  it("warns that the vault stays open until the tab or browser closes when set to never", async () => {
    render(<ControlledSettingsScreen {...baseProps()} initialAutoLock={15} />);

    expect(screen.queryByText(/stays unlocked until you close/i)).not.toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Auto-lock"), "never");

    expect(screen.getByText(/stays unlocked until you close/i)).toBeInTheDocument();
  });

  it("passes the numeric setting, not the option's raw string value, to onAutoLockChange", async () => {
    // AutoLockSetting is 1 | 5 | 15 | 30 | 60 | "on-close" | "never" --
    // readAutoLock's `SETTINGS.includes(parsed)` check is a strict-equality
    // membership test, so a caller that forwarded the <option> value
    // unparsed would hand it the string "30" where every other consumer
    // (starting with this very component's own `value={String(autoLock)}`
    // binding) expects the number 30.
    const onAutoLockChange = vi.fn();
    render(<SettingsScreen {...baseProps({ onAutoLockChange })} />);

    await userEvent.selectOptions(screen.getByLabelText("Auto-lock"), "30");

    expect(onAutoLockChange).toHaveBeenCalledWith(30);
  });
});

describe("SettingsScreen master password", () => {
  it("rejects a mismatched confirmation before calling onChangePassword", async () => {
    const onChangePassword = vi.fn();
    render(<SettingsScreen {...baseProps({ onChangePassword })} />);

    await fillPasswordForm("old-password", "new-password-1", "new-password-2");

    expect(screen.getByRole("alert")).toHaveTextContent(/do not match/i);
    expect(onChangePassword).not.toHaveBeenCalled();
  });

  it("tells the user their other devices were signed out after a successful change", async () => {
    const onChangePassword = vi.fn().mockResolvedValue(undefined);
    render(<SettingsScreen {...baseProps({ onChangePassword })} />);

    await fillPasswordForm("old-password", "new-password", "new-password");

    expect(await screen.findByText(/other devices have been signed out/i)).toBeInTheDocument();
    expect(onChangePassword).toHaveBeenCalledWith({
      currentPassword: "old-password",
      newPassword: "new-password",
    });
  });

  it("shows the server's own message for a wrong current password", async () => {
    const onChangePassword = vi
      .fn()
      .mockRejectedValue(new ApiError("unauthorized", 401, "master password is incorrect", null));
    render(<SettingsScreen {...baseProps({ onChangePassword })} />);

    await fillPasswordForm("wrong-password", "new-password", "new-password");

    expect(await screen.findByRole("alert")).toHaveTextContent(/master password is incorrect/i);
  });

  it("reports an unreachable server as a connection problem, never as a password problem", async () => {
    const onChangePassword = vi.fn().mockRejectedValue(new NetworkError(new Error("down")));
    render(<SettingsScreen {...baseProps({ onChangePassword })} />);

    await fillPasswordForm("old-password", "new-password", "new-password");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/could not reach/i);
    expect(alert).not.toHaveTextContent(/password/i);
  });
});

describe("SettingsScreen recovery code", () => {
  it("shows a freshly generated code once, then clears it from state on acknowledgement", async () => {
    const code = "ABCDE-FGHJK-MNPQR-STVWX-YZ234";
    const onRegenerateRecoveryCode = vi.fn().mockResolvedValue(code);
    render(<SettingsScreen {...baseProps({ onRegenerateRecoveryCode })} />);

    await userEvent.click(screen.getByRole("button", { name: "New recovery code" }));
    await userEvent.type(screen.getByLabelText("Master password"), "old-password");
    await userEvent.click(screen.getByRole("button", { name: "Generate new code" }));

    expect(await screen.findByText(code)).toBeInTheDocument();
    expect(onRegenerateRecoveryCode).toHaveBeenCalledWith("old-password");

    await userEvent.click(screen.getByLabelText(/I have saved this/i));
    await userEvent.click(screen.getByRole("button", { name: "Done" }));

    // Not just hidden by CSS or an unmounted subtree -- gone from the DOM,
    // which is what proves it was cleared from this component's own state
    // rather than left sitting there for a future re-render to expose again.
    // The exact bug this guards was found and fixed in EnrolScreen: a parent
    // unmount was relied on instead of clearing state, and re-mounting the
    // same subtree brought the old code straight back.
    expect(screen.queryByText(code)).not.toBeInTheDocument();
  });

  it("reports a wrong password on regeneration without touching the master-password form", async () => {
    const onRegenerateRecoveryCode = vi
      .fn()
      .mockRejectedValue(new ApiError("unauthorized", 401, "master password is incorrect", null));
    render(<SettingsScreen {...baseProps({ onRegenerateRecoveryCode })} />);

    await userEvent.click(screen.getByRole("button", { name: "New recovery code" }));
    await userEvent.type(screen.getByLabelText("Master password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "Generate new code" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/master password is incorrect/i);
    // The master-password section's own alert must not also fire -- there is
    // exactly one alert on the page, the recovery section's.
    expect(screen.getAllByRole("alert")).toHaveLength(1);
  });
});

describe("SettingsScreen sessions", () => {
  it("locks the vault when the current session is revoked", async () => {
    const onLock = vi.fn();
    const onRevokeSession = vi.fn().mockResolvedValue(undefined);
    render(<SettingsScreen {...baseProps({ onLock, onRevokeSession })} />);

    await userEvent.click(screen.getByRole("button", { name: "Sign out this device" }));

    await waitFor(() => expect(onRevokeSession).toHaveBeenCalledWith("s1"));
    expect(onLock).toHaveBeenCalledOnce();
  });

  it("does not lock the vault when a different session is revoked", async () => {
    const onLock = vi.fn();
    const onRevokeSession = vi.fn().mockResolvedValue(undefined);
    render(<SettingsScreen {...baseProps({ onLock, onRevokeSession })} />);

    await userEvent.click(screen.getByRole("button", { name: "Revoke session" }));

    await waitFor(() => expect(onRevokeSession).toHaveBeenCalledWith("s2"));
    expect(onLock).not.toHaveBeenCalled();
  });
});
