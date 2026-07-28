import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Confirm } from "./Confirm.js";

describe("Confirm", () => {
  it("moves focus onto the dialog itself when it opens", () => {
    render(
      <Confirm title="Remove?" body="Body text" confirmLabel="Remove" onConfirm={vi.fn()} onCancel={vi.fn()} />,
    );
    expect(screen.getByRole("alertdialog")).toHaveFocus();
  });

  it("returns focus to the element that had it once the dialog unmounts", () => {
    const trigger = document.createElement("button");
    trigger.textContent = "open";
    document.body.appendChild(trigger);
    trigger.focus();
    expect(trigger).toHaveFocus();

    const { unmount } = render(
      <Confirm title="Remove?" body="Body text" confirmLabel="Remove" onConfirm={vi.fn()} onCancel={vi.fn()} />,
    );
    expect(trigger).not.toHaveFocus();

    unmount();
    expect(trigger).toHaveFocus();
    trigger.remove();
  });

  it("cancels on Escape without calling onConfirm", async () => {
    const onCancel = vi.fn();
    const onConfirm = vi.fn();
    render(
      <Confirm title="Remove?" body="Body text" confirmLabel="Remove" onConfirm={onConfirm} onCancel={onCancel} />,
    );
    await userEvent.keyboard("{Escape}");
    expect(onCancel).toHaveBeenCalledOnce();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("keeps the confirm button disabled until the required phrase is typed exactly", async () => {
    const onConfirm = vi.fn();
    render(
      <Confirm
        title="Reset this vault?"
        body="This destroys everything."
        confirmLabel="Reset"
        requireTyped="RESET"
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );
    const confirmButton = screen.getByRole("button", { name: /^reset$/i });
    expect(confirmButton).toBeDisabled();

    await userEvent.type(screen.getByLabelText(/type/i), "reset");
    expect(confirmButton).toBeDisabled(); // wrong case is not an exact match

    await userEvent.clear(screen.getByLabelText(/type/i));
    await userEvent.type(screen.getByLabelText(/type/i), "RESET");
    expect(confirmButton).toBeEnabled();

    await userEvent.click(confirmButton);
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("calls onCancel when Cancel is clicked", async () => {
    const onCancel = vi.fn();
    render(
      <Confirm title="Remove?" body="Body text" confirmLabel="Remove" onConfirm={vi.fn()} onCancel={onCancel} />,
    );
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledOnce();
  });
});
