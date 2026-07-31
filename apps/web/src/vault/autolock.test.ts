import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startAutoLock } from "./autolock.js";

// The auto-lock *setting* -- reading it, writing it, its default, its
// fallback for a bad stored value -- moved to preferences.ts and is covered
// by preferences.test.ts now. What is left here is the DOM half: the timers
// and event listeners startAutoLock itself owns, none of which preferences.ts
// touches.
describe("startAutoLock", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());
  afterEach(() => vi.restoreAllMocks());

  it("locks after the configured idle period", () => {
    const onLock = vi.fn();
    startAutoLock({ setting: 1, onLock });

    vi.advanceTimersByTime(59_000);
    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1_001);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("restarts the countdown on user activity", () => {
    const onLock = vi.fn();
    startAutoLock({ setting: 1, onLock });

    vi.advanceTimersByTime(50_000);
    window.dispatchEvent(new Event("keydown"));
    vi.advanceTimersByTime(50_000);

    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(11_000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("locks on wake when more wall-clock time passed than the timer saw", () => {
    // The case auto-lock exists for: the lid was closed. setTimeout did not
    // fire, so a timer-only implementation leaves the vault open.
    let clock = 0;
    const onLock = vi.fn();
    startAutoLock({ setting: 1, onLock, now: () => clock });

    clock = 120_000; // two minutes of real time, no timers fired
    document.dispatchEvent(new Event("visibilitychange"));

    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("locks immediately when the page is hidden and the setting is on-close", () => {
    const onLock = vi.fn();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
    startAutoLock({ setting: "on-close", onLock });

    document.dispatchEvent(new Event("visibilitychange"));

    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("never locks when the setting is never, however long it idles", () => {
    const onLock = vi.fn();
    startAutoLock({ setting: "never", onLock });
    vi.advanceTimersByTime(24 * 60 * 60 * 1000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it("stops locking after teardown", () => {
    const onLock = vi.fn();
    const stop = startAutoLock({ setting: 1, onLock });
    stop();
    vi.advanceTimersByTime(120_000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it("removes its listeners on teardown, so activity after unmount does nothing", () => {
    const onLock = vi.fn();
    const stop = startAutoLock({ setting: 1, onLock });
    stop();
    window.dispatchEvent(new Event("keydown"));
    vi.advanceTimersByTime(120_000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it("stops responding to visibilitychange after teardown, on the idle path", () => {
    let clock = 0;
    const onLock = vi.fn();
    const stop = startAutoLock({ setting: 1, onLock, now: () => clock });

    stop();
    // Long enough that a live checkElapsed would lock immediately.
    clock = 120_000;
    document.dispatchEvent(new Event("visibilitychange"));

    expect(onLock).not.toHaveBeenCalled();
  });

  it("stops responding to visibilitychange after teardown, on the on-close path", () => {
    const onLock = vi.fn();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
    const stop = startAutoLock({ setting: "on-close", onLock });

    stop();
    document.dispatchEvent(new Event("visibilitychange"));

    expect(onLock).not.toHaveBeenCalled();
  });
});
