import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SecretDetail } from "./SecretDetail";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
const mockInvoke = vi.mocked(invoke);

describe("SecretDetail", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  it("shows placeholder when no path is selected", () => {
    render(<SecretDetail path={null} onDeleted={vi.fn()} />);
    expect(
      screen.getByText("Select a secret to view details")
    ).toBeInTheDocument();
  });

  it("shows the secret path as the title", () => {
    render(
      <SecretDetail path="credentials/stripe/secret-key" onDeleted={vi.fn()} />
    );
    expect(
      screen.getByText("credentials/stripe/secret-key")
    ).toBeInTheDocument();
  });

  it("shows a masked value and a Reveal control that never writes IPC into the DOM", () => {
    render(<SecretDetail path="misc/token" onDeleted={vi.fn()} />);
    expect(screen.getByText("*".repeat(32))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reveal" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Hide" })).not.toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("reveals via reveal_secret(path) without writing a value into the DOM", async () => {
    const user = userEvent.setup();
    // Even if a buggy backend returned a string, the UI must not display it.
    mockInvoke.mockResolvedValue("sk_live_secret");

    render(<SecretDetail path="credentials/stripe/key" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Reveal" }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Shown" })).toBeInTheDocument()
    );
    expect(mockInvoke).toHaveBeenCalledWith("reveal_secret", {
      path: "credentials/stripe/key",
    });
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "get_secret",
      expect.anything()
    );
    expect(screen.queryByText("sk_live_secret")).not.toBeInTheDocument();
    expect(screen.getByText("*".repeat(32))).toBeInTheDocument();
  });

  it("shows error when reveal invoke fails and stays masked", async () => {
    const user = userEvent.setup();
    mockInvoke.mockRejectedValue(new Error("native dialog unavailable"));

    render(<SecretDetail path="misc/key" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Reveal" }));

    await waitFor(() =>
      expect(
        screen.getByText("Error: native dialog unavailable")
      ).toBeInTheDocument()
    );
    expect(screen.getByText("*".repeat(32))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reveal" })).toBeInTheDocument();
  });

  it("does not call get_secret on mount or copy", async () => {
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue(undefined);

    render(<SecretDetail path="credentials/stripe/key" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Copy" }));

    expect(mockInvoke).not.toHaveBeenCalledWith(
      "get_secret",
      expect.anything()
    );
    expect(
      mockInvoke.mock.calls.some(([cmd]) => cmd === "get_secret")
    ).toBe(false);
  });

  it("copies via copy_secret(path) without sending the value through JS", async () => {
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue(undefined);

    render(<SecretDetail path="misc/token" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Copy" }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Copied!" })).toBeInTheDocument()
    );
    expect(mockInvoke).toHaveBeenCalledWith("copy_secret", {
      path: "misc/token",
    });
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "copy_to_clipboard",
      expect.anything()
    );
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "get_secret",
      expect.anything()
    );
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "reveal_secret",
      expect.anything()
    );
  });

  it("shows error when copy_secret fails", async () => {
    const user = userEvent.setup();
    mockInvoke.mockRejectedValue(new Error("clipboard unavailable"));

    render(<SecretDetail path="misc/key" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Copy" }));

    await waitFor(() =>
      expect(
        screen.getByText("Error: clipboard unavailable")
      ).toBeInTheDocument()
    );
  });

  it("calls invoke('delete_secret') and onDeleted after confirmed delete", async () => {
    const onDeleted = vi.fn();
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue(undefined);

    render(<SecretDetail path="misc/token" onDeleted={onDeleted} />);

    await user.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(onDeleted).toHaveBeenCalled());
    expect(mockInvoke).toHaveBeenCalledWith("delete_secret", {
      path: "misc/token",
    });
  });

  it("does not delete when confirm is cancelled", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    const onDeleted = vi.fn();
    const user = userEvent.setup();

    render(<SecretDetail path="misc/token" onDeleted={onDeleted} />);

    await user.click(screen.getByRole("button", { name: "Delete" }));

    expect(mockInvoke).not.toHaveBeenCalled();
    expect(onDeleted).not.toHaveBeenCalled();
  });
  it("discards a delayed reveal after selecting another secret", async () => {
    const user = userEvent.setup();
    let resolveOld!: (value: string) => void;
    mockInvoke.mockReturnValueOnce(new Promise<string>((resolve) => { resolveOld = resolve; }));
    const { rerender } = render(<SecretDetail path="misc/old" onDeleted={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Reveal" }));
    rerender(<SecretDetail path="misc/new" onDeleted={vi.fn()} />);
    await act(async () => { resolveOld("old secret"); });
    expect(screen.queryByText("old secret")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reveal" })).toBeEnabled();
    mockInvoke.mockResolvedValueOnce(undefined);
    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(mockInvoke).toHaveBeenLastCalledWith("copy_secret", { path: "misc/new" });
  });

  it("does not show a stale copy confirmation after switching away and back", async () => {
    const user = userEvent.setup();
    let resolveOld!: (value: string) => void;
    mockInvoke.mockReturnValueOnce(new Promise<string>((resolve) => { resolveOld = resolve; }));
    const { rerender } = render(<SecretDetail path="misc/old" onDeleted={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Copy" }));
    rerender(<SecretDetail path="misc/new" onDeleted={vi.fn()} />);
    rerender(<SecretDetail path="misc/old" onDeleted={vi.fn()} />);
    await act(async () => { resolveOld("old secret"); });
    expect(screen.getByRole("button", { name: "Copy" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copied!" })).not.toBeInTheDocument();
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(mockInvoke).toHaveBeenCalledWith("copy_secret", { path: "misc/old" });
  });

});
