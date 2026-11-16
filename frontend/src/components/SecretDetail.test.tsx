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

  it("shows masked value before reveal", () => {
    render(<SecretDetail path="misc/token" onDeleted={vi.fn()} />);
    expect(screen.getByText("*".repeat(32))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reveal" })).toBeInTheDocument();
  });

  it("calls invoke('get_secret') and shows value on Reveal click", async () => {
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue("sk_live_secret");

    render(<SecretDetail path="credentials/stripe/key" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Reveal" }));

    await waitFor(() =>
      expect(screen.getByText("sk_live_secret")).toBeInTheDocument()
    );
    expect(mockInvoke).toHaveBeenCalledWith("get_secret", {
      path: "credentials/stripe/key",
    });
    expect(screen.getByRole("button", { name: "Hide" })).toBeInTheDocument();
  });

  it("hides value again when Hide is clicked", async () => {
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue("my-secret");

    render(<SecretDetail path="misc/pw" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Reveal" }));
    await screen.findByText("my-secret");

    await user.click(screen.getByRole("button", { name: "Hide" }));

    expect(screen.queryByText("my-secret")).not.toBeInTheDocument();
    expect(screen.getByText("*".repeat(32))).toBeInTheDocument();
  });

  it("shows error when reveal invoke fails", async () => {
    const user = userEvent.setup();
    mockInvoke.mockRejectedValue(new Error("decryption failed"));

    render(<SecretDetail path="misc/key" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Reveal" }));

    await waitFor(() =>
      expect(screen.getByText("Error: decryption failed")).toBeInTheDocument()
    );
  });

  it("shows 'Copied!' after successful copy", async () => {
    const user = userEvent.setup();
    // First call (get_secret) returns the value; second (copy_to_clipboard) resolves
    mockInvoke
      .mockResolvedValueOnce("the-secret")
      .mockResolvedValueOnce(undefined);

    render(<SecretDetail path="misc/token" onDeleted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Copy" }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Copied!" })).toBeInTheDocument()
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
    mockInvoke.mockResolvedValueOnce("new secret").mockResolvedValueOnce(undefined);
    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(mockInvoke).toHaveBeenCalledWith("copy_to_clipboard", { value: "new secret" });
  });

  it("does not copy a pending old selection after switching away and back", async () => {
    const user = userEvent.setup();
    let resolveOld!: (value: string) => void;
    mockInvoke.mockReturnValueOnce(new Promise<string>((resolve) => { resolveOld = resolve; }));
    const { rerender } = render(<SecretDetail path="misc/old" onDeleted={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Copy" }));
    rerender(<SecretDetail path="misc/new" onDeleted={vi.fn()} />);
    rerender(<SecretDetail path="misc/old" onDeleted={vi.fn()} />);
    await act(async () => { resolveOld("old secret"); });
    expect(mockInvoke).not.toHaveBeenCalledWith("copy_to_clipboard", expect.anything());
  });

});
