import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SetupScreen } from "./SetupScreen";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
const mockInvoke = vi.mocked(invoke);

const mockSummary = {
  store_dir: "/home/user/.revealui/passage-store",
  identity_file: "/home/user/.config/age/keys.txt",
  public_key: "age1abc123",
  store_existed: false,
  identity_existed: false,
};

describe("SetupScreen", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("renders the initial setup prompt", () => {
    render(<SetupScreen onComplete={vi.fn()} />);
    expect(screen.getByText("Create your encrypted vault")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Set up vault" })
    ).toBeInTheDocument();
  });

  it("shows default store and identity paths in the description", () => {
    render(<SetupScreen onComplete={vi.fn()} />);
    expect(
      screen.getByText("~/.revealui/passage-store")
    ).toBeInTheDocument();
    expect(screen.getByText("~/.config/age/keys.txt")).toBeInTheDocument();
  });

  it("shows 'Vault ready' after successful init", async () => {
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue(mockSummary);

    render(<SetupScreen onComplete={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Set up vault" }));

    await waitFor(() =>
      expect(screen.getByText("Vault ready")).toBeInTheDocument()
    );
    expect(screen.getByText("age1abc123")).toBeInTheDocument();
  });

  it("calls onComplete when 'Open vault' is clicked after init", async () => {
    const onComplete = vi.fn();
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue(mockSummary);

    render(<SetupScreen onComplete={onComplete} />);

    await user.click(screen.getByRole("button", { name: "Set up vault" }));
    await screen.findByText("Vault ready");
    await user.click(screen.getByRole("button", { name: "Open vault" }));

    expect(onComplete).toHaveBeenCalled();
  });

  it("shows an error message when init fails", async () => {
    const user = userEvent.setup();
    mockInvoke.mockRejectedValue(new Error("permission denied"));

    render(<SetupScreen onComplete={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Set up vault" }));

    await waitFor(() =>
      expect(screen.getByText("Error: permission denied")).toBeInTheDocument()
    );
  });
});
