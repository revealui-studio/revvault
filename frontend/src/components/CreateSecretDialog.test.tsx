import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CreateSecretDialog } from "./CreateSecretDialog";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
const mockInvoke = vi.mocked(invoke);

describe("CreateSecretDialog", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("renders nothing when closed", () => {
    render(
      <CreateSecretDialog open={false} onClose={vi.fn()} onCreated={vi.fn()} />
    );
    expect(screen.queryByText("Create Secret")).not.toBeInTheDocument();
  });

  it("renders the form when open", () => {
    render(
      <CreateSecretDialog open={true} onClose={vi.fn()} onCreated={vi.fn()} />
    );
    expect(screen.getByText("Create Secret")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("credentials/stripe/secret-key")).toBeInTheDocument();
  });

  it("shows validation error when fields are empty on submit", async () => {
    const user = userEvent.setup();
    render(
      <CreateSecretDialog open={true} onClose={vi.fn()} onCreated={vi.fn()} />
    );

    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(screen.getByText("Path and value are required.")).toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("calls invoke('set_secret') with path and value on valid submit", async () => {
    const onCreated = vi.fn();
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue(undefined);

    render(
      <CreateSecretDialog open={true} onClose={vi.fn()} onCreated={onCreated} />
    );

    await user.type(
      screen.getByPlaceholderText("credentials/stripe/secret-key"),
      "credentials/test/key"
    );
    await user.type(screen.getByPlaceholderText("Secret value..."), "my-secret");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(mockInvoke).toHaveBeenCalledWith("set_secret", {
      path: "credentials/test/key",
      value: "my-secret",
      force: false,
    });
  });

  it("calls onCreated with the path after successful save", async () => {
    const onCreated = vi.fn();
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue(undefined);

    render(
      <CreateSecretDialog open={true} onClose={vi.fn()} onCreated={onCreated} />
    );

    await user.type(
      screen.getByPlaceholderText("credentials/stripe/secret-key"),
      "misc/token"
    );
    await user.type(screen.getByPlaceholderText("Secret value..."), "abc123");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(onCreated).toHaveBeenCalledWith("misc/token"));
  });

  it("shows error message on invoke failure", async () => {
    const user = userEvent.setup();
    mockInvoke.mockRejectedValue(new Error("vault locked"));

    render(
      <CreateSecretDialog open={true} onClose={vi.fn()} onCreated={vi.fn()} />
    );

    await user.type(
      screen.getByPlaceholderText("credentials/stripe/secret-key"),
      "misc/key"
    );
    await user.type(screen.getByPlaceholderText("Secret value..."), "val");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(screen.getByText("Error: vault locked")).toBeInTheDocument()
    );
  });

  it("calls onClose and resets state when Cancel is clicked", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();

    render(
      <CreateSecretDialog open={true} onClose={onClose} onCreated={vi.fn()} />
    );

    await user.type(
      screen.getByPlaceholderText("credentials/stripe/secret-key"),
      "some/path"
    );
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(onClose).toHaveBeenCalled();
  });
  it("preserves whitespace in secret values", async () => {
    const user = userEvent.setup();
    mockInvoke.mockResolvedValue(undefined);
    render(<CreateSecretDialog open={true} onClose={vi.fn()} onCreated={vi.fn()} />);
    await user.type(screen.getByPlaceholderText("credentials/stripe/secret-key"), "misc/key");
    await user.type(screen.getByPlaceholderText("Secret value..."), "  secret{Enter} ");
    await user.click(screen.getByRole("button", { name: "Create" }));
    expect(mockInvoke).toHaveBeenCalledWith("set_secret", {
      path: "misc/key", value: "  secret\n ", force: false,
    });
  });

});
