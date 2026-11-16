import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type { SecretInfo } from "./types";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
const mockInvoke = vi.mocked(invoke);

const mockSecrets: SecretInfo[] = [
  { path: "credentials/stripe/key", namespace: "credentials" },
  { path: "credentials/github/token", namespace: "credentials" },
  { path: "misc/token", namespace: "misc" },
];

// init_store resolves → list_secrets always resolves to `secrets`.
// Using mockImplementation so repeated list_secrets calls (direct + effect) both succeed.
function setupHappyPath(secrets: SecretInfo[] = mockSecrets) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "init_store") return Promise.resolve(undefined);
    if (cmd === "list_secrets") return Promise.resolve(secrets);
    return Promise.resolve(undefined);
  });
}

describe("App", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("calls init_store on mount", async () => {
    setupHappyPath([]);
    render(<App />);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("init_store")
    );
  });

  it("renders main UI with secrets after successful init", async () => {
    setupHappyPath();
    render(<App />);

    await waitFor(() =>
      expect(
        screen.getByText("credentials/stripe/key")
      ).toBeInTheDocument()
    );
    expect(
      screen.getByRole("button", { name: "+ New" })
    ).toBeInTheDocument();
  });

  it("shows error banner when init_store fails with a generic error", async () => {
    mockInvoke.mockRejectedValueOnce("permission denied");

    render(<App />);

    await waitFor(() =>
      expect(screen.getByText("permission denied")).toBeInTheDocument()
    );
  });

  it("shows SetupScreen when init_store reports vault not found", async () => {
    mockInvoke.mockRejectedValueOnce("store not found");

    render(<App />);

    await waitFor(() =>
      expect(screen.getByText("Create your encrypted vault")).toBeInTheDocument()
    );
    expect(
      screen.getByRole("button", { name: "Set up vault" })
    ).toBeInTheDocument();
  });

  it("shows namespace list in sidebar from loaded secrets", async () => {
    setupHappyPath();
    render(<App />);

    await waitFor(() =>
      expect(screen.getByText("credentials")).toBeInTheDocument()
    );
    expect(screen.getByText("misc")).toBeInTheDocument();
  });

  it("calls search_secrets when search query is entered", async () => {
    const user = userEvent.setup();
    setupHappyPath();
    // Override search_secrets specifically
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "init_store") return Promise.resolve(undefined);
      if (cmd === "list_secrets") return Promise.resolve(mockSecrets);
      if (cmd === "search_secrets") return Promise.resolve([mockSecrets[0]]);
      return Promise.resolve(undefined);
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByText("credentials/stripe/key")).toBeInTheDocument()
    );

    await user.type(
      screen.getByPlaceholderText("Search secret names and paths"),
      "stripe"
    );

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("search_secrets", {
        query: "stripe",
      })
    );
  });

  it("reloads list_secrets when search query is cleared", async () => {
    const user = userEvent.setup();
    let listCallCount = 0;
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "init_store") return Promise.resolve(undefined);
      if (cmd === "list_secrets") {
        listCallCount++;
        return Promise.resolve(mockSecrets);
      }
      if (cmd === "search_secrets") return Promise.resolve([mockSecrets[0]]);
      return Promise.resolve(undefined);
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByText("credentials/stripe/key")).toBeInTheDocument()
    );

    const input = screen.getByPlaceholderText("Search secret names and paths");
    await user.type(input, "stripe");
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("search_secrets", {
        query: "stripe",
      })
    );

    const countBefore = listCallCount;
    await user.clear(input);

    await waitFor(() => expect(listCallCount).toBeGreaterThan(countBefore));
  });

  it("opens the create dialog when '+ New' is clicked", async () => {
    const user = userEvent.setup();
    setupHappyPath([]);

    render(<App />);

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "+ New" })
      ).toBeInTheDocument()
    );

    await user.click(screen.getByRole("button", { name: "+ New" }));

    expect(screen.getByText("Create Secret")).toBeInTheDocument();
  });

  it("reloads secrets and shows the new path after creation", async () => {
    const user = userEvent.setup();
    const updated = [
      ...mockSecrets,
      { path: "new/key", namespace: "new" },
    ];

    let postCreate = false;
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "init_store") return Promise.resolve(undefined);
      if (cmd === "list_secrets")
        return Promise.resolve(postCreate ? updated : mockSecrets);
      if (cmd === "set_secret") {
        postCreate = true;
        return Promise.resolve(undefined);
      }
      return Promise.resolve(undefined);
    });

    render(<App />);

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "+ New" })
      ).toBeInTheDocument()
    );

    await user.click(screen.getByRole("button", { name: "+ New" }));
    await user.type(
      screen.getByPlaceholderText("credentials/stripe/secret-key"),
      "new/key"
    );
    await user.type(
      screen.getByPlaceholderText("Secret value..."),
      "val"
    );
    await user.click(screen.getByRole("button", { name: "Create" }));

    // new/key appears in both the list row and the SecretDetail panel
    await waitFor(() =>
      expect(screen.getAllByText("new/key").length).toBeGreaterThan(0)
    );
  });
});
