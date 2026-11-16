import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SecretList } from "./SecretList";
import type { SecretInfo } from "../types";

const secrets: SecretInfo[] = [
  { path: "credentials/stripe/secret-key", namespace: "credentials" },
  { path: "ssh/github", namespace: "ssh" },
];

describe("SecretList", () => {
  it("shows empty state when no secrets", () => {
    render(<SecretList secrets={[]} selected={null} onSelect={vi.fn()} />);
    expect(screen.getByText("No secrets to show")).toBeInTheDocument();
  });

  it("renders each secret's full path", () => {
    render(<SecretList secrets={secrets} selected={null} onSelect={vi.fn()} />);
    expect(screen.getByText("credentials/stripe/secret-key")).toBeInTheDocument();
    expect(screen.getByText("ssh/github")).toBeInTheDocument();
  });

  it("shows the last path segment as the title", () => {
    render(<SecretList secrets={secrets} selected={null} onSelect={vi.fn()} />);
    expect(screen.getByText("secret-key")).toBeInTheDocument();
    expect(screen.getByText("github")).toBeInTheDocument();
  });

  it("calls onSelect with path when a secret is clicked", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(<SecretList secrets={secrets} selected={null} onSelect={onSelect} />);

    await user.click(screen.getByText("secret-key"));

    expect(onSelect).toHaveBeenCalledWith("credentials/stripe/secret-key");
  });

  it("highlights the selected secret", () => {
    render(
      <SecretList
        secrets={secrets}
        selected="ssh/github"
        onSelect={vi.fn()}
      />
    );
    // The selected button contains "github" text — find its containing button
    const selectedBtn = screen.getByText("github").closest("button");
    expect(selectedBtn).toHaveClass("bg-neutral-800");
  });
});
