import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SearchBar } from "./SearchBar";

describe("SearchBar", () => {
  it("renders with placeholder text", () => {
    render(<SearchBar query="" onSearch={vi.fn()} />);
    expect(screen.getByPlaceholderText("Search secret names and paths")).toBeInTheDocument();
  });

  it("reflects the controlled query prop value", () => {
    render(<SearchBar query="stripe" onSearch={vi.fn()} />);
    expect(screen.getByRole("textbox")).toHaveValue("stripe");
  });

  it("calls onSearch with new value when input changes", async () => {
    const onSearch = vi.fn();
    const user = userEvent.setup();
    render(<SearchBar query="" onSearch={onSearch} />);

    await user.type(screen.getByRole("textbox"), "g");

    expect(onSearch).toHaveBeenCalledWith("g");
  });

  it("calls onSearch on every keystroke", async () => {
    const onSearch = vi.fn();
    const user = userEvent.setup();
    render(<SearchBar query="" onSearch={onSearch} />);

    await user.type(screen.getByRole("textbox"), "abc");

    expect(onSearch).toHaveBeenCalledTimes(3);
  });
});
