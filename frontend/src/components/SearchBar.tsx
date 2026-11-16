import { Input } from "@revealui/presentation";

interface SearchBarProps {
  query: string;
  onSearch: (query: string) => void;
}

export function SearchBar({ query, onSearch }: SearchBarProps) {
  return (
    <div className="bg-neutral-900 px-4 py-3">
      <Input
        type="text"
        value={query}
        onChange={(e) => onSearch(e.target.value)}
        placeholder="Search secret names and paths"
      />
    </div>
  );
}
