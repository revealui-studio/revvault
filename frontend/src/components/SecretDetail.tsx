import { Button } from "@revealui/presentation";
import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SecretDetailProps {
  path: string | null;
  onDeleted: () => void;
}

export function SecretDetail(props: SecretDetailProps) {
  return <SelectedSecretDetail key={props.path} {...props} />;
}

function SelectedSecretDetail({ path, onDeleted }: SecretDetailProps) {
  const active = useRef(true);
  const [revealed, setRevealed] = useState(false);
  const [value, setValue] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);

  if (!path) {
    return (
      <div className="flex flex-1 items-center justify-center text-neutral-500">
        Select a secret to view details
      </div>
    );
  }

  async function handleReveal() {
    if (revealed) {
      setRevealed(false);
      setValue(null);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await invoke<string>("get_secret", { path });
      if (!active.current) return;
      setValue(result);
      setRevealed(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleCopy() {
    setError(null);
    try {
      const secret = value ?? (await invoke<string>("get_secret", { path }));
      if (!active.current) return;
      await invoke("copy_to_clipboard", { value: secret });
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleDelete() {
    if (!confirm(`Delete "${path}"?`)) return;
    setError(null);
    try {
      await invoke("delete_secret", { path });
      if (active.current) onDeleted();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="flex flex-1 flex-col p-6">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-neutral-100">{path}</h2>
        <div className="mt-1 text-sm text-neutral-500">
          Namespace: {path.split("/")[0]}
        </div>
      </div>

      <div className="mb-4 rounded-md border border-neutral-700 bg-neutral-900 p-4">
        {revealed && value ? (
          <pre className="whitespace-pre-wrap break-all font-mono text-sm text-neutral-200">
            {value}
          </pre>
        ) : (
          <div className="font-mono text-sm text-neutral-600">
            {"*".repeat(32)}
          </div>
        )}
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="flex gap-2">
        <Button
          type="button"
          variant="neutral"
          appearance="solid"
          onClick={handleReveal}
          disabled={loading}
          isLoading={loading}
        >
          {revealed ? "Hide" : "Reveal"}
        </Button>

        <Button type="button" variant="brand" appearance="solid" onClick={handleCopy}>
          {copied ? "Copied!" : "Copy"}
        </Button>

        <Button type="button" variant="danger" appearance="solid" onClick={handleDelete}>
          Delete
        </Button>
      </div>
    </div>
  );
}
