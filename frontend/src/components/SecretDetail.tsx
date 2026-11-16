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
  const [shown, setShown] = useState(false);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const shownTimer = useRef<number | null>(null);
  const copiedTimer = useRef<number | null>(null);

  function clearTimers() {
    if (shownTimer.current !== null) {
      window.clearTimeout(shownTimer.current);
      shownTimer.current = null;
    }
    if (copiedTimer.current !== null) {
      window.clearTimeout(copiedTimer.current);
      copiedTimer.current = null;
    }
  }

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);

  useEffect(() => () => clearTimers(), []);

  if (!path) {
    return (
      <div className="flex flex-1 items-center justify-center text-neutral-500">
        Select a secret to view details
      </div>
    );
  }

  async function handleReveal() {
    setLoading(true);
    setError(null);
    try {
      // Native dialog in Rust. The command returns unit; JS never sees the value.
      await invoke("reveal_secret", { path });
      if (!active.current) return;
      setShown(true);
      if (shownTimer.current !== null) {
        window.clearTimeout(shownTimer.current);
      }
      shownTimer.current = window.setTimeout(() => {
        setShown(false);
        shownTimer.current = null;
      }, 2000);
    } catch (e) {
      if (active.current) setError(String(e));
    } finally {
      if (active.current) setLoading(false);
    }
  }

  async function handleCopy() {
    setError(null);
    try {
      await invoke("copy_secret", { path });
      if (!active.current) return;
      setCopied(true);
      if (copiedTimer.current !== null) {
        window.clearTimeout(copiedTimer.current);
      }
      copiedTimer.current = window.setTimeout(() => {
        setCopied(false);
        copiedTimer.current = null;
      }, 2000);
    } catch (e) {
      if (active.current) setError(String(e));
    }
  }

  async function handleDelete() {
    if (!confirm(`Delete "${path}"?`)) return;
    setError(null);
    try {
      await invoke("delete_secret", { path });
      if (active.current) onDeleted();
    } catch (e) {
      if (active.current) setError(String(e));
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
        <div className="font-mono text-sm text-neutral-600">
          {"*".repeat(32)}
        </div>
        <p className="mt-3 text-sm text-neutral-500">
          Value stays masked in the webview. Reveal opens a system dialog.
          Copy stays in native code.
        </p>
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
          {shown ? "Shown" : "Reveal"}
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
