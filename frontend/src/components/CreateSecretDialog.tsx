import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogTitle,
  Input,
  Textarea,
} from "@revealui/presentation";
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface CreateSecretDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: (path: string) => void;
}

export function CreateSecretDialog({
  open,
  onClose,
  onCreated,
}: CreateSecretDialogProps) {
  const [path, setPath] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  function reset() {
    setPath("");
    setValue("");
    setError(null);
    setSaving(false);
  }

  function handleClose() {
    reset();
    onClose();
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    const trimmedPath = path.trim();

    if (!trimmedPath || !value) {
      setError("Path and value are required.");
      return;
    }

    setSaving(true);
    setError(null);

    try {
      await invoke("set_secret", {
        path: trimmedPath,
        value,
        force: false,
      });
      const createdPath = trimmedPath;
      reset();
      onCreated(createdPath);
    } catch (e) {
      setError(String(e));
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onClose={handleClose} size="md">
      <form onSubmit={handleSubmit}>
        <DialogTitle>Create Secret</DialogTitle>
        <DialogBody>
          {error && (
            <div className="mb-3 rounded-md border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-300">
              {error}
            </div>
          )}

          <label className="mb-1 block text-sm font-medium text-neutral-400">
            Path
          </label>
          <Input
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="credentials/stripe/secret-key"
            autoFocus
          />

          <label className="mt-4 mb-1 block text-sm font-medium text-neutral-400">
            Value
          </label>
          <Textarea
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Secret value..."
            rows={4}
          />
        </DialogBody>
        <DialogActions>
          <Button
            type="button"
            variant="neutral"
            appearance="ghost"
            onClick={handleClose}
          >
            Cancel
          </Button>
          <Button type="submit" variant="brand" appearance="solid" isLoading={saving}>
            Create
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}
