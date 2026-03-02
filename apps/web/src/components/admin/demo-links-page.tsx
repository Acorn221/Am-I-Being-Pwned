import { useMutation, useQuery } from "@tanstack/react-query";
import { Copy, ExternalLink, Loader2, PlusCircle, Trash2 } from "lucide-react";
import { useState } from "react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@amibeingpwned/ui/dialog";
import { Input } from "@amibeingpwned/ui/input";
import { Label } from "@amibeingpwned/ui/label";

import { useTRPC } from "~/lib/trpc";
import { PageHeader } from "./layout";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type CreateDialogState =
  | { phase: "idle" }
  | { phase: "open" }
  | { phase: "creating" }
  | { phase: "done"; demoUrl: string };

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function DemoLinksPage() {
  const trpc = useTRPC();
  const [createDialog, setCreateDialog] = useState<CreateDialogState>({ phase: "idle" });
  const [labelInput, setLabelInput] = useState("");
  const [copied, setCopied] = useState(false);

  const { data: links, refetch, isLoading } = useQuery(
    trpc.demo.list.queryOptions(),
  );

  const createMutation = useMutation(trpc.demo.create.mutationOptions());
  const revokeMutation = useMutation(trpc.demo.revoke.mutationOptions());

  function openCreateDialog() {
    setLabelInput("");
    setCreateDialog({ phase: "open" });
  }

  async function handleCreate() {
    if (!labelInput.trim()) return;
    setCreateDialog({ phase: "creating" });
    createMutation.mutate(
      { label: labelInput.trim() },
      {
        onSuccess(data) {
          const demoUrl = `${window.location.origin}/demo/${data.slug}`;
          setCreateDialog({ phase: "done", demoUrl });
          void refetch();
        },
        onError() {
          setCreateDialog({ phase: "idle" });
        },
      },
    );
  }

  function handleRevoke(id: string) {
    revokeMutation.mutate(
      { id },
      { onSuccess: () => void refetch() },
    );
  }

  async function copyToClipboard(text: string) {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const isDialogOpen = createDialog.phase !== "idle";

  return (
    <div className="flex flex-col">
      <PageHeader
        breadcrumbs={[
          { label: "Admin", href: "/admin" },
          { label: "Demo Links" },
        ]}
        actions={
          <Button size="sm" onClick={openCreateDialog}>
            <PlusCircle className="mr-1.5 h-4 w-4" />
            New demo link
          </Button>
        }
      />

      <div className="p-6">
        {isLoading ? (
          <div className="flex items-center gap-2 py-12 text-center justify-center">
            <Loader2 className="text-muted-foreground h-5 w-5 animate-spin" />
            <span className="text-muted-foreground text-sm">Loading...</span>
          </div>
        ) : !links?.length ? (
          <div className="py-12 text-center">
            <p className="text-muted-foreground text-sm">
              No demo links yet. Create one to start tracking prospect engagement.
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-muted-foreground px-4 py-3 text-left font-medium">
                    Label
                  </th>
                  <th className="text-muted-foreground px-4 py-3 text-right font-medium">
                    Clicks
                  </th>
                  <th className="text-muted-foreground px-4 py-3 text-right font-medium">
                    Scans
                  </th>
                  <th className="text-muted-foreground px-4 py-3 text-left font-medium">
                    Created
                  </th>
                  <th className="text-muted-foreground px-4 py-3 text-left font-medium">
                    Status
                  </th>
                  <th className="w-10" />
                </tr>
              </thead>
              <tbody>
                {links.map((link) => (
                  <tr key={link.id} className="border-b last:border-0">
                    <td className="px-4 py-3">
                      <p className="text-foreground text-sm font-medium">{link.label}</p>
                      <p className="text-muted-foreground font-mono text-xs">/demo/{link.slug}</p>
                    </td>
                    <td className="text-foreground px-4 py-3 text-right tabular-nums">
                      {link.clickCount}
                    </td>
                    <td className="text-foreground px-4 py-3 text-right tabular-nums">
                      {link.scanCount}
                    </td>
                    <td className="text-muted-foreground px-4 py-3">
                      {new Date(link.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      {link.revokedAt ? (
                        <Badge variant="secondary">Revoked</Badge>
                      ) : (
                        <Badge
                          variant="secondary"
                          className="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                        >
                          Active
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {!link.revokedAt && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-muted-foreground hover:text-destructive h-7 w-7 p-0"
                          onClick={() => handleRevoke(link.id)}
                          disabled={revokeMutation.isPending}
                          title="Revoke link"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create dialog */}
      <Dialog
        open={isDialogOpen}
        onOpenChange={(open) => {
          if (!open) setCreateDialog({ phase: "idle" });
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              {createDialog.phase === "done" ? "Demo link created" : "New demo link"}
            </DialogTitle>
          </DialogHeader>

          {createDialog.phase === "done" ? (
            <div className="flex flex-col gap-4">
              <p className="text-muted-foreground text-sm">
                Copy this link and send it to your prospect. It will only be
                shown once.
              </p>
              <div className="flex gap-2">
                <Input
                  readOnly
                  value={createDialog.demoUrl}
                  className="font-mono text-xs"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => void copyToClipboard(createDialog.demoUrl)}
                  className="shrink-0"
                >
                  {copied ? (
                    <span className="text-xs">Copied!</span>
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  asChild
                  className="shrink-0"
                >
                  <a href={createDialog.demoUrl} target="_blank" rel="noreferrer">
                    <ExternalLink className="h-4 w-4" />
                  </a>
                </Button>
              </div>
              <Button onClick={() => setCreateDialog({ phase: "idle" })}>
                Done
              </Button>
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="demo-label">Link label</Label>
                <Input
                  id="demo-label"
                  placeholder="e.g. TechCorp outreach"
                  value={labelInput}
                  onChange={(e) => setLabelInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void handleCreate();
                  }}
                  autoFocus
                />
                <p className="text-muted-foreground text-xs">
                  For your reference only - prospects won't see this.
                </p>
              </div>
              <Button
                onClick={() => void handleCreate()}
                disabled={!labelInput.trim() || createDialog.phase === "creating"}
              >
                {createDialog.phase === "creating" ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Creating...
                  </>
                ) : (
                  "Create link"
                )}
              </Button>
              {createMutation.isError && (
                <p className="text-destructive text-sm">
                  Failed to create link. Please try again.
                </p>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
