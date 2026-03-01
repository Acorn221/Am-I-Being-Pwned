import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  Check,
  CheckCircle,
  Clock,
  OctagonX,
  Plus,
  RefreshCw,
  Shield,
  Unlock,
} from "lucide-react";


import { Button } from "@amibeingpwned/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@amibeingpwned/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@amibeingpwned/ui/dialog";
import { Switch } from "@amibeingpwned/ui/switch";
import { Input } from "@amibeingpwned/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";
import { Badge } from "@amibeingpwned/ui/badge";
import { Skeleton } from "@amibeingpwned/ui/skeleton";
import { toast } from "@amibeingpwned/ui/toast";

import { useTRPC } from "~/lib/trpc";
import { timeAgo } from "./fleet-types";

type QueueStatus = "pending" | "approved" | "blocked";

// ─── Shared ID extraction ─────────────────────────────────────────────────────

function extractExtensionId(raw: string): string | null {
  const match = raw.trim().toLowerCase().match(/[a-p]{32}/);
  return match ? match[0] : null;
}

// ─── Block Extension Dialog ───────────────────────────────────────────────────

function BlockExtensionDialog({
  open,
  onOpenChange,
  onBlocked,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onBlocked: () => void;
}) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const [input, setInput] = useState("");
  const [error, setError] = useState("");

  const extracted = extractExtensionId(input);

  const blockMutation = useMutation(
    trpc.org.blockExtension.mutationOptions({
      onSuccess: () => {
        toast.success("Extension blocked");
        void queryClient.invalidateQueries(trpc.org.getQueue.queryFilter());
        void queryClient.invalidateQueries(trpc.org.getPolicy.queryFilter());
        setInput("");
        setError("");
        onOpenChange(false);
        onBlocked();
      },
      onError: () => toast.error("Failed to block extension"),
    }),
  );

  function handleConfirm() {
    if (!extracted) {
      setError("No valid extension ID found");
      return;
    }
    blockMutation.mutate({ chromeExtensionId: extracted });
  }

  function handleChange(raw: string) {
    // If pasted value contains non-ID chars, extract immediately
    const isPureId = /^[a-p]{0,32}$/.test(raw.trim().toLowerCase());
    if (!isPureId) {
      const found = extractExtensionId(raw);
      if (found) {
        setInput(found);
        setError("");
        return;
      }
    }
    setInput(raw);
    setError("");
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (!v) { setInput(""); setError(""); } }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Block extension</DialogTitle>
          <DialogDescription>
            Paste a Chrome Web Store URL or a 32-character extension ID. The
            extension will be disabled on all enrolled devices at their next
            sync.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <Input
            autoFocus
            placeholder="Paste URL or extension ID"
            value={input}
            onChange={(e) => handleChange(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") handleConfirm(); }}
            className="font-mono text-sm"
          />
          {error && <p className="text-destructive text-xs">{error}</p>}
        </div>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button
            variant="destructive"
            disabled={!extracted || blockMutation.isPending}
            onClick={handleConfirm}
          >
            {blockMutation.isPending && (
              <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            )}
            Block extension
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Policy Settings Card ─────────────────────────────────────────────────────

function PolicySettingsCard({ onBlocked }: { onBlocked: () => void }) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);

  const { data: policy, isLoading } = useQuery(trpc.org.getPolicy.queryOptions());

  const [maxRiskScore, setMaxRiskScore] = useState<string>("");
  const [blockUnknown, setBlockUnknown] = useState(false);
  const [initialized, setInitialized] = useState(false);

  if (policy && !initialized) {
    setMaxRiskScore(policy.maxRiskScore != null ? String(policy.maxRiskScore) : "");
    setBlockUnknown(policy.blockUnknown ?? false);
    setInitialized(true);
  }

  const saveMutation = useMutation(
    trpc.org.updatePolicy.mutationOptions({
      onSuccess: () => {
        toast.success("Policy saved");
        void queryClient.invalidateQueries(trpc.org.getPolicy.queryFilter());
      },
      onError: () => toast.error("Failed to save policy"),
    }),
  );

  function handleSave() {
    const parsedScore = maxRiskScore === "" ? null : parseInt(maxRiskScore, 10);
    if (maxRiskScore !== "" && (isNaN(parsedScore!) || parsedScore! < 0 || parsedScore! > 100)) {
      toast.error("Risk score must be between 0 and 100");
      return;
    }
    saveMutation.mutate({ maxRiskScore: parsedScore, blockUnknown });
  }

  const blockedCount = policy?.blockedExtensionIds?.length ?? 0;

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-40" />
          <Skeleton className="mt-1 h-4 w-64" />
        </CardHeader>
        <CardContent className="space-y-4">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <BlockExtensionDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        onBlocked={onBlocked}
      />
      <Card
        footerActions={[
          {
            label: saveMutation.isPending ? "Saving..." : "Save policy",
            icon: saveMutation.isPending ? RefreshCw : undefined,
            disabled: saveMutation.isPending,
            onClick: handleSave,
          },
        ]}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Extension Policy
          </CardTitle>
          <CardDescription>
            Configure rules that automatically disable or quarantine extensions
            across all enrolled devices in your organisation.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-0 divide-y">
          {/* Block unknown extensions */}
          <div className="flex items-center justify-between gap-6 py-4">
            <div className="min-w-0">
              <p className="text-sm font-medium">Block unknown extensions</p>
              <p className="text-muted-foreground mt-0.5 text-xs">
                Quarantine any extension not yet in the AIBP database. It will
                be added to the review queue below.
              </p>
            </div>
            <Switch checked={blockUnknown} onCheckedChange={setBlockUnknown} />
          </div>

          {/* Max risk score */}
          <div className="flex items-center justify-between gap-6 py-4">
            <div className="min-w-0">
              <label className="text-sm font-medium" htmlFor="max-risk-score">
                Max risk score threshold
              </label>
              <p className="text-muted-foreground mt-0.5 text-xs">
                Auto-disable extensions with a risk score at or above this
                value (0-100). Leave empty to disable this rule.
              </p>
            </div>
            <Input
              id="max-risk-score"
              type="number"
              min={0}
              max={100}
              placeholder="e.g. 70"
              value={maxRiskScore}
              onChange={(e) => setMaxRiskScore(e.target.value)}
              className="w-24 shrink-0 text-center"
            />
          </div>

          {/* Manual blocklist */}
          <div className="flex items-center justify-between gap-6 py-4">
            <div className="min-w-0">
              <p className="text-sm font-medium">Extension blocklist</p>
              <p className="text-muted-foreground mt-0.5 text-xs">
                {blockedCount > 0
                  ? `${blockedCount} extension${blockedCount === 1 ? "" : "s"} manually blocked - visible in the Blocked tab below.`
                  : "Manually disable specific extensions across all devices."}
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              className="shrink-0"
              onClick={() => setDialogOpen(true)}
            >
              <Plus className="h-3.5 w-3.5" />
              Block extension
            </Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}

// ─── Queue status badge ───────────────────────────────────────────────────────

function QueueStatusBadge({ status }: { status: QueueStatus }) {
  if (status === "pending") {
    return (
      <Badge variant="outline" className="gap-1 text-yellow-600">
        <Clock className="h-3 w-3" />
        Pending
      </Badge>
    );
  }
  if (status === "approved") {
    return (
      <Badge variant="outline" className="gap-1 text-green-600">
        <CheckCircle className="h-3 w-3" />
        Approved
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="text-destructive gap-1">
      <OctagonX className="h-3 w-3" />
      Blocked
    </Badge>
  );
}

// ─── Unblock Confirmation Dialog ─────────────────────────────────────────────

function UnblockDialog({
  item,
  onClose,
}: {
  item: { id: string; chromeExtensionId: string; extensionName: string | null } | null;
  onClose: () => void;
}) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();

  const reviewMutation = useMutation(
    trpc.org.reviewQueueItem.mutationOptions({
      onSuccess: () => {
        toast.success("Extension unblocked - will re-enable on next sync");
        void queryClient.invalidateQueries(trpc.org.getQueue.queryFilter());
        void queryClient.invalidateQueries(trpc.org.getPolicy.queryFilter());
        onClose();
      },
      onError: () => toast.error("Failed to update extension"),
    }),
  );

  if (!item) return null;

  const label = item.extensionName ?? item.chromeExtensionId;

  return (
    <Dialog open={!!item} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Unblock extension?</DialogTitle>
          <DialogDescription>
            <code className="font-mono text-xs">{label}</code> will be
            re-enabled on all enrolled devices at their next sync.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button
            disabled={reviewMutation.isPending}
            onClick={() => reviewMutation.mutate({ queueId: item.id, action: "approve" })}
          >
            {reviewMutation.isPending ? (
              <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Unlock className="mr-1.5 h-3.5 w-3.5" />
            )}
            Unblock
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Review Queue Card ────────────────────────────────────────────────────────

const STATUS_LABELS: Record<QueueStatus, string> = {
  pending: "Pending",
  approved: "Approved",
  blocked: "Blocked",
};

const REASON_LABELS: Record<string, string> = {
  blocklisted: "Blocklisted",
  risk_threshold: "Risk threshold",
  unknown: "Unknown extension",
};

type QueueItem = {
  id: string;
  chromeExtensionId: string;
  extensionName: string | null;
  reason: string;
  status: string;
  riskScore: number | null;
  createdAt: Date;
};

function RowActions({
  item,
  isPending,
  onReview,
  onUnblock,
}: {
  item: QueueItem;
  isPending: boolean;
  onReview: (queueId: string, action: "approve" | "block" | "override") => void;
  onUnblock: (item: QueueItem) => void;
}) {
  if (item.status === "pending") {
    return (
      <div className="flex justify-end gap-1.5">
        <Button
          size="sm"
          variant="outline"
          className="h-7 gap-1 px-2 text-green-600 hover:text-green-700"
          disabled={isPending}
          onClick={() => onReview(item.id, "approve")}
        >
          <Check className="h-3 w-3" />
          Approve
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="text-destructive hover:text-destructive h-7 gap-1 px-2"
          disabled={isPending}
          onClick={() => onReview(item.id, "block")}
        >
          <OctagonX className="h-3 w-3" />
          Block
        </Button>
      </div>
    );
  }
  if (item.status === "blocked") {
    return (
      <div className="flex justify-end">
        <Button
          size="sm"
          variant="outline"
          className="h-7 gap-1 px-2 text-green-600 hover:text-green-700"
          onClick={() => onUnblock(item)}
        >
          <Unlock className="h-3 w-3" />
          Unblock
        </Button>
      </div>
    );
  }
  // approved
  return (
    <div className="flex justify-end">
      <Button
        size="sm"
        variant="outline"
        className="text-destructive hover:text-destructive h-7 gap-1 px-2"
        disabled={isPending}
        onClick={() => onReview(item.id, "block")}
      >
        <OctagonX className="h-3 w-3" />
        Block
      </Button>
    </div>
  );
}

function ReviewQueueCard({
  statusFilter,
  setStatusFilter,
}: {
  statusFilter: QueueStatus;
  setStatusFilter: (s: QueueStatus) => void;
}) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const [unblockTarget, setUnblockTarget] = useState<QueueItem | null>(null);

  // Preload all three tabs in parallel so switching is instant
  const { data: pendingQueue, isLoading: pendingLoading } = useQuery(trpc.org.getQueue.queryOptions({ status: "pending" }));
  const { data: approvedQueue, isLoading: approvedLoading } = useQuery(trpc.org.getQueue.queryOptions({ status: "approved" }));
  const { data: blockedQueue, isLoading: blockedLoading } = useQuery(trpc.org.getQueue.queryOptions({ status: "blocked" }));

  const queues: Record<QueueStatus, QueueItem[] | undefined> = {
    pending: pendingQueue,
    approved: approvedQueue,
    blocked: blockedQueue,
  };
  const loadingMap: Record<QueueStatus, boolean> = {
    pending: pendingLoading,
    approved: approvedLoading,
    blocked: blockedLoading,
  };

  const queue = queues[statusFilter];
  const isLoading = loadingMap[statusFilter];

  const reviewMutation = useMutation(
    trpc.org.reviewQueueItem.mutationOptions({
      onSuccess: (_data, variables) => {
        toast.success(
          variables.action === "approve"
            ? "Extension approved - will re-enable on next sync"
            : "Extension blocked - remains disabled",
        );
        void queryClient.invalidateQueries(trpc.org.getQueue.queryFilter());
        void queryClient.invalidateQueries(trpc.org.getPolicy.queryFilter());
      },
      onError: () => toast.error("Failed to update queue item"),
    }),
  );

  return (
    <>
      <UnblockDialog item={unblockTarget} onClose={() => setUnblockTarget(null)} />
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Ban className="h-4 w-4" />
            Review Queue
          </CardTitle>
          <CardDescription>
            Extensions flagged by your policy land here. Approve to re-enable or
            block to keep disabled.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-1">
            {(["pending", "approved", "blocked"] as QueueStatus[]).map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  statusFilter === s
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {STATUS_LABELS[s]}
              </button>
            ))}
          </div>

          {isLoading ? (
            <div className="space-y-2">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : !queue?.length ? (
            <p className="text-muted-foreground py-8 text-center text-sm">
              No {STATUS_LABELS[statusFilter].toLowerCase()} items
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Extension ID</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Queued</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {queue.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>
                      <code className="font-mono text-xs">{item.chromeExtensionId}</code>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {item.extensionName ?? "-"}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {REASON_LABELS[item.reason] ?? item.reason}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {item.riskScore != null ? (
                        <span
                          className={`text-sm font-medium ${
                            item.riskScore >= 70
                              ? "text-destructive"
                              : item.riskScore >= 40
                                ? "text-orange-500"
                                : "text-muted-foreground"
                          }`}
                        >
                          {item.riskScore}
                        </span>
                      ) : (
                        <span className="text-muted-foreground text-sm">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <QueueStatusBadge status={item.status as QueueStatus} />
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {timeAgo(item.createdAt)}
                    </TableCell>
                    <TableCell>
                      <RowActions
                        item={item}
                        isPending={reviewMutation.isPending}
                        onReview={(id, action) => reviewMutation.mutate({ queueId: id, action })}
                        onUnblock={setUnblockTarget}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  );
}

// ─── Tab root ─────────────────────────────────────────────────────────────────

export function PolicyTab() {
  const [statusFilter, setStatusFilter] = useState<QueueStatus>("pending");

  return (
    <div className="space-y-4">
      <PolicySettingsCard onBlocked={() => setStatusFilter("blocked")} />
      <ReviewQueueCard statusFilter={statusFilter} setStatusFilter={setStatusFilter} />
    </div>
  );
}
