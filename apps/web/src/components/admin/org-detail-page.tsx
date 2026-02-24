import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import { Card } from "@amibeingpwned/ui/card";
import { Input } from "@amibeingpwned/ui/input";
import { Label } from "@amibeingpwned/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";
import {
  AlertTriangle,
  CheckCircle,
  Copy,
  KeyRound,
  RefreshCw,
  Shield,
  ShieldOff,
} from "lucide-react";
import { useState } from "react";

import { useTRPC } from "~/lib/trpc";
import { navigate } from "~/router";
import { PageHeader } from "./layout";

interface OrgDetailPageProps {
  orgId: string;
}

export function OrgDetailPage({ orgId }: OrgDetailPageProps) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const [newKeyName, setNewKeyName] = useState("");
  const [rotatedKey, setRotatedKey] = useState<string | null>(null);
  const [suspendReason, setSuspendReason] = useState("");

  const { data, isLoading } = useQuery(
    trpc.admin.orgs.get.queryOptions({ orgId }),
  );

  const invalidate = () =>
    queryClient.invalidateQueries(trpc.admin.orgs.get.queryFilter({ orgId }));

  const setPlan = useMutation(
    trpc.admin.orgs.setPlan.mutationOptions({ onSuccess: invalidate }),
  );

  const suspend = useMutation(
    trpc.admin.orgs.suspend.mutationOptions({ onSuccess: invalidate }),
  );

  const unsuspend = useMutation(
    trpc.admin.orgs.unsuspend.mutationOptions({ onSuccess: invalidate }),
  );

  const setQuarantine = useMutation(
    trpc.admin.orgs.setQuarantinePolicy.mutationOptions({ onSuccess: invalidate }),
  );

  const rotateApiKey = useMutation(
    trpc.admin.orgs.rotateApiKey.mutationOptions({
      onSuccess: (res) => {
        setRotatedKey(res.rawKey);
        invalidate();
      },
    }),
  );

  const revokeAllDevices = useMutation(
    trpc.admin.orgs.revokeAllDevices.mutationOptions({ onSuccess: invalidate }),
  );

  if (isLoading) {
    return (
      <div className="flex flex-col">
        <PageHeader
          breadcrumbs={[
            { label: "Organisations", href: "/admin/orgs" },
            { label: "Loading…" },
          ]}
        />
        <div className="p-6">
          <div className="bg-muted h-64 animate-pulse rounded-lg" />
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex flex-col">
        <PageHeader
          breadcrumbs={[
            { label: "Organisations", href: "/admin/orgs" },
            { label: "Not found" },
          ]}
        />
        <div className="text-muted-foreground p-6">Organisation not found.</div>
      </div>
    );
  }

  const { org, apiKeys, members, activeDeviceCount } = data;

  return (
    <div className="flex flex-col">
      <PageHeader
        breadcrumbs={[
          { label: "Organisations", href: "/admin/orgs" },
          { label: org.name },
        ]}
        actions={
          <div className="flex gap-2">
            {org.suspendedAt ? (
              <Button
                size="sm"
                variant="outline"
                className="gap-1.5 text-green-600"
                onClick={() => unsuspend.mutate({ orgId })}
                disabled={unsuspend.isPending}
              >
                <CheckCircle className="h-3.5 w-3.5" />
                Unsuspend
              </Button>
            ) : (
              <Button
                size="sm"
                variant="destructive"
                className="gap-1.5"
                onClick={() => {
                  const reason = suspendReason || "Suspended by admin";
                  suspend.mutate({ orgId, reason });
                }}
                disabled={suspend.isPending}
              >
                <ShieldOff className="h-3.5 w-3.5" />
                Suspend
              </Button>
            )}
          </div>
        }
      />

      <div className="space-y-6 p-6">
        {/* Status banner */}
        {org.suspendedAt && (
          <div className="bg-destructive/10 border-destructive/30 flex items-center gap-2 rounded-lg border px-4 py-3 text-sm">
            <AlertTriangle className="text-destructive h-4 w-4 shrink-0" />
            <span>
              <strong>Suspended</strong>
              {org.suspendedReason ? ` — ${org.suspendedReason}` : ""}
            </span>
          </div>
        )}

        {/* Rotated key banner — show once */}
        {rotatedKey && (
          <div className="bg-yellow-500/10 border-yellow-500/30 space-y-2 rounded-lg border px-4 py-3">
            <p className="text-sm font-medium text-yellow-700 dark:text-yellow-400">
              New API key — copy it now, it won't be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="bg-background text-foreground flex-1 rounded px-2 py-1 font-mono text-xs">
                {rotatedKey}
              </code>
              <Button
                size="sm"
                variant="outline"
                className="gap-1.5"
                onClick={() => void navigator.clipboard.writeText(rotatedKey)}
              >
                <Copy className="h-3.5 w-3.5" />
                Copy
              </Button>
            </div>
            <Button
              size="sm"
              variant="ghost"
              className="text-xs"
              onClick={() => setRotatedKey(null)}
            >
              Dismiss
            </Button>
          </div>
        )}

        {/* Stats row */}
        <div className="grid grid-cols-3 gap-4">
          <StatCard label="Active devices" value={activeDeviceCount} />
          <StatCard label="Members" value={members.length} />
          <StatCard label="API keys" value={apiKeys.length} />
        </div>

        {/* Settings */}
        <Card className="p-4 space-y-4">
          <h2 className="text-sm font-semibold">Settings</h2>

          <div className="flex items-center justify-between">
            <div>
              <Label className="text-sm">Plan</Label>
              <p className="text-muted-foreground text-xs">
                Current plan: <strong>{org.plan}</strong>
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant={org.plan === "free" ? "default" : "outline"}
                onClick={() => setPlan.mutate({ orgId, plan: "free" })}
                disabled={setPlan.isPending}
              >
                Free
              </Button>
              <Button
                size="sm"
                variant={org.plan === "pro" ? "default" : "outline"}
                onClick={() => setPlan.mutate({ orgId, plan: "pro" })}
                disabled={setPlan.isPending}
              >
                Pro
              </Button>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label className="text-sm">Quarantine unscanned updates</Label>
              <p className="text-muted-foreground text-xs">
                Disables extensions that update to an unscanned version until
                the scan completes.
              </p>
            </div>
            <Button
              size="sm"
              variant={org.quarantineUnscannedUpdates ? "default" : "outline"}
              className="gap-1.5"
              onClick={() =>
                setQuarantine.mutate({
                  orgId,
                  enabled: !org.quarantineUnscannedUpdates,
                })
              }
              disabled={setQuarantine.isPending}
            >
              <Shield className="h-3.5 w-3.5" />
              {org.quarantineUnscannedUpdates ? "On" : "Off"}
            </Button>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label className="text-sm">Suspend reason</Label>
              <p className="text-muted-foreground text-xs">
                Set before suspending.
              </p>
            </div>
            <Input
              className="max-w-xs text-sm"
              placeholder="e.g. Payment failed"
              value={suspendReason}
              onChange={(e) => setSuspendReason(e.target.value)}
            />
          </div>
        </Card>

        {/* API Keys */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">API Keys</h2>
          </div>
          <div className="border rounded-lg overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Hash prefix</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {apiKeys.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      className="text-muted-foreground py-8 text-center text-sm"
                    >
                      No API keys
                    </TableCell>
                  </TableRow>
                )}
                {apiKeys.map((key) => (
                  <TableRow key={key.id}>
                    <TableCell className="font-medium text-sm">
                      {key.name}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {key.keyHashPrefix}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {key.lastUsedAt
                        ? formatDate(key.lastUsedAt)
                        : "Never"}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {key.expiresAt ? formatDate(key.expiresAt) : "Never"}
                    </TableCell>
                    <TableCell>
                      {key.revokedAt ? (
                        <Badge variant="secondary">Revoked</Badge>
                      ) : (
                        <Badge variant="outline" className="text-green-600 border-green-600/30">
                          Active
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {!key.revokedAt && (
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 gap-1 text-xs"
                          disabled={rotateApiKey.isPending}
                          onClick={() => {
                            setRotatedKey(null);
                            rotateApiKey.mutate({ apiKeyId: key.id });
                          }}
                        >
                          <RefreshCw className="h-3 w-3" />
                          Rotate
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <div className="flex gap-2">
            <Input
              className="max-w-xs text-sm"
              placeholder="Key name (e.g. Production)"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
            />
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5 shrink-0"
              disabled={!newKeyName.trim()}
              onClick={() => {
                // TODO: admin.orgs.createApiKey once built
              }}
            >
              <KeyRound className="h-3.5 w-3.5" />
              Create key
            </Button>
          </div>
        </div>

        {/* Members */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold">Members</h2>
          <div className="border rounded-lg overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {members.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={3}
                      className="text-muted-foreground py-8 text-center text-sm"
                    >
                      No members
                    </TableCell>
                  </TableRow>
                )}
                {members.map((m) => (
                  <TableRow key={m.id}>
                    <TableCell className="font-medium text-sm">
                      {m.name}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {m.email}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{m.role}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>

        {/* Danger zone */}
        <div className="border-destructive/30 space-y-3 rounded-lg border p-4">
          <h2 className="text-destructive text-sm font-semibold">
            Danger zone
          </h2>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Revoke all devices</p>
              <p className="text-muted-foreground text-xs">
                Immediately kills all device tokens for this org.
              </p>
            </div>
            <Button
              size="sm"
              variant="destructive"
              disabled={revokeAllDevices.isPending}
              onClick={() => {
                if (
                  confirm(
                    `Revoke all devices for ${org.name}? This cannot be undone.`,
                  )
                ) {
                  revokeAllDevices.mutate({ orgId });
                }
              }}
            >
              Revoke all
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <Card className="p-4">
      <p className="text-muted-foreground text-xs">{label}</p>
      <p className="text-foreground text-2xl font-semibold">{value}</p>
    </Card>
  );
}

function formatDate(d: Date | string) {
  return new Date(d).toLocaleDateString("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}
