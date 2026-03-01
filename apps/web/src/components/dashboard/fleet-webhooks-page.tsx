import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Braces,
  CheckCircle,
  Copy,
  Plus,
  RefreshCw,
  Settings,
  Trash2,
  Webhook,
  Zap,
} from "lucide-react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import {
  Card,
  CardAction,
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
  DialogTrigger,
} from "@amibeingpwned/ui/dialog";
import { Field, FieldGroup, FieldLabel } from "@amibeingpwned/ui/field";
import { Input } from "@amibeingpwned/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";

import { useTRPC } from "~/lib/trpc";
import { navigate } from "~/router";

const THREAT_PAYLOAD_EXAMPLE = JSON.stringify(
  {
    event: "threat.detected",
    timestamp: 1714000000,
    data: {
      deviceId: "dev_abc123",
      platform: "mac",
      threats: [
        {
          extensionName: "Dark Reader",
          chromeExtensionId: "eimadpbcbfnmbkopoojfekhnkhdbieeh",
          riskScore: 87,
          flaggedReason:
            "Reads all browsing history and sends it to a remote server",
        },
      ],
    },
  },
  null,
  2,
);

export function WebhooksPage() {
  const trpc = useTRPC();
  const queryClient = useQueryClient();

  const { data: webhooks, isPending } = useQuery(
    trpc.webhooks.list.queryOptions(),
  );

  const invalidate = () =>
    void queryClient.invalidateQueries(trpc.webhooks.list.queryFilter());

  const deleteMutation = useMutation(
    trpc.webhooks.delete.mutationOptions({ onSuccess: invalidate }),
  );
  const toggleMutation = useMutation(
    trpc.webhooks.setEnabled.mutationOptions({ onSuccess: invalidate }),
  );
  const testMutation = useMutation(trpc.webhooks.test.mutationOptions());

  const [showForm, setShowForm] = useState(false);
  const [formUrl, setFormUrl] = useState("");
  const [formDesc, setFormDesc] = useState("");
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [testedId, setTestedId] = useState<string | null>(null);

  const createMutation = useMutation(
    trpc.webhooks.create.mutationOptions({
      onSuccess: (data) => {
        setNewSecret(data.secret);
        setShowForm(false);
        setFormUrl("");
        setFormDesc("");
        invalidate();
      },
    }),
  );

  async function copySecret(secret: string) {
    await navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-6">
      {/* Back nav */}
      <div>
        <button
          onClick={() => navigate("/dashboard/settings")}
          className="text-muted-foreground hover:text-foreground flex items-center gap-1.5 text-sm transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Settings
        </button>
        <h1 className="mt-3 flex items-center gap-2 text-lg font-semibold">
          <Webhook className="h-5 w-5" />
          Webhooks
        </h1>
      </div>

      {/* New secret Dialog */}
      <Dialog
        open={!!newSecret}
        onOpenChange={(open) => {
          if (!open) setNewSecret(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-emerald-600">
              <CheckCircle className="h-4 w-4" />
              Webhook created - save your secret
            </DialogTitle>
            <DialogDescription>
              This is the only time the full secret will be shown. Copy it now
              and store it securely.
            </DialogDescription>
          </DialogHeader>
          {newSecret && (
            <div className="flex items-center gap-2">
              <code className="bg-muted flex-1 overflow-x-auto rounded px-3 py-2 font-mono text-xs">
                {newSecret}
              </code>
              <Button
                size="sm"
                variant="outline"
                className="shrink-0 gap-1.5"
                onClick={() => void copySecret(newSecret)}
              >
                {copied ? (
                  <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" onClick={() => setNewSecret(null)}>
                I've saved it - dismiss
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Endpoints Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Webhook className="h-4 w-4" />
            Endpoints
          </CardTitle>
          <CardDescription>
            Receive signed POST notifications when security events occur in your
            org.
          </CardDescription>
          <CardAction>
            <Dialog
              open={showForm}
              onOpenChange={(open) => {
                setShowForm(open);
                if (!open) {
                  setFormUrl("");
                  setFormDesc("");
                }
              }}
            >
              <DialogTrigger asChild>
                <Button size="sm" variant="outline" className="gap-1.5">
                  <Plus className="h-3.5 w-3.5" />
                  Add webhook
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>New webhook</DialogTitle>
                  <DialogDescription>
                    Add an HTTPS endpoint to receive signed event payloads.
                  </DialogDescription>
                </DialogHeader>
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="wh-url">Endpoint URL</FieldLabel>
                    <Input
                      id="wh-url"
                      placeholder="https://your-server.example.com/webhooks/aibp"
                      value={formUrl}
                      onChange={(e) => setFormUrl(e.target.value)}
                    />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="wh-desc">
                      Description{" "}
                      <span className="text-muted-foreground font-normal">
                        (optional)
                      </span>
                    </FieldLabel>
                    <Input
                      id="wh-desc"
                      placeholder="e.g. Slack alerts"
                      value={formDesc}
                      onChange={(e) => setFormDesc(e.target.value)}
                    />
                  </Field>
                </FieldGroup>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button size="sm" variant="ghost">
                      Cancel
                    </Button>
                  </DialogClose>
                  <Button
                    size="sm"
                    disabled={!formUrl || createMutation.isPending}
                    onClick={() =>
                      createMutation.mutate({
                        url: formUrl,
                        description: formDesc || undefined,
                        events: ["threat.detected"],
                      })
                    }
                  >
                    {createMutation.isPending ? (
                      <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                    ) : null}
                    Create webhook
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </CardAction>
        </CardHeader>
        <CardContent>
          {isPending && (
            <div className="flex items-center justify-center py-10">
              <RefreshCw className="h-5 w-5 animate-spin opacity-30" />
            </div>
          )}
          {!isPending && (!webhooks || webhooks.length === 0) && (
            <div className="text-muted-foreground flex flex-col items-center gap-2 py-10">
              <Webhook className="h-8 w-8 opacity-20" />
              <p className="text-sm">No webhooks configured yet.</p>
              <p className="text-xs">
                Add one to start receiving real-time event notifications.
              </p>
            </div>
          )}
          {webhooks && webhooks.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-[148px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {webhooks.map((wh) => (
                  <TableRow
                    key={wh.id}
                    className={!wh.enabled ? "opacity-50" : ""}
                  >
                    <TableCell>
                      <div className="space-y-0.5">
                        <p className="font-mono text-xs">{wh.url}</p>
                        {wh.description && (
                          <p className="text-muted-foreground text-xs">
                            {wh.description}
                          </p>
                        )}
                        <p className="text-muted-foreground font-mono text-[10px]">
                          {wh.secretMasked}
                        </p>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={wh.enabled ? "default" : "secondary"}>
                        {wh.enabled ? "Active" : "Disabled"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        {/* Test */}
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 gap-1 px-2 text-xs"
                          disabled={testMutation.isPending || !wh.enabled}
                          title="Send test event"
                          onClick={() => {
                            setTestedId(wh.id);
                            testMutation.mutate(
                              { webhookId: wh.id },
                              {
                                onSettled: () =>
                                  setTimeout(() => setTestedId(null), 2000),
                              },
                            );
                          }}
                        >
                          {testedId === wh.id ? (
                            <CheckCircle className="h-3 w-3 text-emerald-500" />
                          ) : (
                            <Zap className="h-3 w-3" />
                          )}
                          Test
                        </Button>
                        {/* Toggle */}
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 px-2 text-xs"
                          disabled={toggleMutation.isPending}
                          onClick={() =>
                            toggleMutation.mutate({
                              webhookId: wh.id,
                              enabled: !wh.enabled,
                            })
                          }
                        >
                          {wh.enabled ? "Disable" : "Enable"}
                        </Button>
                        {/* Delete */}
                        <Dialog>
                          <DialogTrigger asChild>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="text-muted-foreground hover:text-destructive h-7 w-7 p-0"
                              title="Delete webhook"
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </DialogTrigger>
                          <DialogContent>
                            <DialogHeader>
                              <DialogTitle>Delete webhook?</DialogTitle>
                              <DialogDescription>
                                This will permanently remove{" "}
                                <span className="text-foreground font-mono">
                                  {wh.url}
                                </span>
                                . Any deliveries in flight may still arrive.
                              </DialogDescription>
                            </DialogHeader>
                            <DialogFooter>
                              <DialogClose asChild>
                                <Button variant="outline">Cancel</Button>
                              </DialogClose>
                              <DialogClose asChild>
                                <Button
                                  variant="destructive"
                                  disabled={deleteMutation.isPending}
                                  onClick={() =>
                                    deleteMutation.mutate({ webhookId: wh.id })
                                  }
                                >
                                  {deleteMutation.isPending ? (
                                    <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                                  ) : null}
                                  Delete
                                </Button>
                              </DialogClose>
                            </DialogFooter>
                          </DialogContent>
                        </Dialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Event payloads Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Braces className="h-4 w-4" />
            Event payloads
          </CardTitle>
          <CardDescription>
            Your endpoint receives a POST with this JSON body whenever a flagged
            extension is detected on a device in your org.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="bg-muted overflow-x-auto rounded p-3 font-mono text-[11px] leading-relaxed">
            {THREAT_PAYLOAD_EXAMPLE}
          </pre>
        </CardContent>
      </Card>

      {/* Verifying signatures Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            Verifying signatures
          </CardTitle>
          <CardDescription>
            Every delivery includes an{" "}
            <code className="bg-muted rounded px-1 py-0.5 text-xs">
              X-AIBP-Signature
            </code>{" "}
            header. Verify it with HMAC-SHA256 to confirm the payload came from
            us and wasn't tampered with.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="bg-muted overflow-x-auto rounded p-3 font-mono text-[11px] leading-relaxed">{`// Node.js / Express example
import { createHmac, timingSafeEqual } from "crypto";

function verifySignature(secret, rawBody, header) {
  const [tPart, v1Part] = header.split(",");
  const timestamp = tPart.replace("t=", "");
  const expected  = v1Part.replace("v1=", "");

  const mac = createHmac("sha256", secret)
    .update(\`\${timestamp}.\${rawBody}\`)
    .digest("hex");

  return timingSafeEqual(
    Buffer.from(mac),
    Buffer.from(expected),
  );
}`}</pre>
        </CardContent>
      </Card>
    </div>
  );
}
