import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRight,
  CheckCircle,
  Copy,
  Link2,
  RefreshCw,
  RotateCcw,
  Webhook,
} from "lucide-react";

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
} from "@amibeingpwned/ui/dialog";

import { useTRPC } from "~/lib/trpc";
import { navigate } from "~/router";

export function SettingsTab({ orgId: _orgId }: { orgId: string }) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();

  // Invite link state
  const { data: inviteLinkData } = useQuery(
    trpc.org.hasInviteLink.queryOptions(),
  );
  const [inviteToken, setInviteToken] = useState<string | null>(null);
  const [inviteCopied, setInviteCopied] = useState(false);
  const [showRotateDialog, setShowRotateDialog] = useState(false);

  const rotateMutation = useMutation(
    trpc.org.rotateInviteLink.mutationOptions({
      onSuccess: (data) => {
        setInviteToken(data.token);
        setShowRotateDialog(false);
        void queryClient.invalidateQueries(
          trpc.org.hasInviteLink.queryFilter(),
        );
      },
    }),
  );

  const inviteUrl = inviteToken
    ? `${window.location.origin}/join/${inviteToken}`
    : null;

  async function copyInviteLink() {
    if (!inviteUrl) return;
    await navigator.clipboard.writeText(inviteUrl);
    setInviteCopied(true);
    setTimeout(() => setInviteCopied(false), 2000);
  }

  return (
    <div className="space-y-4">
      {/* Rotate confirmation dialog */}
      <Dialog open={showRotateDialog} onOpenChange={setShowRotateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate invite link?</DialogTitle>
            <DialogDescription>
              The current link will be revoked immediately. Anyone with the old
              link won't be able to use it.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button
              variant="destructive"
              disabled={rotateMutation.isPending}
              onClick={() => rotateMutation.mutate()}
            >
              {rotateMutation.isPending ? (
                <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
              ) : null}
              Rotate link
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Team Enrollment */}
      <Card
        footerActions={
          inviteToken && inviteUrl
            ? [
                {
                  label: inviteCopied ? "Copied" : "Copy link",
                  icon: inviteCopied ? CheckCircle : Copy,
                  variant: "outline",
                  onClick: () => void copyInviteLink(),
                },
                {
                  label: "Rotate",
                  icon: RotateCcw,
                  variant: "outline",
                  onClick: () => setShowRotateDialog(true),
                },
              ]
            : inviteLinkData?.hasActiveLink
              ? [
                  {
                    label: "Rotate link",
                    icon: RotateCcw,
                    variant: "outline",
                    onClick: () => setShowRotateDialog(true),
                  },
                ]
              : [
                  {
                    label: rotateMutation.isPending
                      ? "Generating..."
                      : "Generate invite link",
                    icon: rotateMutation.isPending ? RefreshCw : Link2,
                    disabled: rotateMutation.isPending,
                    onClick: () => rotateMutation.mutate(),
                  },
                ]
        }
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-4 w-4" />
            Team Enrollment
          </CardTitle>
          <CardDescription>
            Share an invite link with your team. Anyone who clicks it and
            installs the extension is automatically added to your fleet.
          </CardDescription>
        </CardHeader>

        {inviteToken && inviteUrl && (
          <CardContent>
            <code className="bg-muted block overflow-x-auto rounded px-3 py-2 font-mono text-xs">
              {inviteUrl}
            </code>
            <p className="text-muted-foreground mt-2 text-xs">
              Shown once - save it somewhere safe.
            </p>
          </CardContent>
        )}
      </Card>

      {/* Webhooks */}
      <Card
        className="hover:bg-accent/50 cursor-pointer transition-colors"
        onClick={() => navigate("/dashboard/webhooks")}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Webhook className="h-4 w-4" />
            Webhooks
          </CardTitle>
          <CardDescription>
            Send signed event payloads to your servers when threats are
            detected.
          </CardDescription>
          <CardAction>
            <ArrowRight className="text-muted-foreground h-4 w-4" />
          </CardAction>
        </CardHeader>
      </Card>
    </div>
  );
}
