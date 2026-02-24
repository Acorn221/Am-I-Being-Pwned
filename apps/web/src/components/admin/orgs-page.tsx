import { useQuery } from "@tanstack/react-query";
import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import { Input } from "@amibeingpwned/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";
import { Building2, Plus, Search } from "lucide-react";
import { useState } from "react";

import { useTRPC } from "~/lib/trpc";
import { navigate } from "~/router";
import { PageHeader } from "./layout";

export function OrgsPage() {
  const trpc = useTRPC();
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery(
    trpc.admin.orgs.list.queryOptions({
      page,
      limit: 20,
      search: search || undefined,
    }),
  );

  return (
    <div className="flex flex-col">
      <PageHeader
        breadcrumbs={[{ label: "Organisations" }]}
        actions={
          <Button size="sm" className="gap-1.5">
            <Plus className="h-3.5 w-3.5" />
            New org
          </Button>
        }
      />

      <div className="p-6 space-y-4">
        <div className="relative max-w-sm">
          <Search className="text-muted-foreground absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2" />
          <Input
            className="pl-9"
            placeholder="Search orgs..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
        </div>

        <div className="border rounded-lg overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Plan</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Quarantine</TableHead>
                <TableHead className="w-24">Devices</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading &&
                Array.from({ length: 5 }).map((_, i) => (
                  <TableRow key={i}>
                    {Array.from({ length: 5 }).map((_, j) => (
                      <TableCell key={j}>
                        <div className="bg-muted h-4 w-24 animate-pulse rounded" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))}

              {!isLoading && data?.rows.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="text-muted-foreground py-12 text-center"
                  >
                    <Building2 className="mx-auto mb-2 h-8 w-8 opacity-30" />
                    No organisations yet
                  </TableCell>
                </TableRow>
              )}

              {data?.rows.map((org) => (
                <TableRow
                  key={org.id}
                  className="cursor-pointer"
                  onClick={() => navigate(`/admin/orgs/${org.id}`)}
                >
                  <TableCell className="font-medium">
                    <div>{org.name}</div>
                    <div className="text-muted-foreground text-xs">
                      {org.slug}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={org.plan === "pro" ? "default" : "secondary"}>
                      {org.plan}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {org.suspendedAt ? (
                      <Badge variant="destructive">Suspended</Badge>
                    ) : (
                      <Badge variant="outline" className="text-green-600 border-green-600/30">
                        Active
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {org.quarantineUnscannedUpdates ? (
                      <Badge variant="outline" className="text-yellow-600 border-yellow-600/30">
                        On
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground text-sm">—</span>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    —
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {data && data.total > 20 && (
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">
              {data.total} orgs total
            </span>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={page === 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={page * 20 >= data.total}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
