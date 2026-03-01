import { useEffect, useMemo, useState } from "react";
import type { Column, ColumnDef, SortingState } from "@tanstack/react-table";
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import {
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  ArrowUpDown,
  Cloud,
  Monitor,
  RefreshCw,
  Search,
  X,
} from "lucide-react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@amibeingpwned/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@amibeingpwned/ui/dropdown-menu";
import { Input } from "@amibeingpwned/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";
import { Skeleton } from "@amibeingpwned/ui/skeleton";
import { toast } from "@amibeingpwned/ui/toast";

import { useTRPC } from "~/lib/trpc";
import { timeAgo } from "./fleet-types";
import type { FleetOverview } from "./fleet-types";
import { WorkspaceSetupCard } from "./fleet-alerts-tab";

// Types

type FleetDeviceSortBy = "extensionCount" | "flaggedCount" | "lastSeenAt";
type WorkspaceSortBy = "machineName" | "extensionCount" | "lastSyncedAt";

interface DeviceRow {
  id: string;
  displayName: string | null;
  platform: string | null;
  os: string | null;
  arch: string | null;
  identityEmail: string | null;
  extensionCount: number;
  flaggedExtensionCount: number | null;
  lastActivityAt: Date;
}

function DeviceSortableHeader({
  column,
  label,
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  column: Column<DeviceRow, any>;
  label: string;
}) {
  const sorted = column.getIsSorted();
  return (
    <button
      className="hover:text-foreground flex items-center gap-1 text-xs font-medium tracking-wide uppercase"
      onClick={() => column.toggleSorting(sorted === "asc")}
    >
      {label}
      {sorted === "asc" ? (
        <ArrowUp className="h-3 w-3" />
      ) : sorted === "desc" ? (
        <ArrowDown className="h-3 w-3" />
      ) : (
        <ArrowUpDown className="h-3 w-3 opacity-40" />
      )}
    </button>
  );
}

const FLEET_DEV_COL_SORT: Record<string, FleetDeviceSortBy> = {
  extensionCount: "extensionCount",
  flaggedExtensionCount: "flaggedCount",
  lastActivityAt: "lastSeenAt",
};

const WS_DEV_COL_SORT: Record<string, WorkspaceSortBy> = {
  displayName: "machineName",
  extensionCount: "extensionCount",
  lastActivityAt: "lastSyncedAt",
};

function FleetDevicesDataTable() {
  const trpc = useTRPC();
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [sortBy, setSortBy] = useState<FleetDeviceSortBy>("flaggedCount");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [platformFilter, setPlatformFilter] = useState("");

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(searchInput);
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  useEffect(() => {
    setPage(1);
  }, [platformFilter]);

  const { data, isFetching } = useQuery({
    ...trpc.fleet.devices.queryOptions({
      page,
      limit: pageSize,
      search: debouncedSearch || undefined,
      sortBy,
      sortDir,
      platform: platformFilter
        ? (platformFilter as "chrome" | "edge")
        : undefined,
    }),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const rows = useMemo<DeviceRow[]>(
    () =>
      (data?.rows ?? []).map((d) => {
        const displayName =
          d.identityEmail ??
          (d.os && d.arch ? `${d.os} ${d.arch}` : d.os ?? d.arch ?? null);
        return {
          id: d.id,
          displayName,
          platform: d.platform,
          os: d.os ?? null,
          arch: d.arch ?? null,
          identityEmail: d.identityEmail ?? null,
          extensionCount: d.extensionCount,
          flaggedExtensionCount: d.flaggedExtensionCount,
          lastActivityAt: d.lastSeenAt,
        };
      }),
    [data],
  );

  const colId =
    sortBy === "lastSeenAt"
      ? "lastActivityAt"
      : sortBy === "flaggedCount"
        ? "flaggedExtensionCount"
        : sortBy;
  const sorting: SortingState = [{ id: colId, desc: sortDir === "desc" }];

  const columns = useMemo<ColumnDef<DeviceRow>[]>(
    () => [
      {
        accessorKey: "id",
        header: "Device",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-muted-foreground font-mono text-xs">
            {row.original.id.slice(0, 20)}...
          </span>
        ),
      },
      {
        accessorKey: "identityEmail",
        header: "User",
        enableSorting: false,
        cell: ({ row }) => {
          const email = row.original.identityEmail;
          return email ? (
            <span className="text-sm">{email}</span>
          ) : (
            <span className="text-muted-foreground text-xs">-</span>
          );
        },
      },
      {
        accessorKey: "platform",
        header: "Platform",
        enableSorting: false,
        cell: ({ row }) => (
          <Badge variant="outline" className="text-xs capitalize">
            {row.original.platform}
          </Badge>
        ),
      },
      {
        accessorKey: "extensionCount",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Extensions" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-right text-sm tabular-nums">
            {row.original.extensionCount}
          </div>
        ),
      },
      {
        accessorKey: "flaggedExtensionCount",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Flagged" />
          </div>
        ),
        cell: ({ row }) => {
          const flagged = row.original.flaggedExtensionCount ?? 0;
          return (
            <div className="text-right text-sm tabular-nums">
              {flagged > 0 ? (
                <span className="text-destructive font-medium">{flagged}</span>
              ) : (
                <span className="text-muted-foreground">0</span>
              )}
            </div>
          );
        },
      },
      {
        accessorKey: "lastActivityAt",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Last seen" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-muted-foreground text-right text-xs">
            {timeAgo(row.original.lastActivityAt)}
          </div>
        ),
      },
    ],
    [],
  );

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, pagination: { pageIndex: page - 1, pageSize } },
    manualSorting: true,
    manualPagination: true,
    pageCount,
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      const first = next[0];
      if (first) {
        setSortBy(FLEET_DEV_COL_SORT[first.id] ?? "lastSeenAt");
        setSortDir(first.desc ? "desc" : "asc");
        setPage(1);
      }
    },
    onPaginationChange: (updater) => {
      const next =
        typeof updater === "function"
          ? updater({ pageIndex: page - 1, pageSize })
          : updater;
      setPage(next.pageIndex + 1);
      setPageSize(next.pageSize);
    },
    getCoreRowModel: getCoreRowModel(),
  });

  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div className="space-y-2">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="text-muted-foreground absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2" />
          <Input
            className="pl-8 focus-visible:ring-0"
            placeholder="Search by device ID..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          {isFetching && (
            <RefreshCw className="text-muted-foreground absolute top-1/2 right-2.5 h-3.5 w-3.5 -translate-y-1/2 animate-spin" />
          )}
        </div>
        <div className="flex items-center gap-2">
          <select
            value={platformFilter}
            onChange={(e) => setPlatformFilter(e.target.value)}
            className="border-input dark:bg-input/30 rounded-md border bg-transparent px-2 py-[7px] text-xs outline-none"
          >
            <option value="">All platforms</option>
            <option value="chrome">Chrome</option>
            <option value="edge">Edge</option>
          </select>
          {platformFilter && (
            <button
              onClick={() => setPlatformFilter("")}
              className="border-input dark:bg-input/30 text-muted-foreground hover:text-foreground rounded-md border bg-transparent p-[7px] transition-colors"
              title="Clear filters"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      <Card className="overflow-hidden py-0">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id} className="hover:bg-transparent">
                {hg.headers.map((header) => (
                  <TableHead key={header.id} className="h-9 px-3">
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {!data ? (
              Array.from({ length: pageSize }).map((_, i) => (
                <TableRow key={i} className="pointer-events-none">
                  {columns.map((_, j) => (
                    <TableCell key={j} className="px-3">
                      <Skeleton className="h-4 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="text-muted-foreground py-8 text-center text-sm"
                >
                  No devices found.
                </TableCell>
              </TableRow>
            ) : (
              <>
                {table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    className={row.index % 2 === 1 ? "bg-muted/20" : ""}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id} className="px-3">
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext(),
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
                {Array.from({
                  length: Math.max(
                    0,
                    pageSize - table.getRowModel().rows.length,
                  ),
                }).map((_, i) => (
                  <TableRow
                    key={`filler-${i}`}
                    aria-hidden
                    className="pointer-events-none select-none opacity-0"
                  >
                    <TableCell colSpan={columns.length}>&nbsp;</TableCell>
                  </TableRow>
                ))}
              </>
            )}
          </TableBody>
        </Table>
      </Card>

      {total > 0 && (
        <div className="flex items-center justify-between pt-1">
          <span className="text-muted-foreground text-xs">{`Showing ${start}-${end} of ${total}`}</span>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground text-xs">Rows per page</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                >
                  {pageSize} <ArrowDown className="h-3 w-3 opacity-50" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="min-w-16">
                <DropdownMenuRadioGroup
                  value={String(pageSize)}
                  onValueChange={(v) => {
                    setPageSize(Number(v));
                    setPage(1);
                  }}
                >
                  {[10, 25, 50].map((ps) => (
                    <DropdownMenuRadioItem
                      key={ps}
                      value={String(ps)}
                      className="text-xs"
                    >
                      {ps}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
            </Button>
            <span className="text-muted-foreground text-xs tabular-nums">
              {page} / {pageCount}
            </span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function WorkspaceDevicesDataTable() {
  const trpc = useTRPC();
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [sortBy, setSortBy] = useState<WorkspaceSortBy>("extensionCount");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(searchInput);
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const { data, isFetching } = useQuery({
    ...trpc.workspace.devices.queryOptions({
      page,
      limit: pageSize,
      search: debouncedSearch || undefined,
      sortBy,
      sortDir,
    }),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const rows = useMemo<DeviceRow[]>(
    () =>
      (data?.rows ?? []).map((d) => ({
        id: d.googleDeviceId,
        displayName: d.machineName,
        platform: null,
        os: null,
        arch: null,
        identityEmail: null,
        extensionCount: d.extensionCount,
        flaggedExtensionCount: null,
        lastActivityAt: d.lastSyncedAt,
      })),
    [data],
  );

  const wsColId =
    sortBy === "machineName"
      ? "displayName"
      : sortBy === "lastSyncedAt"
        ? "lastActivityAt"
        : sortBy;
  const sorting: SortingState = [{ id: wsColId, desc: sortDir === "desc" }];

  const columns = useMemo<ColumnDef<DeviceRow>[]>(
    () => [
      {
        accessorKey: "displayName",
        header: ({ column }) => (
          <DeviceSortableHeader column={column} label="Machine" />
        ),
        cell: ({ row }) =>
          row.original.displayName ? (
            <span className="text-sm font-medium">
              {row.original.displayName}
            </span>
          ) : (
            <span className="text-muted-foreground font-mono text-xs">
              {row.original.id.slice(0, 20)}...
            </span>
          ),
      },
      {
        accessorKey: "extensionCount",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Extensions" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-right text-sm tabular-nums">
            {row.original.extensionCount}
          </div>
        ),
      },
      {
        accessorKey: "lastActivityAt",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Last synced" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-muted-foreground text-right text-xs">
            {timeAgo(row.original.lastActivityAt)}
          </div>
        ),
      },
    ],
    [],
  );

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, pagination: { pageIndex: page - 1, pageSize } },
    manualSorting: true,
    manualPagination: true,
    pageCount,
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      const first = next[0];
      if (first) {
        setSortBy(WS_DEV_COL_SORT[first.id] ?? "extensionCount");
        setSortDir(first.desc ? "desc" : "asc");
        setPage(1);
      }
    },
    onPaginationChange: (updater) => {
      const next =
        typeof updater === "function"
          ? updater({ pageIndex: page - 1, pageSize })
          : updater;
      setPage(next.pageIndex + 1);
      setPageSize(next.pageSize);
    },
    getCoreRowModel: getCoreRowModel(),
  });

  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div className="space-y-2">
      <div className="relative">
        <Search className="text-muted-foreground absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2" />
        <Input
          className="pl-8 focus-visible:ring-0"
          placeholder="Search by machine name..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />
        {isFetching && (
          <RefreshCw className="text-muted-foreground absolute top-1/2 right-2.5 h-3.5 w-3.5 -translate-y-1/2 animate-spin" />
        )}
      </div>

      <Card className="overflow-hidden py-0">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id} className="hover:bg-transparent">
                {hg.headers.map((header) => (
                  <TableHead key={header.id} className="h-9 px-3">
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {!data ? (
              Array.from({ length: pageSize }).map((_, i) => (
                <TableRow key={i} className="pointer-events-none">
                  {columns.map((_, j) => (
                    <TableCell key={j} className="px-3">
                      <Skeleton className="h-4 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="text-muted-foreground py-8 text-center text-sm"
                >
                  No devices found.
                </TableCell>
              </TableRow>
            ) : (
              <>
                {table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    className={row.index % 2 === 1 ? "bg-muted/20" : ""}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id} className="px-3">
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext(),
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
                {Array.from({
                  length: Math.max(
                    0,
                    pageSize - table.getRowModel().rows.length,
                  ),
                }).map((_, i) => (
                  <TableRow
                    key={`filler-${i}`}
                    aria-hidden
                    className="pointer-events-none select-none opacity-0"
                  >
                    <TableCell colSpan={columns.length}>&nbsp;</TableCell>
                  </TableRow>
                ))}
              </>
            )}
          </TableBody>
        </Table>
      </Card>

      {total > 0 && (
        <div className="flex items-center justify-between pt-1">
          <span className="text-muted-foreground text-xs">{`Showing ${start}-${end} of ${total}`}</span>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground text-xs">Rows per page</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                >
                  {pageSize} <ArrowDown className="h-3 w-3 opacity-50" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="min-w-16">
                <DropdownMenuRadioGroup
                  value={String(pageSize)}
                  onValueChange={(v) => {
                    setPageSize(Number(v));
                    setPage(1);
                  }}
                >
                  {[10, 25, 50].map((ps) => (
                    <DropdownMenuRadioItem
                      key={ps}
                      value={String(ps)}
                      className="text-xs"
                    >
                      {ps}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
            </Button>
            <span className="text-muted-foreground text-xs tabular-nums">
              {page} / {pageCount}
            </span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export function DevicesTab({ overview: _overview }: { overview: FleetOverview }) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const [blockedReason, setBlockedReason] = useState<string | undefined>();

  // Lightweight existence checks - the data tables own their own full queries
  const { data: fleetCheck, isPending: fleetPending } = useQuery(
    trpc.fleet.devices.queryOptions({ page: 1, limit: 1 }),
  );
  const { data: wsCheck, isPending: wsPending } = useQuery(
    trpc.workspace.devices.queryOptions({ page: 1, limit: 1 }),
  );

  const syncMutation = useMutation(
    trpc.workspace.sync.mutationOptions({
      onSuccess: (data) => {
        void queryClient.invalidateQueries(
          trpc.workspace.devices.queryFilter(),
        );
        void queryClient.invalidateQueries(trpc.workspace.apps.queryFilter());
        if (data.appCount === 0) {
          toast.warning(
            "Sync complete but no data yet - Google's API can take a few hours to reflect newly enrolled browsers. Try again later.",
            { duration: 10000 },
          );
        } else {
          toast.success(
            `Sync complete - ${data.appCount} extensions, ${data.deviceCount} devices`,
          );
        }
      },
      onError: (err) => {
        if (err.message.includes("Could not resolve 'my_customer'")) {
          setBlockedReason(
            "This account isn't a Google Workspace super admin, or Chrome Browser Cloud Management (CBCM) isn't enabled on your domain. Contact your Workspace admin.",
          );
        } else {
          const msg =
            err.message.includes("401") || err.message.includes("403")
              ? "Google access denied - try signing out and back in to re-grant permissions."
              : `Sync failed: ${err.message}`;
          toast.error(msg, { duration: 8000 });
        }
      },
    }),
  );

  if (fleetPending || wsPending) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-5 w-5 animate-spin opacity-30" />
      </div>
    );
  }

  const hasFleetDevices = (fleetCheck?.total ?? 0) > 0;
  const hasWorkspaceDevices = (wsCheck?.total ?? 0) > 0;

  if (!hasFleetDevices && !hasWorkspaceDevices) {
    return (
      <WorkspaceSetupCard
        onSync={() => syncMutation.mutate()}
        isSyncing={syncMutation.isPending}
        blockedReason={blockedReason}
      />
    );
  }

  return (
    <div className="space-y-6">
      {hasFleetDevices && (
        <div className="space-y-3">
          <div className="text-muted-foreground flex items-center gap-2 text-sm">
            <Monitor className="h-4 w-4" />
            <span>Devices registered via extension</span>
          </div>
          <FleetDevicesDataTable />
        </div>
      )}

      {hasWorkspaceDevices && (
        <div className="space-y-3">
          <div className="text-muted-foreground flex items-center gap-2 text-sm">
            <Cloud className="h-4 w-4" />
            <span>Chrome browsers enrolled in Google Workspace</span>
          </div>
          <WorkspaceDevicesDataTable />
        </div>
      )}

      {hasFleetDevices && !hasWorkspaceDevices && (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Cloud className="h-4 w-4" />
              Connect Google Workspace
            </CardTitle>
            <CardDescription>
              Also sync managed Chrome browsers via the Chrome Management API
              for fuller device coverage.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              disabled={syncMutation.isPending}
              onClick={() => syncMutation.mutate()}
            >
              <RefreshCw
                className={`h-4 w-4 ${syncMutation.isPending ? "animate-spin" : ""}`}
              />
              {syncMutation.isPending ? "Connecting..." : "Connect & Sync"}
            </Button>
            {blockedReason && (
              <p className="text-destructive mt-2 text-xs">{blockedReason}</p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
