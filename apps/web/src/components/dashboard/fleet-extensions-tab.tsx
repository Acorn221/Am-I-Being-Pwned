import type {
  Column,
  ColumnDef,
  Row,
  SortingState,
} from "@tanstack/react-table";
import { useEffect, useMemo, useState } from "react";
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
  AlertTriangle,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  ArrowUpDown,
  CheckCircle,
  Cloud,
  Puzzle,
  RefreshCw,
  Search,
  X,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import {
  Card,
  CardAction,
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
import { Skeleton } from "@amibeingpwned/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";
import { toast } from "@amibeingpwned/ui/toast";

import { useTRPC } from "~/lib/trpc";
import { WorkspaceSetupCard } from "./fleet-alerts-tab";
import { RiskScore } from "./fleet-shared";
import { timeAgo } from "./fleet-types";

// Types

interface ExtRow {
  chromeExtensionId: string;
  displayName: string | null;
  installType: string | null | undefined;
  flaggedReason: string | null | undefined;
  riskScore: number | null;
  isFlagged: boolean | null;
  deviceCount: number;
  enabledCount?: number;
}

function SortableHeader({
  column,
  label,
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  column: Column<ExtRow, any>;
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

type SortBy = "name" | "riskScore" | "deviceCount";
type RiskLevel = "all" | "low" | "medium" | "high";

// Maps TanStack column IDs to the sortBy param the server expects
const COLUMN_TO_SORT: Record<string, SortBy> = {
  displayName: "name",
  riskScore: "riskScore",
  deviceCount: "deviceCount",
};

const INSTALL_TYPE_LABELS: Record<string, string> = {
  FORCED: "Forced",
  ADMIN: "Admin",
  NORMAL: "User",
  DEVELOPMENT: "Dev",
  SIDELOAD: "Sideloaded",
  OTHER: "Other",
  UNKNOWN: "Unknown",
};

function InstallTypeChip({ type }: { type: string | null }) {
  const label = INSTALL_TYPE_LABELS[type ?? ""] ?? type ?? "Unknown";
  const isForced = type === "FORCED" || type === "ADMIN";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold tracking-wide uppercase ${
        isForced
          ? "border border-blue-500/30 bg-blue-500/15 text-blue-600"
          : "bg-muted text-muted-foreground"
      }`}
    >
      {label}
    </span>
  );
}

function ExtensionsDataTable({
  source,
  showInstallType = false,
}: {
  source: "fleet" | "workspace";
  showInstallType?: boolean;
}) {
  const trpc = useTRPC();

  // Filter / sort / pagination state
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [sortBy, setSortBy] = useState<SortBy>("riskScore");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [showFlaggedOnly, setShowFlaggedOnly] = useState(false);
  const [riskFilter, setRiskFilter] = useState<RiskLevel>("all");
  const [installTypeFilter, setInstallTypeFilter] = useState("");
  const [onlyEnabled, setOnlyEnabled] = useState(false);

  // Debounce search - reset to page 1 when it fires
  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(searchInput);
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
  }, [showFlaggedOnly, riskFilter, installTypeFilter, onlyEnabled]);

  const sharedParams = {
    page,
    limit: pageSize,
    search: debouncedSearch || undefined,
    sortBy,
    sortDir,
    isFlagged: showFlaggedOnly ? true : undefined,
    riskLevel: riskFilter === "all" ? undefined : riskFilter,
  } as const;

  const fleetQuery = useQuery({
    ...trpc.fleet.extensions.queryOptions({
      ...sharedParams,
      onlyEnabled: onlyEnabled ? true : undefined,
    }),
    enabled: source === "fleet",
    placeholderData: keepPreviousData,
  });

  const workspaceQuery = useQuery({
    ...trpc.workspace.apps.queryOptions({
      ...sharedParams,
      installType: installTypeFilter || undefined,
    }),
    enabled: source === "workspace",
    placeholderData: keepPreviousData,
  });

  const activeQuery = source === "fleet" ? fleetQuery : workspaceQuery;
  const isFetching = activeQuery.isFetching;
  const total = activeQuery.data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const rows = useMemo<ExtRow[]>(() => {
    if (source === "fleet") {
      return (fleetQuery.data?.rows ?? []).map((r) => ({
        chromeExtensionId: r.chromeExtensionId,
        displayName: r.name,
        installType: undefined,
        flaggedReason: undefined,
        riskScore: r.riskScore,
        isFlagged: r.isFlagged,
        deviceCount: r.deviceCount,
        enabledCount: r.enabledCount,
      }));
    }
    return (workspaceQuery.data?.rows ?? []).map((r) => ({
      chromeExtensionId: r.chromeExtensionId,
      displayName: r.displayName,
      installType: r.installType,
      flaggedReason: r.flaggedReason,
      riskScore: r.riskScore,
      isFlagged: r.isFlagged,
      deviceCount: r.browserDeviceCount,
    }));
  }, [source, fleetQuery.data, workspaceQuery.data]);

  const columns = useMemo<ColumnDef<ExtRow>[]>(() => {
    const cols: ColumnDef<ExtRow>[] = [
      {
        accessorKey: "displayName",
        header: ({ column }) => (
          <SortableHeader column={column} label="Extension" />
        ),
        cell: ({ row }) => {
          const r = row.original;
          return (
            <div className="flex min-w-0 items-center gap-2">
              {r.isFlagged && (
                <AlertTriangle className="text-destructive h-3.5 w-3.5 shrink-0" />
              )}
              <div className="min-w-0">
                <p
                  className={`truncate text-sm font-medium ${r.isFlagged ? "text-destructive" : ""}`}
                >
                  {r.displayName ?? r.chromeExtensionId}
                </p>
                {r.flaggedReason && (
                  <p className="text-muted-foreground truncate text-xs">
                    {r.flaggedReason}
                  </p>
                )}
              </div>
            </div>
          );
        },
      },
      ...(showInstallType
        ? [
            {
              accessorKey: "installType" as const,
              header: "Install type",
              enableSorting: false,
              cell: ({ row }: { row: Row<ExtRow> }) => (
                <InstallTypeChip type={row.original.installType ?? null} />
              ),
            },
          ]
        : []),
      {
        accessorKey: "riskScore",
        header: ({ column }) => <SortableHeader column={column} label="Risk" />,
        cell: ({ row }) => <RiskScore score={row.original.riskScore ?? 0} />,
      },
      {
        accessorKey: "deviceCount",
        header: ({ column }) => (
          <div className="text-right">
            <SortableHeader column={column} label="Devices" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-right text-sm font-medium tabular-nums">
            {row.original.deviceCount}
          </div>
        ),
      },
      ...(source === "fleet"
        ? [
            {
              accessorKey: "enabledCount" as const,
              header: () => (
                <div className="text-right text-xs font-medium tracking-wide uppercase">
                  Enabled
                </div>
              ),
              enableSorting: false,
              cell: ({ row }: { row: Row<ExtRow> }) => {
                const { enabledCount, deviceCount } = row.original;
                if (enabledCount === undefined) return null;
                return (
                  <div className="text-right">
                    <span className="text-muted-foreground text-xs tabular-nums">
                      {enabledCount}/{deviceCount}
                    </span>
                  </div>
                );
              },
            },
          ]
        : []),
    ];
    return cols;
  }, [source, showInstallType]);

  const sorting: SortingState = [
    {
      id: sortBy === "name" ? "displayName" : sortBy,
      desc: sortDir === "desc",
    },
  ];

  const table = useReactTable({
    data: rows,
    columns,
    state: {
      sorting,
      pagination: { pageIndex: page - 1, pageSize },
    },
    manualSorting: true,
    manualPagination: true,
    pageCount,
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      const first = next[0];
      if (first) {
        setSortBy(COLUMN_TO_SORT[first.id] ?? "deviceCount");
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

  const hasActiveFilters =
    showFlaggedOnly ||
    riskFilter !== "all" ||
    installTypeFilter !== "" ||
    onlyEnabled;
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div className="space-y-2">
      {/* Toolbar */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="text-muted-foreground absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2" />
          <Input
            className="pl-8 focus-visible:ring-0"
            placeholder="Search by name or ID..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          {isFetching && (
            <RefreshCw className="text-muted-foreground absolute top-1/2 right-2.5 h-3.5 w-3.5 -translate-y-1/2 animate-spin" />
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFlaggedOnly(!showFlaggedOnly)}
            className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[7px] text-xs font-medium transition-colors ${
              showFlaggedOnly
                ? "border-destructive/50 bg-destructive/10 text-destructive"
                : "border-input text-muted-foreground hover:text-foreground dark:bg-input/30 bg-transparent"
            }`}
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            Flagged
          </button>
          {source === "fleet" && (
            <button
              onClick={() => setOnlyEnabled(!onlyEnabled)}
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[7px] text-xs font-medium transition-colors ${
                onlyEnabled
                  ? "border-green-500/50 bg-green-500/10 text-green-600 dark:text-green-400"
                  : "border-input text-muted-foreground hover:text-foreground dark:bg-input/30 bg-transparent"
              }`}
            >
              <CheckCircle className="h-3.5 w-3.5" />
              Enabled
            </button>
          )}
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value as typeof riskFilter)}
            className="border-input dark:bg-input/30 rounded-md border bg-transparent px-2 py-[7px] text-xs outline-none"
          >
            <option value="all">All risks</option>
            <option value="low">Low+</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
          </select>
          {showInstallType && (
            <select
              value={installTypeFilter}
              onChange={(e) => setInstallTypeFilter(e.target.value)}
              className="border-input dark:bg-input/30 rounded-md border bg-transparent px-2 py-[7px] text-xs outline-none"
            >
              <option value="">All types</option>
              <option value="FORCED">Forced</option>
              <option value="ADMIN">Admin</option>
              <option value="NORMAL">User</option>
              <option value="DEVELOPMENT">Dev</option>
              <option value="SIDELOAD">Sideloaded</option>
            </select>
          )}
          {hasActiveFilters && (
            <button
              onClick={() => {
                setShowFlaggedOnly(false);
                setRiskFilter("all");
                setInstallTypeFilter("");
                setOnlyEnabled(false);
              }}
              className="border-input dark:bg-input/30 text-muted-foreground hover:text-foreground rounded-md border bg-transparent p-[7px] transition-colors"
              title="Clear filters"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Table */}
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
            {!activeQuery.data ? (
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
                  No extensions match your filters.
                </TableCell>
              </TableRow>
            ) : (
              <>
                {table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    className={
                      row.original.isFlagged
                        ? "border-l-destructive bg-destructive/5 border-l-2"
                        : row.index % 2 === 1
                          ? "bg-muted/20"
                          : ""
                    }
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
                    className="pointer-events-none opacity-0 select-none"
                  >
                    <TableCell colSpan={columns.length}>&nbsp;</TableCell>
                  </TableRow>
                ))}
              </>
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between pt-1">
          <span className="text-muted-foreground text-xs">
            {`Showing ${start}-${end} of ${total}`}
          </span>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground text-xs">Rows per page</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                >
                  {pageSize}
                  <ArrowDown className="h-3 w-3 opacity-50" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="min-w-[4rem]">
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

export function ExtensionsTab() {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const [blockedReason, setBlockedReason] = useState<string | undefined>();

  // Lightweight existence checks - the tables own their own full queries
  const { data: appsData, isPending: appsLoading } = useQuery(
    trpc.workspace.apps.queryOptions({ page: 1, limit: 1 }),
  );

  const { data: fleetExtData, isPending: fleetLoading } = useQuery(
    trpc.fleet.extensions.queryOptions({ page: 1, limit: 1 }),
  );

  // Check if there are any fleet devices registered (even with no extensions yet)
  const { data: fleetDeviceCheck, isPending: fleetDeviceLoading } = useQuery(
    trpc.fleet.devices.queryOptions({ page: 1, limit: 1 }),
  );

  const syncMutation = useMutation(
    trpc.workspace.sync.mutationOptions({
      onSuccess: (data) => {
        void queryClient.invalidateQueries(trpc.workspace.apps.queryFilter());
        void queryClient.invalidateQueries(
          trpc.workspace.devices.queryFilter(),
        );
        if (data.appCount === 0) {
          toast.warning(
            "Sync complete but no data yet, Google's API can take a few hours to reflect newly enrolled browsers. Try again later.",
            { duration: 10000 },
          );
        } else {
          toast.success(
            `Sync complete, ${data.appCount} extensions, ${data.deviceCount} devices`,
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
              ? "Google access denied, try signing out and back in to re-grant permissions."
              : `Sync failed: ${err.message}`;
          toast.error(msg, { duration: 8000 });
        }
      },
    }),
  );

  const isSyncing = syncMutation.isPending;
  const isPending = appsLoading || fleetLoading || fleetDeviceLoading;

  const hasWorkspaceData = (appsData?.rows.length ?? 0) > 0;
  const hasFleetData = (fleetExtData?.rows.length ?? 0) > 0;
  const hasFleetDevices = (fleetDeviceCheck?.total ?? 0) > 0;

  if (isPending) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-5 w-5 animate-spin opacity-30" />
      </div>
    );
  }

  if (!hasWorkspaceData && !hasFleetData && !hasFleetDevices) {
    const syncedButEmpty = appsData?.lastSyncedAt !== null;
    return (
      <WorkspaceSetupCard
        onSync={() => syncMutation.mutate()}
        isSyncing={isSyncing}
        blockedReason={blockedReason}
        syncedButEmpty={syncedButEmpty}
      />
    );
  }

  return (
    <div className="space-y-8">
      {/* Extension agent section */}
      {hasFleetDevices && !hasFleetData && (
        <div className="rounded-lg border border-dashed px-6 py-8 text-center">
          <Puzzle className="text-muted-foreground mx-auto mb-3 h-8 w-8" />
          <p className="text-sm font-medium">
            Extension connected, no extensions detected yet
          </p>
          <p className="text-muted-foreground mt-1 text-sm">
            The browser extension is registered. Extension inventory will appear
            here after the next sync.
          </p>
        </div>
      )}
      {hasFleetData && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Puzzle className="text-muted-foreground h-4 w-4" />
            <span className="text-sm font-medium">Installed Extensions</span>
          </div>
          <ExtensionsDataTable source="fleet" />
        </div>
      )}

      {/* Google Workspace section */}
      {hasWorkspaceData && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cloud className="text-muted-foreground h-4 w-4" />
              <span className="text-sm font-medium">Google Workspace</span>
              {appsData?.lastSyncedAt ? (
                <span className="text-muted-foreground text-xs">
                  - last synced {timeAgo(appsData.lastSyncedAt)}
                </span>
              ) : isSyncing ? (
                <span className="text-muted-foreground flex items-center gap-1 text-xs">
                  <RefreshCw className="h-3 w-3 animate-spin" />
                  Syncing...
                </span>
              ) : (
                <span className="text-muted-foreground text-xs">
                  - never synced
                </span>
              )}
            </div>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              disabled={isSyncing}
              onClick={() => syncMutation.mutate()}
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${isSyncing ? "animate-spin" : ""}`}
              />
              {isSyncing ? "Syncing..." : "Sync now"}
            </Button>
          </div>
          <ExtensionsDataTable source="workspace" showInstallType />
        </div>
      )}

      {/* Workspace setup nudge when only fleet data exists */}
      {hasFleetData && !hasWorkspaceData && (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Cloud className="h-4 w-4" />
              Connect Google Workspace
            </CardTitle>
            <CardDescription>
              Sync managed Chrome browsers via the Chrome Management API for
              install type info and per-device extension policies.
            </CardDescription>
            <CardAction>
              <Button
                size="sm"
                variant="outline"
                disabled={isSyncing}
                onClick={() => syncMutation.mutate()}
              >
                <RefreshCw
                  className={`h-3.5 w-3.5 ${isSyncing ? "animate-spin" : ""}`}
                />
                {isSyncing ? "Syncing..." : "Sync"}
              </Button>
            </CardAction>
          </CardHeader>
        </Card>
      )}
    </div>
  );
}
