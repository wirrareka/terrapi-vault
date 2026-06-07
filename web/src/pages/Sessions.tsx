import { useMemo, useState } from "react";
import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { SearchInput } from "@/components/ui";
import { useSessions } from "@/hooks/use-observe";
import { useFiltered } from "@/stores/filters";
import { fmtUnix, matches, untilExpiry } from "@/lib/utils";
import type { Session } from "@/lib/types";

export default function Sessions() {
  const { data, isLoading, error } = useSessions();
  const rows = useFiltered(data?.sessions);
  const [q, setQ] = useState("");
  const shown = useMemo(
    () => (rows ?? []).filter((s) => matches(q, s.session_id, s.principal, s.broker)),
    [rows, q],
  );
  const now = data?.now ?? Math.floor(Date.now() / 1000);

  const columns: Column<Session>[] = [
    { header: "Session", cell: (s) => <span className="font-mono text-xs">{s.session_id}</span> },
    {
      header: "Principal",
      cell: (s) => s.principal ?? <span className="text-muted-foreground">—</span>,
    },
    { header: "Broker", cell: (s) => <span className="text-muted-foreground">{s.broker}</span> },
    { header: "Leases", className: "tabular-nums", cell: (s) => s.child_count },
    {
      header: "Expires",
      className: "tabular-nums",
      cell: (s) => <span title={fmtUnix(s.expires_at)}>{untilExpiry(s.expires_at, now)}</span>,
    },
  ];

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Sessions" count={shown.length}>
        <SearchInput value={q} onChange={setQ} placeholder="Filter sessions…" />
      </PageHeader>
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={shown}
          rowKey={(s) => s.broker + s.session_id}
          isLoading={isLoading}
          error={error}
          emptyText="No active sessions"
        />
      </div>
    </div>
  );
}
