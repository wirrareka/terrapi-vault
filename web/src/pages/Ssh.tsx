import { useMemo, useState } from "react";
import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { Badge, SearchInput } from "@/components/ui";
import { useSsh } from "@/hooks/use-observe";
import { useFiltered } from "@/stores/filters";
import { matches } from "@/lib/utils";
import type { SshSerial } from "@/lib/types";

export default function Ssh() {
  const { data, isLoading, error } = useSsh();
  const rows = useFiltered(data?.issued);
  const revoked = new Set((data?.revoked ?? []).map((r) => r.broker + ":" + r.serial));
  const [q, setQ] = useState("");
  const shown = useMemo(
    () => (rows ?? []).filter((s) => matches(q, String(s.serial), s.lease_id, s.broker)),
    [rows, q],
  );

  const columns: Column<SshSerial>[] = [
    { header: "Serial", className: "tabular-nums", cell: (s) => s.serial },
    { header: "Lease", cell: (s) => <span className="font-mono text-xs">{s.lease_id}</span> },
    { header: "Broker", cell: (s) => <span className="text-muted-foreground">{s.broker}</span> },
    {
      header: "Status",
      cell: (s) =>
        revoked.has(s.broker + ":" + s.serial) ? (
          <Badge variant="destructive">revoked</Badge>
        ) : (
          <Badge variant="success">valid</Badge>
        ),
    },
  ];

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="SSH certs" count={shown.length}>
        <span className="text-sm text-muted-foreground">{data?.revoked.length ?? 0} revoked</span>
        <SearchInput value={q} onChange={setQ} placeholder="Filter certs…" />
      </PageHeader>
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={shown}
          rowKey={(s) => s.broker + s.serial}
          isLoading={isLoading}
          error={error}
          emptyText="No issued SSH certs"
        />
      </div>
    </div>
  );
}
