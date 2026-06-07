import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { Badge } from "@/components/ui";
import { useLeases } from "@/hooks/use-observe";
import { fmtUnix, untilExpiry } from "@/lib/utils";
import type { Lease } from "@/lib/types";

export default function Leases() {
  const { data, isLoading, error } = useLeases();
  const now = data?.now ?? Math.floor(Date.now() / 1000);

  const columns: Column<Lease>[] = [
    { header: "Lease", cell: (l) => <span className="font-mono text-xs">{l.lease_id}</span> },
    { header: "Broker", cell: (l) => <span className="text-muted-foreground">{l.broker}</span> },
    {
      header: "Role",
      cell: (l) =>
        l.role ? <Badge variant="secondary">{l.role}</Badge> : <span className="text-muted-foreground">ssh</span>,
    },
    { header: "Renewable", cell: (l) => (l.renewable ? "yes" : "no") },
    {
      header: "Expires",
      className: "tabular-nums",
      cell: (l) => <span title={fmtUnix(l.expires_at)}>{untilExpiry(l.expires_at, now)}</span>,
    },
  ];

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Leases" count={data?.leases.length} />
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={data?.leases}
          rowKey={(l) => l.broker + l.lease_id}
          isLoading={isLoading}
          error={error}
          emptyText="No active leases"
        />
      </div>
    </div>
  );
}
