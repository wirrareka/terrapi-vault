import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { Badge } from "@/components/ui";
import { useSsh } from "@/hooks/use-observe";
import type { SshSerial } from "@/lib/types";

export default function Ssh() {
  const { data, isLoading, error } = useSsh();
  const revoked = new Set((data?.revoked ?? []).map((r) => r.broker + ":" + r.serial));

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
      <PageHeader title="SSH certs" count={data?.issued.length}>
        <span className="text-sm text-muted-foreground">{data?.revoked.length ?? 0} revoked</span>
      </PageHeader>
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={data?.issued}
          rowKey={(s) => s.broker + s.serial}
          isLoading={isLoading}
          error={error}
          emptyText="No issued SSH certs"
        />
      </div>
    </div>
  );
}
