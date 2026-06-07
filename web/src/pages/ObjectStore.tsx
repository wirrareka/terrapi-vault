import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { Badge } from "@/components/ui";
import { useObjectStore } from "@/hooks/use-observe";
import { useFiltered } from "@/stores/filters";
import type { ObjectStoreStatus } from "@/lib/types";

export default function ObjectStore() {
  const { data, isLoading, error } = useObjectStore();
  const rows = useFiltered(data?.brokers);

  const columns: Column<ObjectStoreStatus>[] = [
    { header: "Broker", cell: (o) => <span className="font-medium">{o.broker}</span> },
    {
      header: "Presign",
      cell: (o) =>
        o.configured ? <Badge variant="success">configured</Badge> : <Badge variant="secondary">off</Badge>,
    },
  ];

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Object store" count={rows?.length} />
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(o) => o.broker}
          isLoading={isLoading}
          error={error}
          emptyText="No brokers"
        />
      </div>
    </div>
  );
}
