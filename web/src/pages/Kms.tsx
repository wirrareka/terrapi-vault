import { useMemo, useState } from "react";
import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { SearchInput } from "@/components/ui";
import { useKms } from "@/hooks/use-observe";
import { useFiltered } from "@/stores/filters";
import { matches } from "@/lib/utils";
import type { KmsKey } from "@/lib/types";

export default function Kms() {
  const { data, isLoading, error } = useKms();
  const rows = useFiltered(data?.keys);
  const [q, setQ] = useState("");
  const shown = useMemo(
    () => (rows ?? []).filter((k) => matches(q, k.tenant_id, k.key_id, k.broker)),
    [rows, q],
  );

  const columns: Column<KmsKey>[] = [
    { header: "Tenant", cell: (k) => <span className="font-mono text-xs">{k.tenant_id}</span> },
    { header: "Key", cell: (k) => <span className="font-medium">{k.key_id}</span> },
    { header: "Version", className: "tabular-nums", cell: (k) => `v${k.current_version}` },
    { header: "Broker", cell: (k) => <span className="text-muted-foreground">{k.broker}</span> },
  ];

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="KMS keys" count={shown.length}>
        <SearchInput value={q} onChange={setQ} placeholder="Filter keys…" />
      </PageHeader>
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={shown}
          rowKey={(k) => `${k.broker}/${k.tenant_id}/${k.key_id}`}
          isLoading={isLoading}
          error={error}
          emptyText="No KEK targets"
        />
      </div>
    </div>
  );
}
