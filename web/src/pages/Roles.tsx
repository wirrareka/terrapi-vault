import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { Badge } from "@/components/ui";
import { useRoles } from "@/hooks/use-observe";
import type { Role } from "@/lib/types";

export default function Roles() {
  const { data, isLoading, error } = useRoles();

  const columns: Column<Role>[] = [
    { header: "SAN", cell: (r) => <span className="font-mono text-xs">{r.san}</span> },
    { header: "Role", cell: (r) => <span className="font-medium">{r.role}</span> },
    { header: "Broker", cell: (r) => <span className="text-muted-foreground">{r.broker}</span> },
    {
      header: "Capabilities",
      cell: (r) => (
        <div className="flex flex-wrap gap-1">
          {r.caps.map((c) => (
            <Badge key={c} variant="outline">
              {c}
            </Badge>
          ))}
        </div>
      ),
    },
  ];

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Roles" count={data?.roles.length} />
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={data?.roles}
          rowKey={(r) => r.broker + r.san}
          isLoading={isLoading}
          error={error}
          emptyText="No registered roles"
        />
      </div>
    </div>
  );
}
