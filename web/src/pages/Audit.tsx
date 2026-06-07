import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { Badge } from "@/components/ui";
import { useAudit } from "@/hooks/use-observe";
import type { AuditRecord } from "@/lib/types";

/** Safe string read of an unknown JSON value. */
function str(v: unknown): string {
  if (v == null) return "";
  return typeof v === "string" ? v : JSON.stringify(v);
}
/** Read a nested field from the B3 event object. */
function field(ev: Record<string, unknown>, key: string): unknown {
  return ev[key];
}

export default function Audit() {
  // P1: most-recent tail from seq 0 (the console aggregator caps + merges per broker). Cursor
  // paging (?since=next_seq) is a P1-follow refinement.
  const { data, isLoading, error } = useAudit(0, 200);

  const columns: Column<AuditRecord>[] = [
    { header: "Seq", className: "tabular-nums text-muted-foreground", cell: (r) => r.seq },
    { header: "Time", cell: (r) => <span className="text-xs text-muted-foreground">{str(field(r.event, "ts"))}</span> },
    { header: "Action", cell: (r) => <span className="font-medium">{str(field(r.event, "action"))}</span> },
    {
      header: "Target",
      cell: (r) => {
        const target = field(r.event, "target");
        const id = target && typeof target === "object" ? (target as Record<string, unknown>).id : undefined;
        return <span className="font-mono text-xs text-muted-foreground">{str(id)}</span>;
      },
    },
    {
      header: "Outcome",
      cell: (r) => {
        const o = str(field(r.event, "outcome")).toLowerCase();
        return o.includes("succ") ? <Badge variant="success">{o}</Badge> : <Badge variant="destructive">{o || "?"}</Badge>;
      },
    },
    { header: "Broker", cell: (r) => <span className="text-muted-foreground">{r.broker}</span> },
  ];

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Audit" count={data?.records.length} />
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={data?.records}
          rowKey={(r) => r.broker + r.seq}
          isLoading={isLoading}
          error={error}
          emptyText="No audit records"
        />
      </div>
    </div>
  );
}
