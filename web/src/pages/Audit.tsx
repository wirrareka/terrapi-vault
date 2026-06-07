import { useMemo, useState } from "react";
import { PageHeader } from "@/components/Layout";
import { DataTable, type Column } from "@/components/DataTable";
import { Badge, SearchInput } from "@/components/ui";
import { useAudit } from "@/hooks/use-observe";
import { useFiltered } from "@/stores/filters";
import { matches } from "@/lib/utils";
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
/** The target id (B3 `target.id`) from an event, if present. */
function targetId(ev: Record<string, unknown>): string {
  const t = field(ev, "target");
  return t && typeof t === "object" ? str((t as Record<string, unknown>).id) : "";
}

export default function Audit() {
  // P1: most-recent tail from seq 0 (the console aggregator caps + merges per broker). Cursor
  // paging (?since=next_seq) is a P1-follow refinement.
  const { data, isLoading, error } = useAudit(0, 200);
  const rows = useFiltered(data?.records);
  const [q, setQ] = useState("");
  const shown = useMemo(
    () =>
      (rows ?? []).filter((r) =>
        matches(q, str(field(r.event, "action")), targetId(r.event), r.broker, str(field(r.event, "outcome"))),
      ),
    [rows, q],
  );

  const columns: Column<AuditRecord>[] = [
    { header: "Seq", className: "tabular-nums text-muted-foreground", cell: (r) => r.seq },
    { header: "Time", cell: (r) => <span className="text-xs text-muted-foreground">{str(field(r.event, "ts"))}</span> },
    { header: "Action", cell: (r) => <span className="font-medium">{str(field(r.event, "action"))}</span> },
    {
      header: "Target",
      cell: (r) => <span className="font-mono text-xs text-muted-foreground">{targetId(r.event)}</span>,
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
      <PageHeader title="Audit" count={shown.length}>
        <SearchInput value={q} onChange={setQ} placeholder="Filter audit…" />
      </PageHeader>
      <div className="flex-1 overflow-auto">
        <DataTable
          columns={columns}
          rows={shown}
          rowKey={(r) => r.broker + r.seq}
          isLoading={isLoading}
          error={error}
          emptyText="No audit records"
        />
      </div>
    </div>
  );
}
