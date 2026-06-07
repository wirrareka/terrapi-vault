import * as React from "react";
import { Spinner, Table, Td, Th } from "@/components/ui";
import { cn } from "@/lib/utils";

export interface Column<T> {
  header: string;
  cell: (row: T) => React.ReactNode;
  className?: string;
}

/**
 * State-aware read-only table: handles loading / error / empty / data uniformly (the
 * three-state pattern), so each observe page is just `columns` + `rows`.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  isLoading,
  error,
  emptyText = "Nothing to show",
}: {
  columns: Column<T>[];
  rows: T[] | undefined;
  rowKey: (row: T, i: number) => string;
  isLoading: boolean;
  error?: unknown;
  emptyText?: string;
}) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <Spinner />
      </div>
    );
  }
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
        <p className="text-base text-destructive">Failed to load</p>
        <p className="text-sm mt-1">{error instanceof Error ? error.message : String(error)}</p>
      </div>
    );
  }
  const data = rows ?? [];
  if (data.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
        <p className="text-base">{emptyText}</p>
      </div>
    );
  }
  return (
    <Table>
      <thead className="border-b">
        <tr>
          {columns.map((c) => (
            <Th key={c.header} className={c.className}>
              {c.header}
            </Th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={rowKey(row, i)} className="border-b last:border-0 hover:bg-muted/50">
            {columns.map((c) => (
              <Td key={c.header} className={cn("text-sm", c.className)}>
                {c.cell(row)}
              </Td>
            ))}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
