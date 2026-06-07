import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DataTable, type Column } from "./DataTable";

interface Row {
  broker: string;
  name: string;
}
const columns: Column<Row>[] = [{ header: "Name", cell: (r) => r.name }];
const rowKey = (r: Row) => r.name;

describe("DataTable", () => {
  it("shows a spinner while loading", () => {
    render(<DataTable columns={columns} rows={undefined} rowKey={rowKey} isLoading />);
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  it("shows the empty text when there are no rows", () => {
    render(<DataTable columns={columns} rows={[]} rowKey={rowKey} isLoading={false} emptyText="None here" />);
    expect(screen.getByText("None here")).toBeInTheDocument();
  });

  it("surfaces an error message", () => {
    render(
      <DataTable
        columns={columns}
        rows={undefined}
        rowKey={rowKey}
        isLoading={false}
        error={new Error("boom")}
      />,
    );
    expect(screen.getByText("boom")).toBeInTheDocument();
  });

  it("renders rows", () => {
    render(
      <DataTable
        columns={columns}
        rows={[{ broker: "b1", name: "alpha" }]}
        rowKey={rowKey}
        isLoading={false}
      />,
    );
    expect(screen.getByText("alpha")).toBeInTheDocument();
  });
});
