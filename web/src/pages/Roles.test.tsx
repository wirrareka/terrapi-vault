import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { RolesResponse } from "@/lib/types";

// Mock the data hook so the page renders without QueryClient/network — validates the full
// page → DataTable → DOM path (incl. the global broker filter passthrough + cap badges).
vi.mock("@/hooks/use-observe", () => ({
  useRoles: (): { data: RolesResponse; isLoading: boolean; error: null } => ({
    data: {
      roles: [
        {
          broker: "vesta-eu-1",
          san: "demon-operator.eu.proximi.internal",
          role: "demon-operator",
          caps: ["ssh-sign", "session"],
        },
      ],
    },
    isLoading: false,
    error: null,
  }),
  useBrokers: () => ({ data: [], isLoading: false }),
}));

import Roles from "./Roles";

describe("Roles page", () => {
  it("renders roles from the hook into the table", () => {
    render(<Roles />);
    expect(screen.getByText("demon-operator")).toBeInTheDocument();
    expect(screen.getByText("demon-operator.eu.proximi.internal")).toBeInTheDocument();
    expect(screen.getByText("ssh-sign")).toBeInTheDocument();
  });
});
