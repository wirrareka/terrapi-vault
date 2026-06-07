import { create } from "zustand";

// The console aggregates N brokers per group; a global broker filter narrows every observe view.
// "all" = no filter.
interface FilterState {
  broker: string;
  setBroker: (broker: string) => void;
}

export const useFilters = create<FilterState>((set) => ({
  broker: "all",
  setBroker: (broker) => set({ broker }),
}));

/** Narrow a broker-tagged row list by the active global broker filter. */
export function useFiltered<T extends { broker: string }>(rows: T[] | undefined): T[] | undefined {
  const broker = useFilters((s) => s.broker);
  if (!rows || broker === "all") return rows;
  return rows.filter((r) => r.broker === broker);
}
