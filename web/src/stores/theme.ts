import { create } from "zustand";

type Theme = "dark" | "light";
const KEY = "vc-theme";

function readInitial(): Theme {
  if (typeof localStorage === "undefined") return "dark";
  return localStorage.getItem(KEY) === "light" ? "light" : "dark";
}
function apply(theme: Theme) {
  if (typeof document !== "undefined") {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }
}

const initial = readInitial();
apply(initial);

interface ThemeState {
  theme: Theme;
  toggle: () => void;
}

export const useTheme = create<ThemeState>((set, get) => ({
  theme: initial,
  toggle: () => {
    const theme: Theme = get().theme === "dark" ? "light" : "dark";
    if (typeof localStorage !== "undefined") localStorage.setItem(KEY, theme);
    apply(theme);
    set({ theme });
  },
}));
