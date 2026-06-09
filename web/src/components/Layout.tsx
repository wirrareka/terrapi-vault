import * as React from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useIsFetching } from "@tanstack/react-query";
import {
  Activity,
  KeyRound,
  ListTree,
  Lock,
  LogOut,
  type LucideIcon,
  Moon,
  ScrollText,
  Server,
  ShieldCheck,
  Sun,
  TerminalSquare,
  Users,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useBrokers } from "@/hooks/use-observe";
import { logout, useMe } from "@/hooks/use-auth";
import { useFilters } from "@/stores/filters";
import { useTheme } from "@/stores/theme";
import { Badge } from "@/components/ui";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

const NAV: NavItem[] = [
  { to: "/", label: "Overview", icon: Activity, end: true },
  { to: "/leases", label: "Leases", icon: ListTree },
  { to: "/sessions", label: "Sessions", icon: Users },
  { to: "/roles", label: "Roles", icon: ShieldCheck },
  { to: "/ssh", label: "SSH certs", icon: TerminalSquare },
  { to: "/kms", label: "KMS", icon: KeyRound },
  { to: "/object-store", label: "Object store", icon: Server },
  { to: "/audit", label: "Audit", icon: ScrollText },
];

export function AppLayout() {
  const { data: brokers } = useBrokers();
  const { data: me } = useMe();
  const fetching = useIsFetching() > 0;
  const broker = useFilters((s) => s.broker);
  const setBroker = useFilters((s) => s.setBroker);
  const theme = useTheme((s) => s.theme);
  const toggleTheme = useTheme((s) => s.toggle);
  const group = brokers?.[0]?.group;
  const reachable = brokers?.filter((b) => b.reachable).length ?? 0;
  const total = brokers?.length ?? 0;

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      <aside className="flex w-60 shrink-0 flex-col border-r">
        <div className="flex items-center gap-2 border-b px-5 py-4">
          <Lock className="h-5 w-5" />
          <div className="flex-1 leading-tight">
            <div className="text-sm font-semibold tracking-tight">vault-console</div>
            <div className="text-xs text-muted-foreground">
              {group ? `${group} group` : "operator view"}
            </div>
          </div>
          {/* Global activity: any in-flight query → a soft pulse. */}
          <span
            className={cn(
              "h-2 w-2 rounded-full transition-opacity",
              fetching ? "animate-pulse bg-green-500 opacity-100" : "opacity-0",
            )}
            aria-label={fetching ? "syncing" : undefined}
            title="syncing"
          />
        </div>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t px-3 py-2">
          <label className="px-1 text-[11px] uppercase tracking-wide text-muted-foreground">Broker</label>
          <select
            value={broker}
            onChange={(e) => setBroker(e.target.value)}
            className="mt-1 flex h-8 w-full rounded-md border border-input bg-transparent px-2 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            <option value="all">All brokers</option>
            {(brokers ?? []).map((b) => (
              <option key={b.id} value={b.id}>
                {b.id}
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-2 border-t px-4 py-3 text-xs text-muted-foreground">
          <div className="flex items-center justify-between">
            <span>Brokers</span>
            <Badge variant={total > 0 && reachable === total ? "success" : "secondary"}>
              {reachable}/{total}
            </Badge>
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="truncate" title={me?.subject}>
              {me ? (me.email ?? me.subject) : "—"}
            </span>
            <div className="flex items-center gap-0.5">
              <button
                type="button"
                onClick={toggleTheme}
                className="flex items-center rounded px-1.5 py-1 hover:bg-accent hover:text-foreground"
                title={theme === "dark" ? "Switch to light" : "Switch to dark"}
                aria-label="Toggle theme"
              >
                {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
              </button>
              <button
                type="button"
                onClick={() => void logout()}
                className="flex items-center rounded px-1.5 py-1 hover:bg-accent hover:text-foreground"
                title="Sign out"
                aria-label="Sign out"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </div>
      </aside>

      <main className="flex flex-1 flex-col overflow-hidden">
        <Outlet />
      </main>
    </div>
  );
}

/** Standard page header (border-b, px-6 py-4): title + optional count badge + right-aligned actions. */
export function PageHeader({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between border-b px-6 py-4">
      <div className="flex items-center gap-2.5">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {count !== undefined && <Badge variant="secondary">{count}</Badge>}
      </div>
      {children && <div className="flex items-center gap-3">{children}</div>}
    </div>
  );
}
