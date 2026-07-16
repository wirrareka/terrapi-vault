/**
 * Federated `./Module` entry for vesta-console (the M5 module-federation pilot).
 *
 * This is the CHROME-LESS mode: the beast-shell host owns the persistent
 * sidebar/topbar, so here we render only vesta's own content + a slim in-module
 * sub-nav. The module brings its OWN react-router (v6) mounted under the
 * host-provided `basePath` — the host is on react-router v7, and they do NOT
 * share a router; only react/react-dom are shared singletons. Deep links like
 * `/m/vesta/leases` resolve inside this router.
 *
 * Standalone mode (own login + full AppLayout chrome) still ships from
 * `src/main.tsx`, unchanged. Build the two modes with the same source; the
 * federated build is gated by `VITE_FEDERATED=1` (see vite.config.ts).
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  NavLink,
  Outlet,
  RouterProvider,
  createBrowserRouter,
} from "react-router-dom";
import type { ReactNode } from "react";
import {
  Activity,
  KeyRound,
  ListTree,
  ScrollText,
  Server,
  ShieldCheck,
  TerminalSquare,
  Users,
  type LucideIcon,
} from "lucide-react";
import {
  HostProvider,
  defineRemoteModule,
  type HostContext,
} from "@terrapi/ui/federation";

import Dashboard from "@/pages/Dashboard";
import Leases from "@/pages/Leases";
import Sessions from "@/pages/Sessions";
import Roles from "@/pages/Roles";
import Ssh from "@/pages/Ssh";
import Kms from "@/pages/Kms";
import ObjectStore from "@/pages/ObjectStore";
import Audit from "@/pages/Audit";
import { NotFound, RouteError } from "@/components/RouteError";
import "@/index.css";

interface Item {
  path: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

// Single source of truth for both the router children and the route manifest
// the host reads (meta.routes below).
const ITEMS: Item[] = [
  { path: "", label: "Overview", icon: Activity, end: true },
  { path: "leases", label: "Leases", icon: ListTree },
  { path: "sessions", label: "Sessions", icon: Users },
  { path: "roles", label: "Roles", icon: ShieldCheck },
  { path: "ssh", label: "SSH certs", icon: TerminalSquare },
  { path: "kms", label: "KMS", icon: KeyRound },
  { path: "object-store", label: "Object store", icon: Server },
  { path: "audit", label: "Audit", icon: ScrollText },
];

const ELEMENTS: Record<string, ReactNode> = {
  "": <Dashboard />,
  leases: <Leases />,
  sessions: <Sessions />,
  roles: <Roles />,
  ssh: <Ssh />,
  kms: <Kms />,
  "object-store": <ObjectStore />,
  audit: <Audit />,
};

/** Chrome-less shell: slim sub-nav (host owns the outer chrome) + content. */
function ChromelessLayout() {
  return (
    <div className="flex h-full flex-col">
      <nav className="flex gap-1 overflow-x-auto border-b px-4 py-2">
        {ITEMS.map(({ path, label, icon: Icon, end }) => (
          <NavLink
            key={path}
            to={path === "" ? "" : path}
            end={end ?? path === ""}
            className={({ isActive }) =>
              [
                "flex items-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1.5 text-sm",
                isActive
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:bg-muted",
              ].join(" ")
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="min-h-0 flex-1 overflow-auto">
        <Outlet />
      </div>
    </div>
  );
}

/** The mount component the host renders. Receives the live host context. */
function VestaModule({ host }: { host: HostContext }) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: 1, staleTime: 5_000, refetchOnWindowFocus: false },
    },
  });

  // Own router, mounted under the host-provided base path so deep links work.
  const router = createBrowserRouter(
    [
      {
        path: "/",
        element: <ChromelessLayout />,
        errorElement: <RouteError />,
        children: [
          ...ITEMS.filter((it) => it.path !== "").map(({ path }) => ({
            path,
            element: ELEMENTS[path],
          })),
          { index: true as const, element: ELEMENTS[""] },
          { path: "*", element: <NotFound /> },
        ],
      },
    ],
    { basename: host.basePath },
  );

  return (
    <HostProvider value={host}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </HostProvider>
  );
}

export default defineRemoteModule({
  meta: {
    name: "vesta",
    label: "Vesta",
    routes: ITEMS.map(({ path, label, icon }) => ({
      path,
      label,
      icon: icon.displayName ?? undefined,
      nav: true,
    })),
  },
  mount: VestaModule,
});
