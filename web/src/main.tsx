import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { AppLayout } from "@/components/Layout";
import Dashboard from "@/pages/Dashboard";
import Leases from "@/pages/Leases";
import Sessions from "@/pages/Sessions";
import Roles from "@/pages/Roles";
import Ssh from "@/pages/Ssh";
import Kms from "@/pages/Kms";
import ObjectStore from "@/pages/ObjectStore";
import Audit from "@/pages/Audit";
import "@/index.css";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 5_000, refetchOnWindowFocus: false } },
});

const router = createBrowserRouter([
  {
    path: "/",
    element: <AppLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "leases", element: <Leases /> },
      { path: "sessions", element: <Sessions /> },
      { path: "roles", element: <Roles /> },
      { path: "ssh", element: <Ssh /> },
      { path: "kms", element: <Kms /> },
      { path: "object-store", element: <ObjectStore /> },
      { path: "audit", element: <Audit /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
);
