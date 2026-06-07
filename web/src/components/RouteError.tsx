import { isRouteErrorResponse, Link, useRouteError } from "react-router-dom";

/** Router `errorElement`: renders an uncaught render/loader error without a white screen. */
export function RouteError() {
  const error = useRouteError();
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : error instanceof Error
      ? error.message
      : "Unexpected error";

  return (
    <div className="flex h-screen flex-col items-center justify-center gap-3 bg-background text-foreground">
      <p className="text-lg font-semibold">Something went wrong</p>
      <p className="text-sm text-muted-foreground">{message}</p>
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to overview
      </Link>
    </div>
  );
}

/** Catch-all 404. */
export function NotFound() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground">
      <p className="text-lg">Page not found</p>
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to overview
      </Link>
    </div>
  );
}
