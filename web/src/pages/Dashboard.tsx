import { PageHeader } from "@/components/Layout";
import { Badge, Card, CardContent, CardHeader, CardTitle, Spinner } from "@/components/ui";
import { useBrokers, useLeases, useSessions } from "@/hooks/use-observe";

export default function Dashboard() {
  const brokers = useBrokers();
  const leases = useLeases();
  const sessions = useSessions();

  const reachable = brokers.data?.filter((b) => b.reachable).length ?? 0;
  const sealed = brokers.data?.filter((b) => b.sealed).length ?? 0;

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Overview" />
      <div className="flex-1 overflow-auto p-6">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Stat title="Brokers reachable" value={`${reachable}/${brokers.data?.length ?? 0}`} loading={brokers.isLoading} />
          <Stat title="Sealed" value={String(sealed)} loading={brokers.isLoading} warn={sealed > 0} />
          <Stat title="Active leases" value={String(leases.data?.leases.length ?? 0)} loading={leases.isLoading} />
          <Stat title="Active sessions" value={String(sessions.data?.sessions.length ?? 0)} loading={sessions.isLoading} />
        </div>

        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Brokers</CardTitle>
          </CardHeader>
          <CardContent>
            {brokers.isLoading ? (
              <Spinner />
            ) : (
              <div className="space-y-2">
                {(brokers.data ?? []).map((b) => (
                  <div key={b.id} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                    <div>
                      <span className="font-medium">{b.id}</span>{" "}
                      <span className="text-muted-foreground">{b.addr}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {b.version && <span className="text-xs text-muted-foreground">{b.version}</span>}
                      {b.sealed && <Badge variant="outline">sealed</Badge>}
                      <Badge variant={b.reachable ? "success" : "destructive"}>
                        {b.reachable ? "up" : "down"}
                      </Badge>
                    </div>
                  </div>
                ))}
                {(brokers.data ?? []).length === 0 && (
                  <p className="text-sm text-muted-foreground">No brokers configured.</p>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Stat({ title, value, loading, warn }: { title: string; value: string; loading: boolean; warn?: boolean }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-semibold tabular-nums ${warn ? "text-destructive" : ""}`}>
          {loading ? "—" : value}
        </div>
      </CardContent>
    </Card>
  );
}
