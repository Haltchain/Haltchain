import { useEffect, useState } from "react";

import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { getAuditLog } from "@/lib/admin-api";

export default function AuditLogPage() {
  const [rows, setRows] = useState<unknown[]>([]);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  const load = async () => {
    setLoading(true);
    try {
      const data = await getAuditLog(200);
      setRows(Array.isArray(data.events) ? data.events : []);
    } catch (e) {
      toast({
        title: "Could not load audit log",
        description: e instanceof Error ? e.message : "error",
        variant: "destructive",
      });
      setRows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h1 className="text-2xl">Operator audit log</h1>
            <p className="text-sm text-muted-foreground">
              Recent events from the API audit sink (admin actions, validate summaries). Redaction applies on the server.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            Refresh
          </Button>
        </div>

        {loading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">No events returned (or empty backend log).</p>
        ) : (
          <div className="rounded-md border border-border overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">Preview</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((ev, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs whitespace-pre-wrap break-all max-w-[70vw]">
                      {typeof ev === "string" ? ev : JSON.stringify(ev)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
