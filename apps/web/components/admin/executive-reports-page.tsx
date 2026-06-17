"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Download, FileText, Plus, Trash2, RefreshCw } from "lucide-react";
import {
  createExecutiveReport,
  deleteExecutiveReport,
  fetchExecutiveReports,
  resolveReportArtifactUrl,
  type ExecutiveReportPeriod,
  type ExecutiveReportSummary,
  type ExecutiveReportTemplate
} from "../../lib/api";
import { useAuth } from "../auth/auth-shell";
import { useToast } from "../ui/toast";
import { PageHeader } from "../layout/page-header";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "../ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from "../ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "../ui/table";
import { Skeleton } from "../ui/skeleton";
import { formatDateTime, formatRelative } from "../../lib/format";

const PERIOD_OPTIONS: { value: ExecutiveReportPeriod; label: string; description: string }[] = [
  { value: "WEEK", label: "Last 7 days", description: "Weekly board update" },
  { value: "MONTH", label: "Last 30 days", description: "Monthly CISO digest" },
  { value: "QUARTER", label: "Last 90 days", description: "Quarterly review" }
];

const TEMPLATE_OPTIONS: {
  value: ExecutiveReportTemplate;
  label: string;
  description: string;
}[] = [
  {
    value: "EXECUTIVE_SUMMARY",
    label: "Executive summary",
    description:
      "Cross-vendor SaaS Detection & Response summary with KPIs, MTTR trends, and recommendations for CISOs and the board."
  },
  {
    value: "GOOGLE_WORKSPACE_ASSESSMENT",
    label: "Google Workspace assessment",
    description:
      "Graded review of Google Workspace identity, admin, OAuth, mailbox, sharing, and DWD controls."
  }
];

const TEMPLATE_LABELS: Record<ExecutiveReportTemplate, string> = {
  EXECUTIVE_SUMMARY: "Executive summary",
  GOOGLE_WORKSPACE_ASSESSMENT: "Google Workspace"
};

export function ExecutiveReportsPage() {
  const { session } = useAuth();
  const { toast } = useToast();
  const canManage = session?.user.role === "OWNER" || session?.user.role === "ADMIN";

  const [reports, setReports] = useState<ExecutiveReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generateOpen, setGenerateOpen] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [selectedPeriod, setSelectedPeriod] = useState<ExecutiveReportPeriod>("MONTH");
  const [selectedTemplate, setSelectedTemplate] =
    useState<ExecutiveReportTemplate>("EXECUTIVE_SUMMARY");

  const load = useCallback(async () => {
    if (!canManage) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetchExecutiveReports();
      setReports(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load reports");
    } finally {
      setLoading(false);
    }
  }, [canManage]);

  useEffect(() => {
    void load();
  }, [load]);

  // Poll while any report is GENERATING so the UI moves to READY without manual refresh.
  useEffect(() => {
    if (!canManage) return;
    const anyGenerating = reports.some((r) => r.status === "GENERATING");
    if (!anyGenerating) return;
    const t = setInterval(() => {
      void load();
    }, 4_000);
    return () => clearInterval(t);
  }, [reports, canManage, load]);

  async function handleGenerate() {
    setGenerating(true);
    try {
      const response = await createExecutiveReport({
        period: selectedPeriod,
        template: selectedTemplate
      });
      toast({
        title: "Report queued",
        description: `${response.data.title} is generating.`,
        tone: "success"
      });
      setGenerateOpen(false);
      await load();
    } catch (err) {
      toast({
        title: "Unable to start report",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setGenerating(false);
    }
  }

  async function handleDelete(id: string) {
    if (!window.confirm("Delete this report and its artifacts?")) return;
    try {
      await deleteExecutiveReport(id);
      toast({ title: "Report deleted", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to delete report",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    }
  }

  if (!canManage) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader
          eyebrow="Admin"
          title="Executive reports"
          description="Only workspace owners and admins can generate executive reports."
        />
        <Card>
          <CardContent className="p-6 text-sm text-muted-foreground">
            You don't have permission to view this page.{" "}
            <Link
              href="/settings"
              className="font-medium text-foreground underline-offset-4 hover:underline"
            >
              Back to personal settings
            </Link>
            .
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Admin"
        title="Executive reports"
        description="Generate digestible CISO and board-ready SaaS Detection & Response summaries with trends, narratives, and recommendations. Download as PDF for distribution."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void load()}
              disabled={loading}
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setGenerateOpen(true)}>
              <Plus className="h-3.5 w-3.5" />
              Generate report
            </Button>
          </>
        }
      />

      {error ? (
        <Card>
          <CardContent className="p-4 text-sm text-destructive">{error}</CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Report history</CardTitle>
          <CardDescription>
            Reports persist their HTML and PDF artifacts under the configured export
            directory. Download links require admin session.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex flex-col gap-2">
              <Skeleton className="h-10" />
              <Skeleton className="h-10" />
              <Skeleton className="h-10" />
            </div>
          ) : reports.length === 0 ? (
            <div className="rounded-md border border-dashed border-border/80 p-8 text-center">
              <FileText className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
              <p className="text-sm font-medium text-foreground">No reports yet</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Generate your first executive report to capture current SaaS Detection & Response state and trends.
              </p>
              <Button
                className="mt-4"
                size="sm"
                onClick={() => setGenerateOpen(true)}
              >
                Generate first report
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Report</TableHead>
                  <TableHead>Template</TableHead>
                  <TableHead>Period</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Generated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((report) => (
                  <TableRow key={report.id}>
                    <TableCell>
                      <Link
                        href={`/admin/reports/${report.id}`}
                        className="font-medium text-foreground hover:underline"
                      >
                        {report.title}
                      </Link>
                      {report.summary ? (
                        <p className="mt-0.5 line-clamp-1 text-xs text-muted-foreground">
                          {report.summary}
                        </p>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {TEMPLATE_LABELS[report.template] ?? report.template}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{report.period}</Badge>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {formatDateTime(report.periodStart)} →{" "}
                        {formatDateTime(report.periodEnd)}
                      </div>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={report.status} />
                      {report.status === "FAILED" && report.errorMessage ? (
                        <p className="mt-1 line-clamp-2 text-xs text-destructive">
                          {report.errorMessage}
                        </p>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {report.generatedAt
                        ? formatRelative(report.generatedAt)
                        : report.status === "GENERATING"
                          ? "in progress"
                          : "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="inline-flex items-center gap-1">
                        {(() => {
                          const pdfUrl = resolveReportArtifactUrl(report, "pdf");
                          if (!pdfUrl) return null;
                          return (
                            <Button asChild variant="ghost" size="sm">
                              <a href={pdfUrl} target="_blank" rel="noreferrer">
                                <Download className="h-3.5 w-3.5" />
                                PDF
                              </a>
                            </Button>
                          );
                        })()}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => void handleDelete(report.id)}
                          aria-label="Delete report"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={generateOpen} onOpenChange={setGenerateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate report</DialogTitle>
            <DialogDescription>
              Pick a template and time window. Reports compare against the prior
              equivalent window where applicable.
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-4 py-2">
            <div className="flex flex-col gap-2">
              <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Template
              </div>
              {TEMPLATE_OPTIONS.map((option) => {
                const selected = option.value === selectedTemplate;
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => setSelectedTemplate(option.value)}
                    className={`flex flex-col items-start gap-0.5 rounded-md border p-3 text-left transition-colors ${
                      selected
                        ? "border-primary bg-primary/5"
                        : "border-border hover:border-foreground/30"
                    }`}
                  >
                    <span className="text-sm font-medium text-foreground">
                      {option.label}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {option.description}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="flex flex-col gap-2">
              <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Window
              </div>
              {PERIOD_OPTIONS.map((option) => {
                const selected = option.value === selectedPeriod;
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => setSelectedPeriod(option.value)}
                    className={`flex flex-col items-start gap-0.5 rounded-md border p-3 text-left transition-colors ${
                      selected
                        ? "border-primary bg-primary/5"
                        : "border-border hover:border-foreground/30"
                    }`}
                  >
                    <span className="text-sm font-medium text-foreground">
                      {option.label}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {option.description}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setGenerateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleGenerate} loading={generating} loadingText="Queuing…">
              Generate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function StatusBadge({ status }: { status: ExecutiveReportSummary["status"] }) {
  switch (status) {
    case "READY":
      return <Badge variant="success">Ready</Badge>;
    case "GENERATING":
      return <Badge variant="signal">Generating…</Badge>;
    case "FAILED":
      return <Badge variant="destructive">Failed</Badge>;
  }
}
