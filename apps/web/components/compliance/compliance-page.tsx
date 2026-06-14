"use client";

import * as React from "react";
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Download,
  RefreshCw,
  ShieldCheck,
  XCircle
} from "lucide-react";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { useToast } from "../ui/toast";
import { useAuth } from "../auth/auth-shell";
import {
  exportComplianceReport,
  type ComplianceReportPayload
} from "../../lib/api";
import { cn } from "../../lib/utils";

type ControlStatus = "PASS" | "FAIL" | "PARTIAL" | "NOT_APPLICABLE";

type Control = {
  id: string;
  title: string;
  status: ControlStatus;
  evidenceCount: number;
  owner: string;
};

type ControlGroup = {
  id: string;
  title: string;
  description: string;
  controls: Control[];
};

type Framework = {
  id: string;
  name: string;
  version: string;
  description: string;
  groups: ControlGroup[];
};

const STATUS_TONE: Record<
  ControlStatus,
  { label: string; pill: string; dot: string; icon: React.ComponentType<{ className?: string }> }
> = {
  PASS: {
    label: "Pass",
    pill: "border-success/30 bg-success/15 text-success",
    dot: "bg-success",
    icon: CheckCircle2
  },
  PARTIAL: {
    label: "Partial",
    pill: "border-warning/30 bg-warning/15 text-warning",
    dot: "bg-warning",
    icon: AlertTriangle
  },
  FAIL: {
    label: "Fail",
    pill: "border-destructive/30 bg-destructive/15 text-destructive",
    dot: "bg-destructive",
    icon: XCircle
  },
  NOT_APPLICABLE: {
    label: "N/A",
    pill: "border-muted-foreground/20 bg-muted text-muted-foreground",
    dot: "bg-muted-foreground/40",
    icon: CircleDashed
  }
};

const NIST: Framework = {
  id: "nist-800-53",
  name: "NIST 800-53 Rev. 5",
  version: "rev. 5 · moderate baseline",
  description:
    "Security and privacy controls for federal information systems. Mapped against connector signals, configuration drift, and access reviews.",
  groups: [
    {
      id: "AC",
      title: "Access Control (AC)",
      description: "Account provisioning, separation of duties, session lock.",
      controls: [
        { id: "AC-2", title: "Account Management", status: "PASS", evidenceCount: 18, owner: "Identity team" },
        { id: "AC-3", title: "Access Enforcement", status: "PASS", evidenceCount: 24, owner: "Identity team" },
        { id: "AC-6", title: "Least Privilege", status: "PARTIAL", evidenceCount: 9, owner: "Identity team" },
        { id: "AC-7", title: "Unsuccessful Logon Attempts", status: "PASS", evidenceCount: 14, owner: "SecOps" },
        { id: "AC-17", title: "Remote Access", status: "PARTIAL", evidenceCount: 6, owner: "SecOps" }
      ]
    },
    {
      id: "AU",
      title: "Audit & Accountability (AU)",
      description: "Event logging, tamper-evident audit storage, log review.",
      controls: [
        { id: "AU-2", title: "Event Logging", status: "PASS", evidenceCount: 22, owner: "Platform" },
        { id: "AU-3", title: "Content of Audit Records", status: "PASS", evidenceCount: 22, owner: "Platform" },
        { id: "AU-6", title: "Audit Record Review", status: "PARTIAL", evidenceCount: 7, owner: "SecOps" },
        { id: "AU-9", title: "Protection of Audit Information", status: "PASS", evidenceCount: 12, owner: "Platform" },
        { id: "AU-12", title: "Audit Generation", status: "PASS", evidenceCount: 22, owner: "Platform" }
      ]
    },
    {
      id: "IA",
      title: "Identification & Authentication (IA)",
      description: "User identity proofing, MFA, authenticator management.",
      controls: [
        { id: "IA-2", title: "Identification and Authentication", status: "PASS", evidenceCount: 16, owner: "Identity team" },
        { id: "IA-2(1)", title: "MFA to Privileged Accounts", status: "FAIL", evidenceCount: 3, owner: "Identity team" },
        { id: "IA-5", title: "Authenticator Management", status: "PARTIAL", evidenceCount: 11, owner: "Identity team" },
        { id: "IA-8", title: "Identification for Non-Org Users", status: "PASS", evidenceCount: 9, owner: "Identity team" }
      ]
    },
    {
      id: "CM",
      title: "Configuration Management (CM)",
      description: "Baseline configurations, change control, software inventory.",
      controls: [
        { id: "CM-2", title: "Baseline Configuration", status: "PASS", evidenceCount: 13, owner: "Platform" },
        { id: "CM-6", title: "Configuration Settings", status: "PARTIAL", evidenceCount: 8, owner: "Platform" },
        { id: "CM-7", title: "Least Functionality", status: "PARTIAL", evidenceCount: 6, owner: "Platform" },
        { id: "CM-8", title: "System Component Inventory", status: "PASS", evidenceCount: 17, owner: "IT" }
      ]
    },
    {
      id: "SI",
      title: "System & Information Integrity (SI)",
      description: "Flaw remediation, malicious code protection, monitoring.",
      controls: [
        { id: "SI-2", title: "Flaw Remediation", status: "PARTIAL", evidenceCount: 10, owner: "Platform" },
        { id: "SI-3", title: "Malicious Code Protection", status: "PASS", evidenceCount: 11, owner: "Endpoint" },
        { id: "SI-4", title: "System Monitoring", status: "PASS", evidenceCount: 19, owner: "SecOps" },
        { id: "SI-7", title: "Software, Firmware & Information Integrity", status: "NOT_APPLICABLE", evidenceCount: 0, owner: "—" }
      ]
    },
    {
      id: "SC",
      title: "System & Comms Protection (SC)",
      description: "Boundary protection, cryptography, transmission integrity.",
      controls: [
        { id: "SC-7", title: "Boundary Protection", status: "PASS", evidenceCount: 14, owner: "Platform" },
        { id: "SC-8", title: "Transmission Confidentiality", status: "PASS", evidenceCount: 18, owner: "Platform" },
        { id: "SC-12", title: "Cryptographic Key Establishment", status: "PASS", evidenceCount: 9, owner: "Platform" },
        { id: "SC-28", title: "Protection of Information at Rest", status: "PASS", evidenceCount: 12, owner: "Platform" }
      ]
    }
  ]
};

const CIS: Framework = {
  id: "cis-v8",
  name: "CIS Controls v8",
  version: "v8 · IG1 + IG2",
  description:
    "Center for Internet Security top 18 controls. Connector evidence is auto-mapped to safeguards across each implementation group.",
  groups: [
    {
      id: "01",
      title: "01 · Inventory & Control of Enterprise Assets",
      description: "Hardware, virtual, cloud, and remote assets.",
      controls: [
        { id: "1.1", title: "Detailed asset inventory", status: "PASS", evidenceCount: 17, owner: "IT" },
        { id: "1.2", title: "Address unauthorized assets", status: "PARTIAL", evidenceCount: 6, owner: "IT" }
      ]
    },
    {
      id: "02",
      title: "02 · Inventory & Control of Software Assets",
      description: "Software inventory, allow-listing, unauthorized software removal.",
      controls: [
        { id: "2.1", title: "Software inventory", status: "PASS", evidenceCount: 21, owner: "IT" },
        { id: "2.3", title: "Address unauthorized software", status: "PARTIAL", evidenceCount: 8, owner: "SecOps" },
        { id: "2.5", title: "Allowlist authorized software", status: "FAIL", evidenceCount: 2, owner: "SecOps" }
      ]
    },
    {
      id: "03",
      title: "03 · Data Protection",
      description: "Data inventory, classification, retention, disposal.",
      controls: [
        { id: "3.1", title: "Data management process", status: "PASS", evidenceCount: 9, owner: "GRC" },
        { id: "3.3", title: "Configure data access control lists", status: "PARTIAL", evidenceCount: 11, owner: "Platform" },
        { id: "3.6", title: "Encrypt data on end-user devices", status: "PASS", evidenceCount: 13, owner: "Endpoint" }
      ]
    },
    {
      id: "05",
      title: "05 · Account Management",
      description: "Inventory and lifecycle of accounts and privileges.",
      controls: [
        { id: "5.1", title: "Account inventory", status: "PASS", evidenceCount: 18, owner: "Identity team" },
        { id: "5.3", title: "Disable dormant accounts", status: "PARTIAL", evidenceCount: 5, owner: "Identity team" },
        { id: "5.6", title: "Centralized account management", status: "PASS", evidenceCount: 14, owner: "Identity team" }
      ]
    },
    {
      id: "06",
      title: "06 · Access Control Management",
      description: "Grant, revoke, and review access on a least-privilege basis.",
      controls: [
        { id: "6.3", title: "Require MFA for externally exposed apps", status: "FAIL", evidenceCount: 2, owner: "Identity team" },
        { id: "6.5", title: "Require MFA for admin access", status: "FAIL", evidenceCount: 3, owner: "Identity team" },
        { id: "6.8", title: "Define and maintain role-based access", status: "PARTIAL", evidenceCount: 10, owner: "Identity team" }
      ]
    },
    {
      id: "08",
      title: "08 · Audit Log Management",
      description: "Collect, alert on, and review audit logs.",
      controls: [
        { id: "8.2", title: "Collect audit logs", status: "PASS", evidenceCount: 22, owner: "Platform" },
        { id: "8.5", title: "Collect detailed audit logs", status: "PASS", evidenceCount: 20, owner: "Platform" },
        { id: "8.9", title: "Centralize audit logs", status: "PARTIAL", evidenceCount: 9, owner: "SecOps" }
      ]
    },
    {
      id: "13",
      title: "13 · Network Monitoring & Defense",
      description: "Network-based intrusion detection and response.",
      controls: [
        { id: "13.1", title: "Centralize SIEM alerting", status: "PASS", evidenceCount: 11, owner: "SecOps" },
        { id: "13.6", title: "Collect network traffic flow logs", status: "PARTIAL", evidenceCount: 4, owner: "Network" },
        { id: "13.7", title: "Deploy a host-based intrusion prevention solution", status: "NOT_APPLICABLE", evidenceCount: 0, owner: "—" }
      ]
    },
    {
      id: "17",
      title: "17 · Incident Response Management",
      description: "Incident plan, contact list, and post-incident reviews.",
      controls: [
        { id: "17.1", title: "Designate personnel to manage incidents", status: "PASS", evidenceCount: 4, owner: "GRC" },
        { id: "17.3", title: "Establish an incident response process", status: "PASS", evidenceCount: 5, owner: "GRC" },
        { id: "17.8", title: "Conduct post-incident reviews", status: "PARTIAL", evidenceCount: 3, owner: "GRC" }
      ]
    }
  ]
};

const FRAMEWORKS: Framework[] = [NIST, CIS];

function summarize(framework: Framework) {
  let pass = 0;
  let fail = 0;
  let partial = 0;
  let na = 0;
  let evidence = 0;
  for (const group of framework.groups) {
    for (const c of group.controls) {
      if (c.status === "PASS") pass++;
      else if (c.status === "FAIL") fail++;
      else if (c.status === "PARTIAL") partial++;
      else na++;
      evidence += c.evidenceCount;
    }
  }
  const inScope = pass + fail + partial;
  const score = inScope === 0 ? 0 : Math.round(((pass + partial * 0.5) / inScope) * 100);
  return { pass, fail, partial, na, evidence, total: pass + fail + partial + na, score };
}

function scoreTone(score: number): { text: string; bar: string; ring: string } {
  if (score >= 85) return { text: "text-success", bar: "bg-success", ring: "ring-success/30" };
  if (score >= 60) return { text: "text-warning", bar: "bg-warning", ring: "ring-warning/30" };
  return { text: "text-destructive", bar: "bg-destructive", ring: "ring-destructive/30" };
}

function FrameworkSummaryRow({ framework }: { framework: Framework }) {
  const s = summarize(framework);
  const tone = scoreTone(s.score);
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
      <Card className="md:col-span-1">
        <CardContent className="flex flex-col items-start gap-2 p-4">
          <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Posture score
          </span>
          <span className={cn("text-3xl font-semibold tabular-nums", tone.text)}>
            {s.score}%
          </span>
          <div className="h-1.5 w-full overflow-hidden rounded-sm bg-muted">
            <div className={cn("h-full", tone.bar)} style={{ width: `${s.score}%` }} />
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="flex flex-col gap-1 p-4">
          <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Controls passing
          </span>
          <span className="text-2xl font-semibold tabular-nums text-success">
            {s.pass}
          </span>
          <span className="text-[11px] text-muted-foreground">of {s.total} in scope</span>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="flex flex-col gap-1 p-4">
          <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Partial / gaps
          </span>
          <span className="text-2xl font-semibold tabular-nums text-warning">
            {s.partial}
          </span>
          <span className="text-[11px] text-muted-foreground">need evidence</span>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="flex flex-col gap-1 p-4">
          <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Failing
          </span>
          <span className="text-2xl font-semibold tabular-nums text-destructive">
            {s.fail}
          </span>
          <span className="text-[11px] text-muted-foreground">remediation owed</span>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="flex flex-col gap-1 p-4">
          <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Evidence collected
          </span>
          <span className="text-2xl font-semibold tabular-nums text-foreground">
            {s.evidence}
          </span>
          <span className="text-[11px] text-muted-foreground">artifacts from connectors</span>
        </CardContent>
      </Card>
    </div>
  );
}

function ControlGroupCard({ group }: { group: ControlGroup }) {
  const counts = group.controls.reduce(
    (acc, c) => ({ ...acc, [c.status]: acc[c.status] + 1 }),
    { PASS: 0, FAIL: 0, PARTIAL: 0, NOT_APPLICABLE: 0 } as Record<ControlStatus, number>
  );
  const inScope = counts.PASS + counts.PARTIAL + counts.FAIL;
  const score = inScope === 0 ? 0 : Math.round(((counts.PASS + counts.PARTIAL * 0.5) / inScope) * 100);
  const tone = scoreTone(score);
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-3 p-4 pb-2">
        <div className="flex flex-col gap-1">
          <CardTitle className="flex items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              {group.id}
            </span>
            {group.title}
          </CardTitle>
          <CardDescription>{group.description}</CardDescription>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={cn("text-lg font-semibold tabular-nums", tone.text)}>
            {score}%
          </span>
          <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            {counts.PASS}P · {counts.PARTIAL}△ · {counts.FAIL}F · {counts.NOT_APPLICABLE}N/A
          </span>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ul className="divide-y divide-border">
          {group.controls.map((c) => {
            const tone = STATUS_TONE[c.status];
            const Icon = tone.icon;
            return (
              <li
                key={c.id}
                className="grid grid-cols-[20px_72px_1fr_auto_auto] items-center gap-3 px-4 py-2 text-sm hover:bg-muted/30"
              >
                <Icon
                  className={cn(
                    "h-4 w-4",
                    c.status === "PASS"
                      ? "text-success"
                      : c.status === "PARTIAL"
                        ? "text-warning"
                        : c.status === "FAIL"
                          ? "text-destructive"
                          : "text-muted-foreground"
                  )}
                  aria-hidden
                />
                <span className="font-mono text-[11px] text-muted-foreground">
                  {c.id}
                </span>
                <span className="truncate text-foreground">{c.title}</span>
                <span
                  className={cn(
                    "rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                    tone.pill
                  )}
                >
                  {tone.label}
                </span>
                <span className="hidden font-mono text-[11px] text-muted-foreground sm:inline">
                  {c.evidenceCount > 0 ? `${c.evidenceCount} evidence` : "—"} · {c.owner}
                </span>
              </li>
            );
          })}
        </ul>
      </CardContent>
    </Card>
  );
}

function FrameworkView({ framework }: { framework: Framework }) {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <h2 className="text-base font-semibold text-foreground">
            {framework.name}
          </h2>
          <Badge variant="outline" className="text-[10px] uppercase">
            {framework.version}
          </Badge>
        </div>
        <p className="max-w-3xl text-sm text-muted-foreground">
          {framework.description}
        </p>
      </div>
      <FrameworkSummaryRow framework={framework} />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {framework.groups.map((g) => (
          <ControlGroupCard key={g.id} group={g} />
        ))}
      </div>
    </div>
  );
}

export function CompliancePage() {
  const { session } = useAuth();
  const { toast } = useToast();
  const [exporting, setExporting] = React.useState(false);

  const handleExport = React.useCallback(async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const payload: ComplianceReportPayload = {
        generatedAt: new Date().toISOString(),
        organization: session?.organization.name ?? "Aperio organization",
        frameworks: FRAMEWORKS.map((f) => ({
          id: f.id,
          name: f.name,
          version: f.version,
          description: f.description,
          groups: f.groups.map((g) => ({
            id: g.id,
            title: g.title,
            description: g.description,
            controls: g.controls.map((c) => ({
              id: c.id,
              title: c.title,
              status: c.status,
              evidenceCount: c.evidenceCount,
              owner: c.owner
            }))
          }))
        }))
      };
      const { blob, filename } = await exportComplianceReport(payload);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      // Defer revoke so Safari has time to start the download.
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast({
        title: "Compliance report exported",
        description: filename,
        tone: "success"
      });
    } catch (error) {
      toast({
        title: "Export failed",
        description:
          error instanceof Error ? error.message : "Please try again.",
        tone: "error"
      });
    } finally {
      setExporting(false);
    }
  }, [exporting, session, toast]);

  const overall = React.useMemo(() => {
    const items = FRAMEWORKS.map((f) => ({ name: f.name, summary: summarize(f) }));
    const totalPass = items.reduce((a, b) => a + b.summary.pass, 0);
    const totalFail = items.reduce((a, b) => a + b.summary.fail, 0);
    const totalPartial = items.reduce((a, b) => a + b.summary.partial, 0);
    const totalEvidence = items.reduce((a, b) => a + b.summary.evidence, 0);
    return { items, totalPass, totalFail, totalPartial, totalEvidence };
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Dashboard"
        title="Compliance"
        description="Compliance posture mapped from Aperio connector evidence. Switch frameworks to drill into each control family."
        actions={
          <>
            <Button variant="outline" size="sm">
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              Re-evaluate
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleExport()}
              disabled={exporting}
            >
              <Download className="h-3.5 w-3.5" aria-hidden />
              {exporting ? "Exporting…" : "Export report"}
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <ShieldCheck className="h-5 w-5 text-signal" aria-hidden />
            <div className="flex flex-col">
              <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Frameworks tracked
              </span>
              <span className="text-xl font-semibold tabular-nums">
                {FRAMEWORKS.length}
              </span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <CheckCircle2 className="h-5 w-5 text-success" aria-hidden />
            <div className="flex flex-col">
              <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Controls passing
              </span>
              <span className="text-xl font-semibold tabular-nums text-success">
                {overall.totalPass}
              </span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <AlertTriangle className="h-5 w-5 text-warning" aria-hidden />
            <div className="flex flex-col">
              <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Partial
              </span>
              <span className="text-xl font-semibold tabular-nums text-warning">
                {overall.totalPartial}
              </span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <XCircle className="h-5 w-5 text-destructive" aria-hidden />
            <div className="flex flex-col">
              <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Failing
              </span>
              <span className="text-xl font-semibold tabular-nums text-destructive">
                {overall.totalFail}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue={NIST.id} className="flex flex-col gap-4">
        <TabsList className="self-start">
          {FRAMEWORKS.map((f) => (
            <TabsTrigger key={f.id} value={f.id}>
              {f.name}
            </TabsTrigger>
          ))}
        </TabsList>
        {FRAMEWORKS.map((f) => (
          <TabsContent key={f.id} value={f.id} className="mt-0">
            <FrameworkView framework={f} />
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
