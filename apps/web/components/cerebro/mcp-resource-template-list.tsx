import { cn } from "../../lib/utils";

export type CerebroMCPResourceTemplateView = {
  uriTemplate: string;
  name?: string | null;
  description?: string | null;
  mimeType?: string | null;
};

export function CerebroMCPResourceTemplateList({
  templates,
  className
}: {
  templates?: readonly CerebroMCPResourceTemplateView[] | null;
  className?: string;
}) {
  const visibleTemplates = (templates ?? []).filter((template) =>
    template.uriTemplate.trim()
  );
  if (visibleTemplates.length === 0) {
    return null;
  }

  return (
    <section className={cn("space-y-2", className)}>
      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        MCP resource templates
      </p>
      <ul className="overflow-hidden rounded-md border border-border/70 bg-muted/20">
        {visibleTemplates.map((template) => (
          <li
            key={template.uriTemplate}
            className="border-t border-border/70 px-3 py-2 first:border-t-0"
          >
            <div className="flex flex-wrap items-start justify-between gap-2">
              <span className="min-w-0 text-xs font-medium text-foreground">
                {template.name || "Cerebro resource"}
              </span>
              {template.mimeType ? (
                <span className="shrink-0 rounded border border-border/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                  {template.mimeType}
                </span>
              ) : null}
            </div>
            {template.description ? (
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                {template.description}
              </p>
            ) : null}
            <p className="mt-1 break-all font-mono text-[11px] text-muted-foreground">
              {template.uriTemplate}
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}
