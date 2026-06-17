"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { useRouter } from "next/navigation";
import { signup } from "../../lib/api";
import { CEREBRO_API_RESOURCE } from "../../lib/cerebro-auth";
import { useAuth } from "./auth-shell";
import { AuthLayout } from "./auth-layout";
import { useCerebroAuthInsights } from "./use-cerebro-auth-insights";
import { Button } from "../ui/button";
import { Field, FormBanner, Input } from "../ui/form";

function normalizeWorkspaceSlug(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-")
    .replace(/[^a-z0-9-]/g, "")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 120);
}

export function SignupPage() {
  const router = useRouter();
  const { refreshSession } = useAuth();
  const [organizationName, setOrganizationName] = useState("");
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [ownerEmail, setOwnerEmail] = useState("");
  const [ownerDisplayName, setOwnerDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const sessionInsights = useCerebroAuthInsights();

  const nameId = useId();
  const slugId = useId();
  const emailId = useId();
  const displayNameId = useId();
  const passwordId = useId();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setMessage("");

    try {
      await signup({
        organizationName: organizationName.trim(),
        organizationSlug: normalizeWorkspaceSlug(organizationSlug),
        ownerEmail: ownerEmail.trim().toLowerCase(),
        ownerDisplayName: ownerDisplayName.trim() || undefined,
        password
      });
      await refreshSession();
      router.replace("/");
    } catch (error) {
      setMessage(
        error instanceof Error ? error.message : "Unable to create workspace"
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <AuthLayout
      title="Create a workspace"
      description={`Provision a tenant, owner principal, and role model for ${CEREBRO_API_RESOURCE} sessions.`}
      showSessionMessaging
      sessionInsights={sessionInsights}
      footer={
        <>
          Already have one?{" "}
          <Link
            href="/login"
            className="font-medium text-foreground underline-offset-4 hover:underline"
          >
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <Field label="Company name" htmlFor={nameId} required>
          <Input
            id={nameId}
            placeholder="Acme Security"
            value={organizationName}
            onChange={(event) => {
              const next = event.target.value;
              setOrganizationName(next);
              if (!slugEdited) {
                setOrganizationSlug(normalizeWorkspaceSlug(next));
              }
            }}
            required
          />
        </Field>

        <Field
          label="Workspace slug"
          htmlFor={slugId}
          hint="Lowercase letters, numbers, and hyphens only."
          required
        >
          <Input
            id={slugId}
            placeholder="acme-security"
            value={organizationSlug}
            onChange={(event) => {
              setSlugEdited(true);
              setOrganizationSlug(normalizeWorkspaceSlug(event.target.value));
            }}
            required
          />
        </Field>

        <Field label="Email" htmlFor={emailId} required>
          <Input
            id={emailId}
            type="email"
            autoComplete="email"
            placeholder="owner@acme.com"
            value={ownerEmail}
            onChange={(event) => setOwnerEmail(event.target.value)}
            required
          />
        </Field>

        <Field label="Display name" htmlFor={displayNameId}>
          <Input
            id={displayNameId}
            autoComplete="name"
            placeholder="Taylor Owner"
            value={ownerDisplayName}
            onChange={(event) => setOwnerDisplayName(event.target.value)}
          />
        </Field>

        <Field
          label="Password"
          htmlFor={passwordId}
          hint="At least 12 characters with upper, lower, and a number."
          required
        >
          <Input
            id={passwordId}
            type="password"
            autoComplete="new-password"
            placeholder="At least 12 characters"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </Field>

        <FormBanner tone="error">{message}</FormBanner>

        <Button
          type="submit"
          className="w-full"
          loading={saving}
          loadingText="Creating…"
        >
          Create workspace
        </Button>
      </form>
    </AuthLayout>
  );
}
