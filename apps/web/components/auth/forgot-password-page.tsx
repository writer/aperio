"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { requestPasswordReset } from "../../lib/api";
import { CEREBRO_HUMAN_AUTH_MODE } from "../../lib/cerebro-auth";
import { AuthLayout } from "./auth-layout";
import { useCerebroAuthInsights } from "./use-cerebro-auth-insights";
import { Button } from "../ui/button";
import { Field, FormBanner, Input } from "../ui/form";

export function ForgotPasswordPage() {
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [email, setEmail] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [success, setSuccess] = useState(false);
  const sessionInsights = useCerebroAuthInsights();

  const slugId = useId();
  const emailId = useId();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setMessage("");
    setSuccess(false);

    try {
      await requestPasswordReset({
        organizationSlug: organizationSlug.trim().toLowerCase(),
        email: email.trim().toLowerCase()
      });
      setSuccess(true);
      setMessage("");
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : "Unable to start the password reset"
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <AuthLayout
      title="Reset your password"
      description={`We'll email a one-time reset link for the tenant-bound ${CEREBRO_HUMAN_AUTH_MODE} principal.`}
      showSessionMessaging
      sessionInsights={sessionInsights}
      footer={
        <Link
          href="/login"
          className="font-medium text-foreground underline-offset-4 hover:underline"
        >
          Back to sign in
        </Link>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <Field label="Workspace slug" htmlFor={slugId} required>
          <Input
            id={slugId}
            placeholder="acme-security"
            value={organizationSlug}
            onChange={(event) => setOrganizationSlug(event.target.value)}
            required
          />
        </Field>

        <Field label="Email" htmlFor={emailId} required>
          <Input
            id={emailId}
            type="email"
            autoComplete="email"
            placeholder="owner@acme.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
          />
        </Field>

        <FormBanner tone="error">{message}</FormBanner>
        <FormBanner tone="success">
          {success
            ? "If that workspace and email match, a reset link is on its way."
            : ""}
        </FormBanner>

        <Button
          type="submit"
          className="w-full"
          loading={saving}
          loadingText="Sending…"
        >
          Send reset link
        </Button>
      </form>
    </AuthLayout>
  );
}
