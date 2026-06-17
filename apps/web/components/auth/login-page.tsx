"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { useRouter } from "next/navigation";
import { login } from "../../lib/api";
import {
  CEREBRO_API_RESOURCE,
  CEREBRO_HUMAN_AUTH_MODE
} from "../../lib/cerebro-auth";
import { useAuth } from "./auth-shell";
import { AuthLayout } from "./auth-layout";
import { Button } from "../ui/button";
import { Field, FormBanner, Input } from "../ui/form";

export function LoginPage() {
  const router = useRouter();
  const { refreshSession } = useAuth();
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  const slugId = useId();
  const emailId = useId();
  const passwordId = useId();
  const totpId = useId();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setMessage("");

    try {
      await login({
        organizationSlug: organizationSlug.trim().toLowerCase(),
        email: email.trim().toLowerCase(),
        password,
        totpCode: totpCode.trim() || undefined
      });
      await refreshSession();
      router.replace("/");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to sign in");
    } finally {
      setSaving(false);
    }
  }

  return (
    <AuthLayout
      title="Sign in"
      description={`Use workspace credentials to bind this browser session to ${CEREBRO_API_RESOURCE} as ${CEREBRO_HUMAN_AUTH_MODE}.`}
      showSessionMessaging
      footer={
        <>
          Need a workspace?{" "}
          <Link
            href="/signup"
            className="font-medium text-foreground underline-offset-4 hover:underline"
          >
            Create one
          </Link>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <Field label="Workspace slug" htmlFor={slugId} required>
          <Input
            id={slugId}
            autoComplete="organization"
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

        <Field label="Password" htmlFor={passwordId} required>
          <Input
            id={passwordId}
            type="password"
            autoComplete="current-password"
            placeholder="At least 12 characters"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </Field>

        <Field
          label="Authentication code"
          htmlFor={totpId}
          hint="Only required when MFA is enabled."
        >
          <Input
            id={totpId}
            inputMode="numeric"
            pattern="[0-9]{6}"
            placeholder="123456"
            value={totpCode}
            onChange={(event) =>
              setTotpCode(event.target.value.replace(/\D/g, "").slice(0, 6))
            }
          />
        </Field>

        <FormBanner tone="error">{message}</FormBanner>

        <Button
          type="submit"
          className="w-full"
          loading={saving}
          loadingText="Signing in…"
        >
          Sign in
        </Button>

        <p className="text-center text-xs text-muted-foreground">
          <Link
            href="/forgot-password"
            className="font-medium underline-offset-4 hover:underline"
          >
            Forgot your password?
          </Link>
        </p>
      </form>
    </AuthLayout>
  );
}
