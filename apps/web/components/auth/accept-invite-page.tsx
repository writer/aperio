"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { acceptInvite } from "../../lib/api";
import { CEREBRO_API_RESOURCE } from "../../lib/cerebro-auth";
import { useAuth } from "./auth-shell";
import { AuthLayout } from "./auth-layout";
import { useCerebroAuthInsights } from "./use-cerebro-auth-insights";
import { Button } from "../ui/button";
import { Field, FormBanner, Input } from "../ui/form";

export function AcceptInvitePage() {
  const params = useSearchParams();
  const router = useRouter();
  const { refreshSession } = useAuth();
  const token = params.get("token") ?? "";

  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const sessionInsights = useCerebroAuthInsights({ loadDiscovery: !token });

  const nameId = useId();
  const passwordId = useId();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setMessage("");
    try {
      await acceptInvite({
        token,
        displayName: displayName.trim() || undefined,
        password
      });
      await refreshSession();
      router.replace("/");
    } catch (error) {
      setMessage(
        error instanceof Error ? error.message : "Unable to accept invite"
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <AuthLayout
      title="Accept invite"
      description={`Finish creating your tenant principal before Aperio issues a scoped ${CEREBRO_API_RESOURCE} session.`}
      showSessionMessaging
      sessionInsights={sessionInsights}
      footer={
        <Link
          href="/login"
          className="font-medium text-foreground underline-offset-4 hover:underline"
        >
          Already onboarded? Sign in
        </Link>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <Field label="Display name" htmlFor={nameId}>
          <Input
            id={nameId}
            autoComplete="name"
            placeholder="Taylor Owner"
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
          />
        </Field>
        <Field
          label="Password"
          htmlFor={passwordId}
          hint="At least 12 characters."
          required
        >
          <Input
            id={passwordId}
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </Field>
        <FormBanner tone="error">{message}</FormBanner>
        {!token ? (
          <FormBanner tone="error">
            Invitation token missing. Use the link from your email.
          </FormBanner>
        ) : null}
        <Button
          type="submit"
          className="w-full"
          loading={saving}
          loadingText="Joining…"
          disabled={!token}
        >
          Accept invite
        </Button>
      </form>
    </AuthLayout>
  );
}
