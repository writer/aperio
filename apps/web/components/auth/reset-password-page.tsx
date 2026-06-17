"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { resetPassword } from "../../lib/api";
import { CEREBRO_HUMAN_AUTH_MODE } from "../../lib/cerebro-auth";
import { useAuth } from "./auth-shell";
import { AuthLayout } from "./auth-layout";
import { Button } from "../ui/button";
import { Field, FormBanner, Input } from "../ui/form";

export function ResetPasswordPage() {
  const params = useSearchParams();
  const router = useRouter();
  const { refreshSession } = useAuth();
  const token = params.get("token") ?? "";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  const passwordId = useId();
  const confirmId = useId();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (password !== confirm) {
      setMessage("Passwords do not match.");
      return;
    }
    setSaving(true);
    setMessage("");
    try {
      await resetPassword({ token, password });
      await refreshSession();
      router.replace("/");
    } catch (error) {
      setMessage(
        error instanceof Error ? error.message : "Unable to reset password"
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <AuthLayout
      title="Set a new password"
      description={`Your token is single-use; the next session is reissued as ${CEREBRO_HUMAN_AUTH_MODE}.`}
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
        <Field
          label="New password"
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
        <Field label="Confirm new password" htmlFor={confirmId} required>
          <Input
            id={confirmId}
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            required
          />
        </Field>
        <FormBanner tone="error">{message}</FormBanner>
        {!token ? (
          <FormBanner tone="error">
            Reset token missing. Use the link from your email.
          </FormBanner>
        ) : null}
        <Button
          type="submit"
          className="w-full"
          loading={saving}
          loadingText="Saving…"
          disabled={!token}
        >
          Save password
        </Button>
      </form>
    </AuthLayout>
  );
}
