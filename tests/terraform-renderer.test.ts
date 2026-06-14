import assert from "node:assert/strict";
import test from "node:test";
import {
  terraformAttribute,
  terraformBlock,
  terraformExpression,
  terraformString,
  terraformValue
} from "../packages/shared/src/terraform";

test("Terraform renderer escapes literal interpolation by default", () => {
  assert.equal(terraformString("literal ${not_a_var}"), "\"literal $${not_a_var}\"");
  assert.equal(terraformString("literal %{ if true }"), "\"literal %%{ if true }\"");
  assert.equal(
    terraformAttribute("value", "literal ${not_a_var} %{ if true }"),
    "value = \"literal $${not_a_var} %%{ if true }\""
  );
});

test("Terraform renderer preserves explicit expressions", () => {
  assert.equal(
    terraformAttribute("member", terraformExpression('"serviceAccount:${google_service_account.reader.email}"')),
    'member = "serviceAccount:${google_service_account.reader.email}"'
  );
});

test("Terraform renderer handles nested maps and quoted keys", () => {
  assert.equal(
    terraformValue({
      "google.subject": "assertion.sub",
      enabled: true
    }),
    '{\n  "google.subject" = "assertion.sub"\n  enabled = true\n}'
  );
});

test("Terraform renderer emits labeled blocks", () => {
  assert.equal(
    terraformBlock("resource", ["google_project_service", "required"], "project = var.project_id"),
    'resource "google_project_service" "required" {\n  project = var.project_id\n}\n'
  );
});
