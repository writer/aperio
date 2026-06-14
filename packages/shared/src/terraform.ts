export type TerraformExpression = {
  readonly kind: "terraform-expression";
  readonly value: string;
};

export type TerraformValue =
  | string
  | number
  | boolean
  | null
  | TerraformExpression
  | TerraformValue[]
  | { [key: string]: TerraformValue };

export function terraformExpression(value: string): TerraformExpression {
  return { kind: "terraform-expression", value };
}

export function terraformString(value: string) {
  return JSON.stringify(
    value.replaceAll("${", () => "$${").replaceAll("%{", () => "%%{")
  );
}

export function terraformValue(value: TerraformValue, depth = 0): string {
  if (isTerraformExpression(value)) {
    return value.value;
  }
  if (typeof value === "string") {
    return terraformString(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const innerIndent = indent(depth + 1);
    const outerIndent = indent(depth);
    return `[\n${value
      .map((item) => `${innerIndent}${terraformValue(item, depth + 1)},`)
      .join("\n")}\n${outerIndent}]`;
  }
  const entries = Object.entries(value);
  if (entries.length === 0) return "{}";
  const innerIndent = indent(depth + 1);
  const outerIndent = indent(depth);
  return `{\n${entries
    .map(
      ([key, item]) =>
        `${innerIndent}${terraformMapKey(key)} = ${terraformValue(item, depth + 1)}`
    )
    .join("\n")}\n${outerIndent}}`;
}

export function terraformAttribute(name: string, value: TerraformValue, depth = 0) {
  return `${indent(depth)}${name} = ${terraformValue(value, depth)}`;
}

export function terraformBlock(type: string, labels: string[], body: string) {
  const labelText = labels.map((label) => ` ${terraformString(label)}`).join("");
  const trimmed = body.trim();
  return `${type}${labelText} {\n${trimmed ? indentLines(trimmed, 2) + "\n" : ""}}\n`;
}

export function terraformResource(type: string, name: string, body: string) {
  return terraformBlock("resource", [type, name], body);
}

export function terraformVariable(name: string, body: string) {
  return terraformBlock("variable", [name], body);
}

export function terraformOutput(name: string, body: string) {
  return terraformBlock("output", [name], body);
}

export function indentLines(value: string, spaces: number) {
  const prefix = " ".repeat(spaces);
  return value
    .split("\n")
    .map((line) => (line ? prefix + line : line))
    .join("\n");
}

function indent(depth: number) {
  return "  ".repeat(depth);
}

function terraformMapKey(key: string) {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(key) ? key : terraformString(key);
}

function isTerraformExpression(value: TerraformValue): value is TerraformExpression {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    "kind" in value &&
    value.kind === "terraform-expression"
  );
}
