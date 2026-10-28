import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  hasBlockingErrors,
  validateTemplateContent,
} from "../validate-policy-size";

function template(opts: {
  actions?: string[];
  attached?: number;
  description?: string;
}): string {
  return JSON.stringify({
    Description: opts.description ?? "test",
    Resources: {
      Policy: {
        Type: "AWS::IAM::ManagedPolicy",
        Properties: {
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Resource: "*",
                Action: opts.actions ?? ["s3:Get*"],
              },
            ],
          },
        },
      },
      Role: {
        Type: "AWS::IAM::Role",
        Properties: {
          ManagedPolicyArns: Array.from(
            { length: opts.attached ?? 2 },
            (_, i) => `arn:${i}`,
          ),
        },
      },
    },
  });
}

function limit(content: string, name: string) {
  const check = validateTemplateContent("t.json", content).limits.find(
    (l) => l.name === name,
  );
  assert.ok(check, `missing ${name}`);
  return check;
}

describe("validateTemplateContent", () => {
  it("passes a template within every limit", () => {
    assert.equal(
      hasBlockingErrors(validateTemplateContent("t.json", template({}))),
      false,
    );
  });

  it("fails a policy over 6,144 characters", () => {
    const actions = Array.from(
      { length: 400 },
      (_, i) => `ec2:DescribeThing${i}`,
    );
    const result = validateTemplateContent("t.json", template({ actions }));
    assert.equal(result.policies[0].valid, false);
    assert.equal(hasBlockingErrors(result), true);
  });

  it("allows exactly 10 attached managed policies and fails at 11", () => {
    assert.equal(
      limit(template({ attached: 10 }), "Role managed policies").valid,
      true,
    );
    const result = validateTemplateContent(
      "t.json",
      template({ attached: 11 }),
    );
    assert.equal(hasBlockingErrors(result), true);
  });

  it("only warns past the 51,200-byte direct upload limit", () => {
    const content = template({ description: "x".repeat(52000) });
    const check = limit(content, "template size for direct upload (bytes)");
    assert.equal(check.valid, false);
    assert.equal(check.severity, "warning");
    assert.equal(
      hasBlockingErrors(validateTemplateContent("t.json", content)),
      false,
    );
  });

  it("fails past the 1 MB S3 template limit", () => {
    const content = template({ description: "x".repeat(1048576) });
    assert.equal(
      hasBlockingErrors(validateTemplateContent("t.json", content)),
      true,
    );
  });

  it("reports invalid JSON as an error", () => {
    assert.equal(
      hasBlockingErrors(validateTemplateContent("t.json", "{")),
      true,
    );
  });
});
