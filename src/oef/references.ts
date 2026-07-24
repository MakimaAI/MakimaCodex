const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

function canonicalMatch(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string"
    && value === value.trim()
    && !CONTROL_CHARACTER_PATTERN.test(value)
    && pattern.test(value);
}

export function isAcceptanceCriterionId(value: unknown): value is string {
  return canonicalMatch(value, /^ac:[A-Za-z0-9][A-Za-z0-9._:-]*$/);
}

export function isHumanId(value: unknown): value is string {
  return canonicalMatch(value, /^human:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
}

export function isServiceId(value: unknown): value is string {
  return canonicalMatch(value, /^service:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
}

export function isApprovalReference(value: unknown): value is string {
  return canonicalMatch(value, /^approval:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
}

export function isEvidenceReference(value: unknown): value is string {
  return canonicalMatch(value, /^artifact:sha256:[a-f0-9]{64}$/);
}

export function isRollbackReference(value: unknown): value is string {
  return canonicalMatch(value, /^(?:git:[a-f0-9]{6,64}|artifact:sha256:[a-f0-9]{64})$/);
}

export function isMemoryRecordId(value: unknown): value is string {
  return canonicalMatch(value, /^memory:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
}

export function isMemoryScope(value: unknown): value is string {
  return canonicalMatch(value, /^(?:task|project|repository|role|agent|model):[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
}
