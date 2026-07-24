import { z } from "zod";
import { actorSchema, type Actor } from "../../core/shared/actor";

export const PRINCIPAL_ROLES = ["human_owner", "task_operator", "verifier"] as const;
export type PrincipalRole = typeof PRINCIPAL_ROLES[number];

export const authenticatedPrincipalSchema = z.object({
  actor: actorSchema,
  roles: z.array(z.enum(PRINCIPAL_ROLES)).min(1),
}).strict();

export interface AuthenticatedPrincipal {
  actor: Actor;
  roles: readonly PrincipalRole[];
}

export function parseAuthenticatedPrincipal(input: unknown): AuthenticatedPrincipal {
  return authenticatedPrincipalSchema.parse(input);
}

export function indexAuthenticatedPrincipals(
  principals: readonly AuthenticatedPrincipal[],
): ReadonlyMap<string, AuthenticatedPrincipal> {
  const result = new Map<string, AuthenticatedPrincipal>();
  for (const input of principals) {
    const principal = parseAuthenticatedPrincipal(input);
    if (result.has(principal.actor.id)) throw new Error(`Duplicate authenticated principal: ${principal.actor.id}`);
    result.set(principal.actor.id, principal);
  }
  return result;
}
