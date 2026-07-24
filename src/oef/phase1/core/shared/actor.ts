import { z } from "zod";

const actorId = z.string().trim().min(1).max(200).refine(value => !/[\u0000-\u001f\u007f]/.test(value));

export const actorSchema = z.object({
  type: z.enum(["human", "agent", "system", "integration", "scheduler"]),
  id: actorId,
  model_ref: z.string().trim().min(1).max(300).optional(),
  runtime_ref: z.string().trim().min(1).max(300).optional(),
}).strict();

export type Actor = z.infer<typeof actorSchema>;

export function parseActor(input: unknown): Actor {
  return actorSchema.parse(input);
}
