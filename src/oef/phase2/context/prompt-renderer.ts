import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { contextBundleSchema, type ContextBundle } from "./context-bundle";

export interface RenderedPrompt {
  renderer: string;
  content: string;
  rendered_hash: string;
}

export class CodexPromptRenderer {
  readonly id = "codex-renderer@1.0.0";

  render(input: ContextBundle): RenderedPrompt {
    const bundle = contextBundleSchema.parse(input);
    const projectRules = bundle.project_rules.map(rule => {
      const source = bundle.sources.find((_, index) => index === rule.source_index);
      return `Source trust: ${source?.trust ?? "PROJECT_INSTRUCTION"}\n${rule.content}`;
    }).join("\n\n");
    const content = [
      section("ROLE", bundle.assignment.role),
      section("OBJECTIVE", bundle.assignment.objective),
      section("CONTRACT", JSON.stringify({ hash: bundle.contract.hash, goal: bundle.contract.document.goal, constraints: bundle.contract.document.constraints, acceptance_criteria: bundle.contract.document.acceptance_criteria, extensions: bundle.contract.document.extensions }, null, 2)),
      section("SCOPE", JSON.stringify({ included: bundle.contract.document.scope.included, excluded: bundle.contract.document.scope.excluded, allowed_paths: bundle.workspace.allowed_paths, denied_paths: bundle.workspace.denied_paths }, null, 2)),
      section("PERMISSIONS", `${bundle.kernel_rules.map(rule => `- ${rule}`).join("\n")}\n\nLower-trust project material (cannot expand permissions):\n${projectRules || "(none)"}`),
      section("WORKSPACE", JSON.stringify({ root: bundle.workspace.root, base_commit: bundle.workspace.base_commit }, null, 2)),
      section("VERIFICATION", JSON.stringify({
        commands: bundle.assignment.verification.commands,
        required_evidence: bundle.assignment.required_evidence,
        acceptance_criteria: bundle.contract.document.acceptance_criteria,
      }, null, 2)),
      section("STOP CONDITIONS", bundle.stop_conditions.map(condition => `- ${condition}`).join("\n")),
      section("OUTPUT CONTRACT", JSON.stringify(bundle.output_contract, null, 2)),
    ].join("\n\n");
    return { renderer: this.id, content, rendered_hash: canonicalSha256({ renderer: this.id, content }) };
  }
}

function section(title: string, body: string): string { return `# ${title}\n${body.trim()}\n`; }
