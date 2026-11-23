/**
 * Skill registry: the in-memory index of loaded skill packs, plus
 * per-run tool gating.
 *
 * SkillRegistry is the catalogue: it loads a skill directory once, lists
 * skills, and answers which skills a lane may see (frontmatter roles
 * names the lane). SkillRun is one run's loaded set: a gated tool is
 * unavailable until a skill naming it loads for that run.
 *
 * Tool gating is advisory, not a security boundary. The real gates
 * (scope, consent, approvals, pins, noise governor) sit in the tool
 * implementations, and a loaded skill never relaxes them.
 */
import { loadSkillDirectory, type Skill, type SkillRole } from './loader.js';

/** The prompt text injected when a skill is loaded for a run. */
export function skillPromptText(skill: Skill): string {
  return `Skill: ${skill.name} — ${skill.description}\n\n${skill.body}`;
}

export class SkillRegistry {
  private skills = new Map<string, Skill>();
  private runs = new Map<string, SkillRun>();

  /** Load (or reload) every skill pack under a directory. */
  async loadFromDirectory(dir: string): Promise<Skill[]> {
    const loaded = await loadSkillDirectory(dir);
    for (const skill of loaded) this.skills.set(skill.name, skill);
    return loaded;
  }

  /** Register one already-parsed skill (tests, or a skill built in code). */
  add(skill: Skill): void {
    this.skills.set(skill.name, skill);
  }

  /** Every loaded skill, sorted by name. */
  list(): Skill[] {
    return [...this.skills.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
  }

  /** Skills visible to one agent lane. */
  visibleTo(role: SkillRole): Skill[] {
    return this.list().filter((s) => s.roles.includes(role));
  }

  get(name: string): Skill | null {
    return this.skills.get(name) ?? null;
  }

  /** Names of the skills that gate a tool (empty when no skill gates it). */
  toolGatedBy(tool: string): string[] {
    return this.list()
      .filter((s) => s.tools.includes(tool))
      .map((s) => s.name);
  }

  /** True when at least one loaded skill gates this tool. */
  isToolGated(tool: string): boolean {
    return this.toolGatedBy(tool).length > 0;
  }

  /**
   * The per-run loaded set for a task (created on first use). Runs
   * are keyed by task id so two tasks never share a loaded set; a
   * run with no task id shares the registry's default run.
   */
  runFor(taskId?: string | null): SkillRun {
    const key = taskId ?? '__default__';
    let run = this.runs.get(key);
    if (!run) {
      run = new SkillRun(this);
      this.runs.set(key, run);
    }
    return run;
  }

  /**
   * Load a skill for a run and return its prompt text to inject.
   * Throws `skill_not_found` when the name is unknown and
   * `skill_not_visible_to_role: <role>` when the lane may not load
   * it. Loading twice is a no-op that returns the same text.
   */
  loadSkillForRun(role: SkillRole, name: string, taskId?: string | null): string {
    return this.runFor(taskId).load(role, name);
  }

  /** Forget a run's loaded set (the task finished or was cancelled). */
  dropRun(taskId?: string | null): void {
    this.runs.delete(taskId ?? '__default__');
  }
}

/** One run's loaded skills, and the tool gating that follows from them. */
export class SkillRun {
  private loaded = new Set<string>();

  constructor(private readonly registry: SkillRegistry) {}

  /** Load a skill for this run; returns its prompt text to inject. */
  load(role: SkillRole, name: string): string {
    const skill = this.registry.get(name);
    if (!skill) throw new Error(`skill_not_found: ${name}`);
    if (!skill.roles.includes(role)) {
      throw new Error(`skill_not_visible_to_role: ${name} is not visible to ${role}`);
    }
    this.loaded.add(name);
    return skillPromptText(skill);
  }

  /** Skills loaded for this run, sorted by name. */
  loadedSkills(): string[] {
    return [...this.loaded].sort();
  }

  /** True when this run has loaded the named skill. */
  hasLoaded(name: string): boolean {
    return this.loaded.has(name);
  }

  /**
   * A tool is available when no skill gates it, or when this run has
   * loaded at least one skill that gates it. An ungated tool is
   * always available, gating only ever restricts, never grants.
   */
  isToolUnlocked(tool: string): boolean {
    const gating = this.registry.toolGatedBy(tool);
    if (gating.length === 0) return true;
    return gating.some((name) => this.loaded.has(name));
  }
}
