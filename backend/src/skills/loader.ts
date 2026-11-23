/**
 * Skill loader: reads skill packs from a directory on disk. A skill is a
 * directory holding one SKILL.md: YAML frontmatter followed by a playbook
 * body. Skills are prompt text only.
 *
 * A skill advises, it never executes. A skill must never declare
 * executable code: no exec/run/command frontmatter keys, no fenced code
 * block tagged as a shell command. A skill that breaks the rule is
 * rejected at load time, never silently trimmed.
 *
 * Loading a skill does not widen scope, skip consent, override an
 * approval, unpin a target, or silence the noise governor. It only adds
 * playbook text and unlocks the tools its frontmatter names, for that run.
 */
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

/** The agent lanes a skill may be visible to. */
export type SkillRole = 'planner' | 'worker' | 'main';

export const SKILL_ROLES: readonly SkillRole[] = ['planner', 'worker', 'main'];

/** Frontmatter keys a skill may declare. Anything else is rejected. */
const ALLOWED_FRONTMATTER_KEYS = new Set([
  'name',
  'description',
  'when-to-use',
  'roles',
  'tools',
]);

/** Frontmatter keys that would turn a skill into executable code. */
const EXECUTABLE_FRONTMATTER_KEYS = new Set(['exec', 'run', 'command', 'script']);

/** Fence tags that mark a code block as a shell command to run. */
const SHELL_FENCE_TAGS = new Set([
  'sh',
  'bash',
  'shell',
  'zsh',
  'console',
  'powershell',
  'ps1',
  'cmd',
  'bat',
]);

/** A skill name is a lowercase slug: letters, digits, hyphens. */
const NAME_SLUG = /^[a-z0-9][a-z0-9-]*$/;

/** One parsed skill pack. */
export interface Skill {
  /** Slug from frontmatter, also the directory name by convention. */
  name: string;
  /** One line: what the skill teaches the agent to do. */
  description: string;
  /** When the planner should reach for this skill. */
  whenToUse: string;
  /** Agent lanes that may load this skill. */
  roles: SkillRole[];
  /** Tool names this skill gates: locked until the skill is loaded. */
  tools: string[];
  /** The playbook body (everything after the frontmatter). */
  body: string;
  /** Directory the skill was loaded from (debugging aid, not a secret). */
  sourceDir: string;
}

/**
 * Parse the frontmatter block (the lines between the two `---`
 * fences) into a key → string | string[] map. Throws
 * `invalid_skill_frontmatter: <detail>` on anything it cannot read.
 */
export function parseFrontmatter(text: string): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  let currentListKey: string | null = null;

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trimEnd();
    if (line.trim() === '') continue;

    const listItem = line.match(/^\s*-\s+(.+)$/);
    if (listItem) {
      if (!currentListKey) {
        throw new Error('invalid_skill_frontmatter: list item without a key');
      }
      const list = out[currentListKey];
      if (!Array.isArray(list)) {
        throw new Error(`invalid_skill_frontmatter: key ${currentListKey} is not a list`);
      }
      list.push(unquote(listItem[1].trim()));
      continue;
    }

    const pair = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!pair) {
      throw new Error(`invalid_skill_frontmatter: cannot parse line "${line.trim()}"`);
    }
    const key = pair[1];
    const value = pair[2].trim();
    currentListKey = null;

    if (EXECUTABLE_FRONTMATTER_KEYS.has(key)) {
      throw new Error(
        `skill_contains_executable_directive: frontmatter key "${key}" is not allowed — skills advise, they never execute`,
      );
    }
    if (!ALLOWED_FRONTMATTER_KEYS.has(key)) {
      throw new Error(`invalid_skill_frontmatter: unknown key "${key}"`);
    }
    if (key in out) {
      throw new Error(`invalid_skill_frontmatter: duplicate key "${key}"`);
    }

    if (value === '') {
      // Block list: the items follow on `- item` lines.
      out[key] = [];
      currentListKey = key;
    } else if (value.startsWith('[') && value.endsWith(']')) {
      const inner = value.slice(1, -1).trim();
      out[key] = inner === '' ? [] : inner.split(',').map((s) => unquote(s.trim()));
    } else {
      out[key] = unquote(value);
    }
  }

  if (currentListKey !== null && (out[currentListKey] as string[]).length === 0) {
    throw new Error(`invalid_skill_frontmatter: key "${currentListKey}" has an empty list`);
  }
  return out;
}

/** Strip one pair of matching single/double quotes, if present. */
function unquote(value: string): string {
  if (
    value.length >= 2 &&
    ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'")))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function asString(value: string | string[] | undefined, key: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`invalid_skill: missing or empty required field "${key}"`);
  }
  return value;
}

function asStringList(value: string | string[] | undefined, key: string): string[] {
  if (value === undefined) {
    throw new Error(`invalid_skill: missing required field "${key}"`);
  }
  return Array.isArray(value) ? value : [value];
}

/**
 * Reject a skill body that declares executable code: any fenced code
 * block whose info tag names a shell. Throws
 * `skill_contains_executable_directive: <tag>`. A fence with no tag
 * or a non-shell tag (e.g. `text`, `json`, `http`) is prose, not a
 * command, and is allowed.
 */
export function assertNoExecutableDirectives(body: string): void {
  for (const line of body.split('\n')) {
    const fence = line.match(/^```\s*([A-Za-z0-9_-]+)?\s*$/);
    if (!fence || !fence[1]) continue;
    const tag = fence[1].toLowerCase();
    if (SHELL_FENCE_TAGS.has(tag)) {
      throw new Error(
        `skill_contains_executable_directive: fenced "${tag}" block — skills advise, they never execute`,
      );
    }
  }
}

/**
 * Parse one SKILL.md file's text into a Skill. Throws on missing
 * frontmatter, missing/invalid fields, or executable directives.
 * `sourceDir` is recorded on the result for debugging only.
 */
export function parseSkillFile(text: string, sourceDir: string): Skill {
  const lines = text.split('\n');
  if (lines[0]?.trim() !== '---') {
    throw new Error('invalid_skill: SKILL.md must start with a YAML frontmatter fence (---)');
  }
  let closeIdx = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === '---') {
      closeIdx = i;
      break;
    }
  }
  if (closeIdx === -1) {
    throw new Error('invalid_skill: frontmatter fence is never closed');
  }

  const frontmatter = parseFrontmatter(lines.slice(1, closeIdx).join('\n'));
  const body = lines.slice(closeIdx + 1).join('\n').trim();

  const name = asString(frontmatter['name'], 'name');
  if (!NAME_SLUG.test(name)) {
    throw new Error(`invalid_skill: name "${name}" is not a lowercase slug`);
  }
  const description = asString(frontmatter['description'], 'description');
  const whenToUse = asString(frontmatter['when-to-use'], 'when-to-use');
  const roles = asStringList(frontmatter['roles'], 'roles');
  for (const role of roles) {
    if (!(SKILL_ROLES as readonly string[]).includes(role)) {
      throw new Error(`invalid_skill: unknown role "${role}"`);
    }
  }
  const tools = asStringList(frontmatter['tools'], 'tools');
  for (const tool of tools) {
    if (!tool || /\s/.test(tool)) {
      throw new Error(`invalid_skill: bad tool name "${tool}"`);
    }
  }
  if (body === '') {
    throw new Error('invalid_skill: skill body is empty — a skill needs a playbook, not just frontmatter');
  }
  assertNoExecutableDirectives(body);

  return {
    name,
    description,
    whenToUse,
    roles: roles as SkillRole[],
    tools,
    body,
    sourceDir,
  };
}

/** Load one skill directory (must contain a SKILL.md). */
export async function loadSkillDir(dir: string): Promise<Skill> {
  const text = await readFile(join(dir, 'SKILL.md'), 'utf8');
  return parseSkillFile(text, dir);
}

/**
 * Load every skill pack under a root directory. Subdirectories
 * without a SKILL.md are skipped (they are not skills); a directory
 * with a malformed SKILL.md fails the whole load, a broken skill
 * must never load half-way. Returns skills sorted by name.
 */
export async function loadSkillDirectory(rootDir: string): Promise<Skill[]> {
  const entries = await readdir(rootDir, { withFileTypes: true });
  const skills: Skill[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const dir = join(rootDir, entry.name);
    let hasSkillFile = false;
    try {
      await readFile(join(dir, 'SKILL.md'), 'utf8');
      hasSkillFile = true;
    } catch {
      hasSkillFile = false;
    }
    if (!hasSkillFile) continue;
    skills.push(await loadSkillDir(dir));
  }
  skills.sort((a, b) => (a.name < b.name ? -1 : 1));
  return skills;
}

/** The shipped skill packs live in backend/skills/ (two levels up from src/skills/). */
export function defaultSkillsDir(): string {
  return join(__dirname, '..', '..', 'skills');
}
