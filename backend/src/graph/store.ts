/**
 * Task and exploration-graph persistence: memory and Postgres behind one
 * interface. Status transitions are validated here, so no caller can move
 * a task backwards or revive a finished one.
 */
import { randomUUID } from 'node:crypto';
import {
  ASSET_KINDS,
  GRAPH_EDGE_RELS,
  GRAPH_NODE_KINDS,
  TERMINAL_TASK_STATUSES,
  type AssetKind,
  type AssetRecord,
  type GraphAnchor,
  type GraphEdge,
  type GraphEdgeRel,
  type GraphNode,
  type GraphNodeKind,
  type TaskGraph,
  type TaskRecord,
  type TaskStatus,
  type TodoItem,
} from './types.js';

export interface CreateTaskInput {
  userId: string;
  goalText: string;
  targetUrl: string;
  scope?: Record<string, unknown> | null;
  scanId?: string | null;
  authorizationId?: string | null;
}

export interface AddNodeInput {
  taskId: string;
  kind: GraphNodeKind;
  label: string;
  detail?: string | null;
  status?: string | null;
}

export interface AddEdgeInput {
  taskId: string;
  fromNodeId: string;
  toNodeId: string;
  rel: GraphEdgeRel;
}

export interface AddAnchorInput {
  taskId: string;
  nodeId: string;
  assetId: string;
}

export interface AddAssetInput {
  taskId: string;
  kind: AssetKind;
  value: string;
  host?: string | null;
}

export interface GraphStore {
  createTask(input: CreateTaskInput): Promise<TaskRecord>;
  getTask(id: string): Promise<TaskRecord | null>;
  listTasks(userId: string): Promise<TaskRecord[]>;
  /**
   * Move a task to a new status. Allowed: running→paused, paused→running,
   * running/paused→done|timeout|failed. Anything else throws an Error
   * (message `invalid_task_transition: <from> -> <to>`). Returns null
   * when the task does not exist. Terminal transitions stamp finishedAt.
   */
  updateTaskStatus(id: string, status: TaskStatus): Promise<TaskRecord | null>;
  /**
   * Replace the task's persistent todolist (planner steps, stored as JSON
   * on the task row). The head agent writes it after goal decomposition
   * and rewrites it as steps complete; the shape is the graph layer's
   * TodoItem (id/text/status), mapped from the planner's richer TodoStep.
   */
  setTaskTodolist(taskId: string, todolist: TodoItem[]): Promise<void>;
  getTaskGraph(taskId: string): Promise<TaskGraph | null>;
  addNode(input: AddNodeInput): Promise<GraphNode>;
  addEdge(input: AddEdgeInput): Promise<GraphEdge>;
  addAnchor(input: AddAnchorInput): Promise<GraphAnchor>;
  addAsset(input: AddAssetInput): Promise<AssetRecord>;
  listNodes(taskId: string): Promise<GraphNode[]>;
  listEdges(taskId: string): Promise<GraphEdge[]>;
  listAnchors(taskId: string): Promise<GraphAnchor[]>;
  listAssets(taskId: string): Promise<AssetRecord[]>;
}

/**
 * Allowed transitions. A task starts `running`; it can pause and resume,
 * and it can finish from either live state, but a finished task never
 * moves again, and pausing/resuming a finished task is not a thing.
 */
export const TASK_TRANSITIONS: Record<TaskStatus, readonly TaskStatus[]> = {
  running: ['paused', 'done', 'timeout', 'failed'],
  paused: ['running', 'done', 'timeout', 'failed'],
  done: [],
  timeout: [],
  failed: [],
};

export function assertTaskTransition(from: TaskStatus, to: TaskStatus): void {
  if (from === to || !TASK_TRANSITIONS[from].includes(to)) {
    throw new Error(`invalid_task_transition: ${from} -> ${to}`);
  }
}

function assertNodeKind(kind: string): asserts kind is GraphNodeKind {
  if (!(GRAPH_NODE_KINDS as readonly string[]).includes(kind)) {
    throw new Error(`invalid_node_kind: ${kind}`);
  }
}

function assertEdgeRel(rel: string): asserts rel is GraphEdgeRel {
  if (!(GRAPH_EDGE_RELS as readonly string[]).includes(rel)) {
    throw new Error(`invalid_edge_rel: ${rel}`);
  }
}

function assertAssetKind(kind: string): asserts kind is AssetKind {
  if (!(ASSET_KINDS as readonly string[]).includes(kind)) {
    throw new Error(`invalid_asset_kind: ${kind}`);
  }
}

const nowIso = () => new Date().toISOString();

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryGraphStore implements GraphStore {
  private tasks = new Map<string, TaskRecord>();
  private nodes = new Map<string, GraphNode>();
  private edges = new Map<string, GraphEdge>();
  private anchors = new Map<string, GraphAnchor>();
  private assets = new Map<string, AssetRecord>();

  async createTask(input: CreateTaskInput): Promise<TaskRecord> {
    const now = nowIso();
    const task: TaskRecord = {
      id: randomUUID(),
      userId: input.userId,
      goalText: input.goalText,
      targetUrl: input.targetUrl,
      scope: input.scope ?? null,
      status: 'running',
      scanId: input.scanId ?? null,
      authorizationId: input.authorizationId ?? null,
      todolist: [],
      createdAt: now,
      updatedAt: now,
      finishedAt: null,
    };
    this.tasks.set(task.id, task);
    return { ...task, todolist: [] };
  }

  async getTask(id: string): Promise<TaskRecord | null> {
    const t = this.tasks.get(id);
    return t ? { ...t, todolist: [...t.todolist] } : null;
  }

  async listTasks(userId: string): Promise<TaskRecord[]> {
    return [...this.tasks.values()]
      .filter((t) => t.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((t) => ({ ...t, todolist: [...t.todolist] }));
  }

  async updateTaskStatus(id: string, status: TaskStatus): Promise<TaskRecord | null> {
    const task = this.tasks.get(id);
    if (!task) return null;
    assertTaskTransition(task.status, status);
    task.status = status;
    task.updatedAt = nowIso();
    if ((TERMINAL_TASK_STATUSES as readonly string[]).includes(status)) {
      task.finishedAt = task.updatedAt;
    }
    return { ...task, todolist: [...task.todolist] };
  }

  async setTaskTodolist(taskId: string, todolist: TodoItem[]): Promise<void> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error('task_not_found');
    task.todolist = todolist.map((t) => ({ ...t }));
    task.updatedAt = nowIso();
  }

  async getTaskGraph(taskId: string): Promise<TaskGraph | null> {
    const task = await this.getTask(taskId);
    if (!task) return null;
    const [nodes, edges, anchors, assets] = await Promise.all([
      this.listNodes(taskId),
      this.listEdges(taskId),
      this.listAnchors(taskId),
      this.listAssets(taskId),
    ]);
    return { task, nodes, edges, anchors, assets };
  }

  async addNode(input: AddNodeInput): Promise<GraphNode> {
    assertNodeKind(input.kind);
    if (!this.tasks.has(input.taskId)) throw new Error('task_not_found');
    const node: GraphNode = {
      id: randomUUID(),
      taskId: input.taskId,
      kind: input.kind,
      label: input.label,
      detail: input.detail ?? null,
      status: input.status ?? null,
      createdAt: nowIso(),
    };
    this.nodes.set(node.id, node);
    return { ...node };
  }

  async addEdge(input: AddEdgeInput): Promise<GraphEdge> {
    assertEdgeRel(input.rel);
    const from = this.nodes.get(input.fromNodeId);
    const to = this.nodes.get(input.toNodeId);
    if (!from || !to || from.taskId !== input.taskId || to.taskId !== input.taskId) {
      throw new Error('edge_nodes_must_belong_to_task');
    }
    const edge: GraphEdge = {
      id: randomUUID(),
      taskId: input.taskId,
      fromNodeId: input.fromNodeId,
      toNodeId: input.toNodeId,
      rel: input.rel,
      createdAt: nowIso(),
    };
    this.edges.set(edge.id, edge);
    return { ...edge };
  }

  async addAnchor(input: AddAnchorInput): Promise<GraphAnchor> {
    const node = this.nodes.get(input.nodeId);
    const asset = this.assets.get(input.assetId);
    if (!node || !asset || node.taskId !== input.taskId || asset.taskId !== input.taskId) {
      throw new Error('anchor_node_and_asset_must_belong_to_task');
    }
    const anchor: GraphAnchor = {
      id: randomUUID(),
      taskId: input.taskId,
      nodeId: input.nodeId,
      assetId: input.assetId,
      createdAt: nowIso(),
    };
    this.anchors.set(anchor.id, anchor);
    return { ...anchor };
  }

  async addAsset(input: AddAssetInput): Promise<AssetRecord> {
    assertAssetKind(input.kind);
    if (!this.tasks.has(input.taskId)) throw new Error('task_not_found');
    const asset: AssetRecord = {
      id: randomUUID(),
      taskId: input.taskId,
      kind: input.kind,
      value: input.value,
      host: input.host ?? null,
      createdAt: nowIso(),
    };
    this.assets.set(asset.id, asset);
    return { ...asset };
  }

  async listNodes(taskId: string): Promise<GraphNode[]> {
    return [...this.nodes.values()]
      .filter((n) => n.taskId === taskId)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))
      .map((n) => ({ ...n }));
  }

  async listEdges(taskId: string): Promise<GraphEdge[]> {
    return [...this.edges.values()]
      .filter((e) => e.taskId === taskId)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))
      .map((e) => ({ ...e }));
  }

  async listAnchors(taskId: string): Promise<GraphAnchor[]> {
    return [...this.anchors.values()]
      .filter((a) => a.taskId === taskId)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))
      .map((a) => ({ ...a }));
  }

  async listAssets(taskId: string): Promise<AssetRecord[]> {
    return [...this.assets.values()]
      .filter((a) => a.taskId === taskId)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))
      .map((a) => ({ ...a }));
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type GraphQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toJson<T>(value: unknown, fallback: T): T {
  if (value == null) return fallback;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}

export class PostgresGraphStore implements GraphStore {
  constructor(private readonly query: GraphQueryFn) {}

  private toTask(row: Record<string, unknown>): TaskRecord {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      goalText: row['goal_text'] as string,
      targetUrl: row['target_url'] as string,
      scope: toJson<Record<string, unknown> | null>(row['scope'], null),
      status: row['status'] as TaskStatus,
      scanId: (row['scan_id'] as string) ?? null,
      authorizationId: (row['authorization_id'] as string) ?? null,
      todolist: toJson(row['todolist'], []),
      createdAt: toIso(row['created_at']),
      updatedAt: toIso(row['updated_at']),
      finishedAt: row['finished_at'] ? toIso(row['finished_at']) : null,
    };
  }

  private toNode(row: Record<string, unknown>): GraphNode {
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      kind: row['kind'] as GraphNodeKind,
      label: row['label'] as string,
      detail: (row['detail'] as string) ?? null,
      status: (row['status'] as string) ?? null,
      createdAt: toIso(row['created_at']),
    };
  }

  private toEdge(row: Record<string, unknown>): GraphEdge {
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      fromNodeId: row['from_node_id'] as string,
      toNodeId: row['to_node_id'] as string,
      rel: row['rel'] as GraphEdgeRel,
      createdAt: toIso(row['created_at']),
    };
  }

  private toAnchor(row: Record<string, unknown>): GraphAnchor {
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      nodeId: row['node_id'] as string,
      assetId: row['asset_id'] as string,
      createdAt: toIso(row['created_at']),
    };
  }

  private toAsset(row: Record<string, unknown>): AssetRecord {
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      kind: row['kind'] as AssetKind,
      value: row['value'] as string,
      host: (row['host'] as string) ?? null,
      createdAt: toIso(row['created_at']),
    };
  }

  async createTask(input: CreateTaskInput): Promise<TaskRecord> {
    const { rows } = await this.query(
      `INSERT INTO tasks (user_id, goal_text, target_url, scope, scan_id, authorization_id)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6) RETURNING *`,
      [
        input.userId,
        input.goalText,
        input.targetUrl,
        input.scope ? JSON.stringify(input.scope) : null,
        input.scanId ?? null,
        input.authorizationId ?? null,
      ],
    );
    return this.toTask(rows[0]);
  }

  async getTask(id: string): Promise<TaskRecord | null> {
    const { rows } = await this.query(`SELECT * FROM tasks WHERE id = $1`, [id]);
    return rows[0] ? this.toTask(rows[0]) : null;
  }

  async listTasks(userId: string): Promise<TaskRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM tasks WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return rows.map((r) => this.toTask(r));
  }

  async updateTaskStatus(id: string, status: TaskStatus): Promise<TaskRecord | null> {
    const current = await this.getTask(id);
    if (!current) return null;
    assertTaskTransition(current.status, status);
    // Terminal transitions stamp finished_at; pause/resume leave it alone.
    const terminal = (TERMINAL_TASK_STATUSES as readonly string[]).includes(status);
    const { rows } = await this.query(
      terminal
        ? `UPDATE tasks SET status = $1, updated_at = now(), finished_at = now() WHERE id = $2 RETURNING *`
        : `UPDATE tasks SET status = $1, updated_at = now() WHERE id = $2 RETURNING *`,
      [status, id],
    );
    return rows[0] ? this.toTask(rows[0]) : null;
  }

  async setTaskTodolist(taskId: string, todolist: TodoItem[]): Promise<void> {
    await this.query(
      `UPDATE tasks SET todolist = $1::jsonb, updated_at = now() WHERE id = $2`,
      [JSON.stringify(todolist), taskId],
    );
  }

  async getTaskGraph(taskId: string): Promise<TaskGraph | null> {
    const task = await this.getTask(taskId);
    if (!task) return null;
    const [nodes, edges, anchors, assets] = await Promise.all([
      this.listNodes(taskId),
      this.listEdges(taskId),
      this.listAnchors(taskId),
      this.listAssets(taskId),
    ]);
    return { task, nodes, edges, anchors, assets };
  }

  async addNode(input: AddNodeInput): Promise<GraphNode> {
    assertNodeKind(input.kind);
    const { rows } = await this.query(
      `INSERT INTO exploration_nodes (task_id, kind, label, detail, status)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [input.taskId, input.kind, input.label, input.detail ?? null, input.status ?? null],
    );
    return this.toNode(rows[0]);
  }

  async addEdge(input: AddEdgeInput): Promise<GraphEdge> {
    assertEdgeRel(input.rel);
    // Both endpoints must be nodes of this task, never bridge two tasks.
    const { rows: found } = await this.query(
      `SELECT id, task_id FROM exploration_nodes WHERE id = $1 OR id = $2`,
      [input.fromNodeId, input.toNodeId],
    );
    const ok =
      found.length === 2 &&
      found.every((r) => (r['task_id'] as string) === input.taskId);
    if (!ok) throw new Error('edge_nodes_must_belong_to_task');
    const { rows } = await this.query(
      `INSERT INTO exploration_edges (task_id, from_node_id, to_node_id, rel)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [input.taskId, input.fromNodeId, input.toNodeId, input.rel],
    );
    return this.toEdge(rows[0]);
  }

  async addAnchor(input: AddAnchorInput): Promise<GraphAnchor> {
    const { rows: nodeRows } = await this.query(
      `SELECT id, task_id FROM exploration_nodes WHERE id = $1`,
      [input.nodeId],
    );
    const { rows: assetRows } = await this.query(
      `SELECT id, task_id FROM assets WHERE id = $1`,
      [input.assetId],
    );
    const ok =
      nodeRows[0]?.['task_id'] === input.taskId && assetRows[0]?.['task_id'] === input.taskId;
    if (!ok) throw new Error('anchor_node_and_asset_must_belong_to_task');
    const { rows } = await this.query(
      `INSERT INTO exploration_anchors (task_id, node_id, asset_id)
       VALUES ($1, $2, $3) RETURNING *`,
      [input.taskId, input.nodeId, input.assetId],
    );
    return this.toAnchor(rows[0]);
  }

  async addAsset(input: AddAssetInput): Promise<AssetRecord> {
    assertAssetKind(input.kind);
    const { rows } = await this.query(
      `INSERT INTO assets (task_id, kind, value, host)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [input.taskId, input.kind, input.value, input.host ?? null],
    );
    return this.toAsset(rows[0]);
  }

  async listNodes(taskId: string): Promise<GraphNode[]> {
    const { rows } = await this.query(
      `SELECT * FROM exploration_nodes WHERE task_id = $1 ORDER BY created_at ASC`,
      [taskId],
    );
    return rows.map((r) => this.toNode(r));
  }

  async listEdges(taskId: string): Promise<GraphEdge[]> {
    const { rows } = await this.query(
      `SELECT * FROM exploration_edges WHERE task_id = $1 ORDER BY created_at ASC`,
      [taskId],
    );
    return rows.map((r) => this.toEdge(r));
  }

  async listAnchors(taskId: string): Promise<GraphAnchor[]> {
    const { rows } = await this.query(
      `SELECT * FROM exploration_anchors WHERE task_id = $1 ORDER BY created_at ASC`,
      [taskId],
    );
    return rows.map((r) => this.toAnchor(r));
  }

  async listAssets(taskId: string): Promise<AssetRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM assets WHERE task_id = $1 ORDER BY created_at ASC`,
      [taskId],
    );
    return rows.map((r) => this.toAsset(r));
  }
}
