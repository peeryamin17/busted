/**
 * Task and exploration-graph types. Pure types, no imports.
 * All timestamps are ISO strings at this layer.
 */

export type TaskStatus = 'running' | 'paused' | 'done' | 'timeout' | 'failed';

export const TASK_STATUSES: readonly TaskStatus[] = [
  'running',
  'paused',
  'done',
  'timeout',
  'failed',
];

/** Terminal states: once a task lands here it never moves again. */
export const TERMINAL_TASK_STATUSES: readonly TaskStatus[] = ['done', 'timeout', 'failed'];

/** One step of the planner's persistent todolist, stored as JSON on the task. */
export interface TodoItem {
  id: string;
  text: string;
  status: 'pending' | 'running' | 'done' | 'skipped';
}

export interface TaskRecord {
  id: string;
  userId: string;
  goalText: string;
  targetUrl: string;
  /** Scope boundaries for the run (same shape as the scan scope policy). */
  scope: Record<string, unknown> | null;
  status: TaskStatus;
  scanId?: string | null;
  authorizationId?: string | null;
  todolist: TodoItem[];
  createdAt: string; // ISO
  updatedAt: string; // ISO
  finishedAt?: string | null; // ISO, set when the task reaches a terminal status
}

export type GraphNodeKind = 'goal' | 'intent' | 'fact' | 'finding' | 'hint' | 'digest';

export const GRAPH_NODE_KINDS: readonly GraphNodeKind[] = [
  'goal',
  'intent',
  'fact',
  'finding',
  'hint',
  'digest',
];

export interface GraphNode {
  id: string;
  taskId: string;
  kind: GraphNodeKind;
  label: string;
  detail?: string | null;
  /** Free-form node state, e.g. 'open' | 'done' for an intent node. */
  status?: string | null;
  createdAt: string; // ISO
}

export type GraphEdgeRel = 'spawns' | 'derived_from' | 'yields' | 'proves' | 'covers';

export const GRAPH_EDGE_RELS: readonly GraphEdgeRel[] = [
  'spawns',
  'derived_from',
  'yields',
  'proves',
  'covers',
];

export interface GraphEdge {
  id: string;
  taskId: string;
  fromNodeId: string;
  toNodeId: string;
  rel: GraphEdgeRel;
  createdAt: string; // ISO
}

export interface GraphAnchor {
  id: string;
  taskId: string;
  nodeId: string;
  assetId: string;
  createdAt: string; // ISO
}

export type AssetKind = 'domain' | 'endpoint' | 'ip' | 'service';

export const ASSET_KINDS: readonly AssetKind[] = ['domain', 'endpoint', 'ip', 'service'];

export interface AssetRecord {
  id: string;
  taskId: string;
  kind: AssetKind;
  value: string;
  host?: string | null;
  createdAt: string; // ISO
}

/** A task with its whole exploration graph, as GET /api/tasks/:id returns it. */
export interface TaskGraph {
  task: TaskRecord;
  nodes: GraphNode[];
  edges: GraphEdge[];
  anchors: GraphAnchor[];
  assets: AssetRecord[];
}
