-- 018_tasks_graph.sql
-- Persistent tasks + exploration graph: a task is the first-class object
-- a swarm run hangs off (goal, target, persistent todolist); the graph
-- records what was tried, with what result and why.
--
-- Node kinds are goal/intent/fact/finding/hint/digest; edges carry the
-- relation between two nodes; anchors join a node to an asset, so a
-- finding traces back to the asset it was observed on. The graph is read
-- back whole per task; no cross-task graph query yet.
--
-- The planner todolist lives on the task row as JSON, an ordered list of
-- {id, text, status} steps.

create table if not exists tasks (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null references users (id) on delete cascade,
  goal_text        text not null,
  target_url       text not null,
  scope            jsonb,
  status           text not null default 'running'
                   check (status in ('running', 'paused', 'done', 'timeout', 'failed')),
  scan_id          uuid references scans (id) on delete set null,
  authorization_id uuid references authorizations (id) on delete set null,
  todolist         jsonb not null default '[]'::jsonb,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  finished_at      timestamptz
);
create index if not exists tasks_user_idx on tasks (user_id, created_at desc);
create index if not exists tasks_status_idx on tasks (status);

create table if not exists exploration_nodes (
  id         uuid primary key default gen_random_uuid(),
  task_id    uuid not null references tasks (id) on delete cascade,
  kind       text not null check (kind in ('goal', 'intent', 'fact', 'finding', 'hint', 'digest')),
  label      text not null,
  detail     text,
  status     text,
  created_at timestamptz not null default now()
);
create index if not exists exploration_nodes_task_idx on exploration_nodes (task_id, created_at);

create table if not exists exploration_edges (
  id           uuid primary key default gen_random_uuid(),
  task_id      uuid not null references tasks (id) on delete cascade,
  from_node_id uuid not null references exploration_nodes (id) on delete cascade,
  to_node_id   uuid not null references exploration_nodes (id) on delete cascade,
  rel          text not null check (rel in ('spawns', 'derived_from', 'yields', 'proves', 'covers')),
  created_at   timestamptz not null default now()
);
create index if not exists exploration_edges_task_idx on exploration_edges (task_id, created_at);

create table if not exists assets (
  id         uuid primary key default gen_random_uuid(),
  task_id    uuid not null references tasks (id) on delete cascade,
  kind       text not null check (kind in ('domain', 'endpoint', 'ip', 'service')),
  value      text not null,
  host       text,
  created_at timestamptz not null default now()
);
create index if not exists assets_task_idx on assets (task_id, created_at);

create table if not exists exploration_anchors (
  id         uuid primary key default gen_random_uuid(),
  task_id    uuid not null references tasks (id) on delete cascade,
  node_id    uuid not null references exploration_nodes (id) on delete cascade,
  asset_id   uuid not null references assets (id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists exploration_anchors_task_idx on exploration_anchors (task_id, created_at);
