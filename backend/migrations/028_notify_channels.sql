-- 028_notify_channels.sql
-- Notification channels.
--
-- One row per destination for task/finding events: a generic webhook, a
-- Telegram chat, or an SMTP mailbox. The row holds only the address
-- (webhook URL, chat id, SMTP host/port/user), never a credential: tokens
-- and passwords live in user_secrets (migration 024, kind 'notify', label
-- = channel id) and are decrypted at send time only.
--
-- `target` shape depends on `type` (validated in src/notify/channels.ts):
-- webhook {url}, telegram {chatId}, smtp {host, port, user, from, to}.
-- `filters` is {minSeverity, events}. One label per user; re-creating a
-- label replaces the old channel.

create table if not exists notify_channels (
  id         uuid primary key default gen_random_uuid(),
  user_id    text not null,
  type       text not null check (type in ('webhook', 'telegram', 'smtp')),
  label      text not null,
  target     jsonb not null,
  filters    jsonb not null,
  enabled    boolean not null default true,
  created_at timestamptz not null default now()
);

create unique index if not exists notify_channels_user_label_idx
  on notify_channels (user_id, label);

create index if not exists notify_channels_user_idx
  on notify_channels (user_id);
