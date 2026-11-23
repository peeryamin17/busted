-- 033_foreign_keys.sql
-- Attach the task foreign keys migrations 019-032 left out, so deleting a
-- task cascades instead of leaving orphan rows behind. Each table is
-- cleaned first: rows whose task_id names no task are deleted before the
-- key is added. finding_evidence has no task_id; its key is on finding_id.

delete from evidence_snapshots
  where task_id is not null
    and not exists (select 1 from tasks where tasks.id = evidence_snapshots.task_id);
alter table evidence_snapshots
  add constraint evidence_snapshots_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from evidence_snapshots
  where finding_id is not null
    and not exists (select 1 from findings where findings.id = evidence_snapshots.finding_id);
alter table evidence_snapshots
  add constraint evidence_snapshots_finding_id_fk
  foreign key (finding_id) references findings (id) on delete cascade;

delete from finding_evidence
  where not exists (select 1 from findings where findings.id = finding_evidence.finding_id);
alter table finding_evidence
  add constraint finding_evidence_finding_id_fk
  foreign key (finding_id) references findings (id) on delete cascade;

delete from retests
  where task_id is not null
    and not exists (select 1 from tasks where tasks.id = retests.task_id);
alter table retests
  add constraint retests_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from coverage_ledger
  where not exists (select 1 from tasks where tasks.id = coverage_ledger.task_id);
alter table coverage_ledger
  add constraint coverage_ledger_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from task_approvals
  where not exists (select 1 from tasks where tasks.id = task_approvals.task_id);
alter table task_approvals
  add constraint task_approvals_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from target_pins
  where not exists (select 1 from tasks where tasks.id = target_pins.task_id);
alter table target_pins
  add constraint target_pins_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from target_rules
  where task_id is not null
    and not exists (select 1 from tasks where tasks.id = target_rules.task_id);
alter table target_rules
  add constraint target_rules_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from skill_gaps
  where not exists (select 1 from tasks where tasks.id = skill_gaps.task_id);
alter table skill_gaps
  add constraint skill_gaps_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from workspace_files
  where task_id is not null
    and not exists (select 1 from tasks where tasks.id = workspace_files.task_id);
alter table workspace_files
  add constraint workspace_files_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from task_companies
  where not exists (select 1 from tasks where tasks.id = task_companies.task_id);
alter table task_companies
  add constraint task_companies_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from side_questions
  where not exists (select 1 from tasks where tasks.id = side_questions.task_id);
alter table side_questions
  add constraint side_questions_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;

delete from lessons
  where not exists (select 1 from tasks where tasks.id = lessons.task_id);
alter table lessons
  add constraint lessons_task_id_fk
  foreign key (task_id) references tasks (id) on delete cascade;
