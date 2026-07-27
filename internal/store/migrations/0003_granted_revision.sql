-- Plan 2b, the sync-contract correction Task 2's review produced.
--
-- The revision cursor is global and monotonic, but visibility is evaluated at
-- query time. An item already in collection C carries a revision BELOW the
-- cursor a newly-granted member's device already holds, so their next
-- incremental sync matches nothing and the household's shared passwords are
-- simply invisible to them — no error, no empty-state signal, until that device
-- wipes its local state.
--
-- Recording the revision at which a membership was created closes it: a shared
-- item is returned when item.revision > since OR membership.granted_revision >
-- since. No row rewrites, and no effect on existing members, whose
-- granted_revision is already below their cursor.
--
-- DEFAULT 0 is right for the rows that already exist. A membership predating
-- this column belongs to someone who has been syncing the collection all along,
-- so it must not fire the backlog resend; 0 is below every live cursor and
-- never will.
ALTER TABLE collection_memberships ADD COLUMN granted_revision INTEGER NOT NULL DEFAULT 0;

-- The sync query filters memberships by user and compares granted_revision.
CREATE INDEX collection_memberships_user_revision
    ON collection_memberships (user_id, granted_revision);
