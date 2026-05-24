-- Track B gap closure: eliminate NULL org rows from tenant-sensitive tables.
-- Use a fixed sentinel UUID for legacy writes that did not include tenant context.
-- This keeps historical rows queryable while allowing strict null-org gates.

UPDATE decisions_hot
SET org_id = '00000000-0000-0000-0000-000000000001'::uuid
WHERE org_id IS NULL;

UPDATE action_embeddings
SET org_id = '00000000-0000-0000-0000-000000000001'::uuid
WHERE org_id IS NULL;
