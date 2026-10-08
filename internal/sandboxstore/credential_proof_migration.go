package sandboxstore

// Append-only schema 11. Proof is part of the immutable generation row so it
// cannot be added later, lost independently, or partially committed. Historical
// synthetic generations keep four NULLs; no authority is inferred by migration.
const credentialProofMigration = `
ALTER TABLE credential_generations ADD COLUMN proof_scheme TEXT;
ALTER TABLE credential_generations ADD COLUMN root_object_digest TEXT;
ALTER TABLE credential_generations ADD COLUMN slot_object_digest TEXT;
ALTER TABLE credential_generations ADD COLUMN locator_digest TEXT
CHECK (
 (proof_scheme IS NULL AND root_object_digest IS NULL AND slot_object_digest IS NULL AND locator_digest IS NULL)
 OR
 (proof_scheme IS NOT NULL AND proof_scheme = 'linux-ext4-source/v1'
  AND root_object_digest IS NOT NULL AND length(root_object_digest)=64 AND length(CAST(root_object_digest AS BLOB))=64 AND root_object_digest NOT GLOB '*[^0-9a-f]*'
  AND slot_object_digest IS NOT NULL AND length(slot_object_digest)=64 AND length(CAST(slot_object_digest AS BLOB))=64 AND slot_object_digest NOT GLOB '*[^0-9a-f]*'
  AND locator_digest IS NOT NULL AND length(locator_digest)=64 AND length(CAST(locator_digest AS BLOB))=64 AND locator_digest NOT GLOB '*[^0-9a-f]*'
  AND length(source_digest)=64 AND length(CAST(source_digest AS BLOB))=64 AND source_digest NOT GLOB '*[^0-9a-f]*')
);
`
