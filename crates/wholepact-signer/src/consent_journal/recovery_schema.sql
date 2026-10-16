-- Append-only generation commit evidence. An ordinary journal opener must refuse
-- any recovered generation; AccountVault verifies its final profile manifest.
CREATE TABLE signer_recovery_generations (
 generation_id TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('prepared','committed')),
 operation_id TEXT NOT NULL, inventory_digest TEXT NOT NULL, fence_digest TEXT NOT NULL,
 writer_epoch INTEGER NOT NULL CHECK(writer_epoch>0), payload TEXT NOT NULL,
 PRIMARY KEY(generation_id,phase)
);
CREATE TRIGGER signer_recovery_generations_no_update BEFORE UPDATE ON signer_recovery_generations BEGIN SELECT RAISE(ABORT,'immutable recovery generation'); END;
CREATE TRIGGER signer_recovery_generations_no_delete BEFORE DELETE ON signer_recovery_generations BEGIN SELECT RAISE(ABORT,'immutable recovery generation'); END;
