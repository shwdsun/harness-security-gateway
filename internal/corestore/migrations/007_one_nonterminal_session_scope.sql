CREATE UNIQUE INDEX runs_one_nonterminal_session_scope
    ON runs(
        binding_fingerprint,
        connector_id,
        actor_ref,
        conversation_ref,
        target_id,
        target_revision
    )
    WHERE state IN ('queued', 'dispatching', 'running');
