package corestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const deliveryColumns = `
d.id, d.run_id, r.connector_id, r.conversation_ref, r.message_ref,
d.text, d.state, COALESCE(d.lease_token, ''),
COALESCE(d.lease_expires_at_ms, 0), d.attempt_count, d.available_at_ms,
COALESCE(d.provider_message_ref, ''), COALESCE(d.failure_code, ''),
d.created_at_ms, d.updated_at_ms`

const deliveryJoin = ` FROM text_deliveries AS d JOIN runs AS r ON r.id = d.run_id `

func (s *Store) insertDeliveryTx(
	ctx context.Context,
	tx *sql.Tx,
	run Run,
	input TextDeliveryInput,
	now int64,
) error {
	existing, err := scanDelivery(tx.QueryRowContext(ctx,
		"SELECT "+deliveryColumns+deliveryJoin+"WHERE d.id = ?", input.ID))
	switch {
	case err == nil:
		if existing.RunID == run.ID && existing.Text == input.Text {
			return nil
		}
		return fmt.Errorf("%w: delivery ID already has different content", ErrConflict)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("check existing delivery: %w", err)
	}
	existing, err = scanDelivery(tx.QueryRowContext(ctx,
		"SELECT "+deliveryColumns+deliveryJoin+"WHERE d.run_id = ?", run.ID))
	if err == nil {
		if existing.Text == input.Text {
			return nil
		}
		return fmt.Errorf("%w: run already has a different delivery", ErrConflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check existing run delivery: %w", err)
	}
	var pending int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM text_deliveries AS d
        JOIN runs AS r ON r.id = d.run_id
        WHERE r.connector_id = ? AND d.state IN ('pending','leased')`, run.ConnectorID).Scan(&pending); err != nil {
		return fmt.Errorf("count pending deliveries: %w", err)
	}
	if pending >= s.admission.MaxPendingDeliveriesPerConnector {
		return fmt.Errorf("%w: pending deliveries", ErrQuotaExceeded)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO text_deliveries(
    id, run_id, media_type, text, state, available_at_ms, created_at_ms, updated_at_ms
) VALUES (?, ?, 'text/plain', ?, 'pending', ?, ?, ?)`,
		input.ID, run.ID, input.Text, now, now, now,
	); err != nil {
		return ingestMutationError("insert text delivery", err)
	}
	return nil
}

func (s *Store) ClaimTextDeliveries(ctx context.Context, connectorID string, limit int, lease time.Duration) ([]TextDelivery, error) {
	if err := validateIdentifier("connector_id", connectorID, MaxIDBytes); err != nil {
		return nil, err
	}
	if limit < 1 || limit > MaxClaimLimit {
		return nil, invalidInput("limit", fmt.Sprintf("must be between 1 and %d", MaxClaimLimit))
	}
	if lease < time.Second || lease > 10*time.Minute {
		return nil, invalidInput("lease", "must be between one second and ten minutes")
	}
	now, err := s.nowMillis()
	if err != nil {
		return nil, err
	}
	leaseMillis := lease.Milliseconds()
	if leaseMillis <= 0 || now > int64(^uint64(0)>>1)-leaseMillis {
		return nil, invalidInput("lease", "expires outside the supported timestamp range")
	}
	expires := now + leaseMillis

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin delivery claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
UPDATE text_deliveries
SET state = 'pending', lease_token = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?
WHERE id IN (
    SELECT d.id FROM text_deliveries AS d
    JOIN runs AS r ON r.id = d.run_id
    WHERE r.connector_id = ? AND d.state = 'leased' AND d.lease_expires_at_ms <= ?
)`, now, connectorID, now); err != nil {
		return nil, fmt.Errorf("release expired delivery leases: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
SELECT d.id
FROM text_deliveries AS d
JOIN runs AS r ON r.id = d.run_id
WHERE r.connector_id = ? AND d.state = 'pending' AND d.available_at_ms <= ?
ORDER BY d.available_at_ms, d.created_at_ms, d.id
LIMIT ?`, connectorID, now, limit)
	if err != nil {
		return nil, fmt.Errorf("select claimable deliveries: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan claimable delivery: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate claimable deliveries: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close claimable deliveries: %w", err)
	}

	claimed := make([]TextDelivery, 0, len(ids))
	for _, id := range ids {
		token, err := s.newLeaseToken()
		if err != nil {
			return nil, fmt.Errorf("create delivery lease token: %w", err)
		}
		if err := validateIdentifier("generated lease_token", token, MaxIDBytes); err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, `
UPDATE text_deliveries
SET state = 'leased', lease_token = ?, lease_expires_at_ms = ?,
    attempt_count = attempt_count + 1, updated_at_ms = ?
WHERE id = ? AND state = 'pending'
  AND EXISTS (
      SELECT 1 FROM runs AS r
      WHERE r.id = text_deliveries.run_id AND r.connector_id = ?
  )`,
			token, expires, now, id, connectorID,
		)
		if err != nil {
			return nil, fmt.Errorf("lease delivery: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return nil, fmt.Errorf("lease delivery changed %d rows: %w", affected, err)
		}
		delivery, err := scanDelivery(tx.QueryRowContext(ctx,
			"SELECT "+deliveryColumns+deliveryJoin+"WHERE d.id = ?", id))
		if err != nil {
			return nil, fmt.Errorf("read leased delivery: %w", err)
		}
		claimed = append(claimed, delivery)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit delivery claim: %w", err)
	}
	return claimed, nil
}

func (s *Store) CompleteDelivery(ctx context.Context, input CompleteDeliveryInput) error {
	now, err := s.nowMillis()
	if err != nil {
		return err
	}
	if err := validateCompletion(input); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delivery completion: %w", err)
	}
	defer tx.Rollback()
	delivery, err := scanDelivery(tx.QueryRowContext(ctx,
		"SELECT "+deliveryColumns+deliveryJoin+"WHERE d.id = ? AND r.connector_id = ?",
		input.DeliveryID, input.ConnectorID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read delivery for completion: %w", err)
	}
	if delivery.LeaseToken != input.LeaseToken {
		return ErrLeaseLost
	}
	if delivery.State == DeliveryDelivered {
		if input.Outcome == DeliveryOutcomeDelivered && delivery.ProviderMessageRef == input.ProviderMessageRef {
			return tx.Commit()
		}
		return fmt.Errorf("%w: delivered result changed", ErrConflict)
	}
	if delivery.State == DeliveryPermanentFailed {
		if input.Outcome == DeliveryOutcomePermanentFailure && delivery.FailureCode == input.FailureCode {
			return tx.Commit()
		}
		return fmt.Errorf("%w: permanent failure result changed", ErrConflict)
	}
	if delivery.State == DeliveryPending {
		if input.Outcome == DeliveryOutcomeRetry && delivery.FailureCode == input.FailureCode {
			return tx.Commit()
		}
		return fmt.Errorf("%w: retry completion result changed", ErrConflict)
	}
	if delivery.State != DeliveryLeased ||
		delivery.LeaseExpiresAt.IsZero() || delivery.LeaseExpiresAt.UnixMilli() <= now {
		return ErrLeaseLost
	}

	switch input.Outcome {
	case DeliveryOutcomeDelivered:
		_, err = tx.ExecContext(ctx, `
UPDATE text_deliveries
SET state = 'delivered', lease_expires_at_ms = NULL, provider_message_ref = ?,
    failure_code = NULL, updated_at_ms = ?
WHERE id = ?`, input.ProviderMessageRef, now, input.DeliveryID)
	case DeliveryOutcomeRetry:
		retryAt := now + s.retryBackoff(delivery.AttemptCount).Milliseconds()
		if retryAt <= now {
			return invalidInput("retry_delay", "expires outside the supported timestamp range")
		}
		_, err = tx.ExecContext(ctx, `
UPDATE text_deliveries
SET state = 'pending', lease_expires_at_ms = NULL,
    available_at_ms = ?, failure_code = ?, updated_at_ms = ?
WHERE id = ?`, retryAt, string(input.FailureCode), now, input.DeliveryID)
	case DeliveryOutcomePermanentFailure:
		_, err = tx.ExecContext(ctx, `
UPDATE text_deliveries
SET state = 'permanent_failed', lease_expires_at_ms = NULL,
    failure_code = ?, updated_at_ms = ?
WHERE id = ?`, string(input.FailureCode), now, input.DeliveryID)
	}
	if err != nil {
		return fmt.Errorf("complete delivery: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delivery completion: %w", err)
	}
	return nil
}

func (s *Store) retryBackoff(attempt int) time.Duration {
	delay := s.retryDelay
	for current := 1; current < attempt && delay < maxRetryDelay; current++ {
		if delay > maxRetryDelay/2 {
			return maxRetryDelay
		}
		delay *= 2
	}
	if delay > maxRetryDelay {
		return maxRetryDelay
	}
	return delay
}

func scanDelivery(row rowScanner) (TextDelivery, error) {
	var delivery TextDelivery
	var leaseExpires int64
	var availableAt, createdAt, updatedAt int64
	if err := row.Scan(
		&delivery.ID, &delivery.RunID, &delivery.ConnectorID,
		&delivery.ConversationRef, &delivery.ReplyToRef, &delivery.Text,
		&delivery.State, &delivery.LeaseToken, &leaseExpires,
		&delivery.AttemptCount, &availableAt, &delivery.ProviderMessageRef,
		&delivery.FailureCode, &createdAt, &updatedAt,
	); err != nil {
		return TextDelivery{}, err
	}
	if leaseExpires > 0 {
		delivery.LeaseExpiresAt = timeFromMillis(leaseExpires)
	}
	delivery.AvailableAt = timeFromMillis(availableAt)
	delivery.CreatedAt = timeFromMillis(createdAt)
	delivery.UpdatedAt = timeFromMillis(updatedAt)
	return delivery, nil
}
