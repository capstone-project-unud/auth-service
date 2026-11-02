package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type Store struct{ DB *pgxpool.Pool }

func (s Store) RevokeUser(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, "DELETE FROM auth_service.sessions WHERE user_id=$1", id)
	return err
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func (s Store) Password(ctx context.Context, id string) (string, error) {
	var h string
	err := s.DB.QueryRow(ctx, "SELECT password_hash FROM auth_service.credentials WHERE user_id=$1", id).Scan(&h)
	return h, err
}
func (s Store) CreateCredential(ctx context.Context, id, hash string) error {
	_, err := s.DB.Exec(ctx, "INSERT INTO auth_service.credentials(user_id,password_hash) VALUES($1,$2)", id, hash)
	return err
}
func (s Store) DeleteCredential(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, "DELETE FROM auth_service.credentials WHERE user_id=$1", id)
	return err
}
func (s Store) Session(ctx context.Context, token string) (string, error) {
	var id string
	err := s.DB.QueryRow(ctx, "SELECT user_id FROM auth_service.sessions WHERE token_hash=$1 AND expires_at>now()", HashToken(token)).Scan(&id)
	return id, err
}
func (s Store) CreateSession(ctx context.Context, token, id string, expiry time.Time) error {
	_, err := s.DB.Exec(ctx, "INSERT INTO auth_service.sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)", HashToken(token), id, expiry)
	return err
}
func (s Store) Revoke(ctx context.Context, token string) error {
	_, err := s.DB.Exec(ctx, "DELETE FROM auth_service.sessions WHERE token_hash=$1", HashToken(token))
	return err
}
func (s Store) ChangePassword(ctx context.Context, id, hash string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "UPDATE auth_service.credentials SET password_hash=$2,updated_at=now() WHERE user_id=$1", id, hash); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM auth_service.sessions WHERE user_id=$1", id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
