package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"capstone/auth-service/internal/accesslog"
	"capstone/auth-service/internal/config"
	"capstone/auth-service/internal/store"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

const CookieName = "capstone_session"

type Server struct {
	Config    config.Config
	Store     store.Store
	Client    *http.Client
	dummyHash []byte
}
type User struct {
	ID       string   `json:"id"`
	FullName string   `json:"full_name"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	IsActive bool     `json:"is_active"`
}

func New(cfg config.Config, db store.Store) *fiber.App {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("invalid-placeholder-password"), 12)
	s := &Server{Config: cfg, Store: db, Client: &http.Client{Timeout: 5 * time.Second}, dummyHash: dummy}
	app := fiber.New(fiber.Config{AppName: "capstone-auth", BodyLimit: 16 * 1024, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, ErrorHandler: func(c fiber.Ctx, e error) error {
		code := 500
		message := "Layanan autentikasi mengalami gangguan."
		var fe *fiber.Error
		if errors.As(e, &fe) {
			code = fe.Code
			message = fe.Message
		}
		return c.Status(code).JSON(fiber.Map{"error": fiber.Map{"message": message}})
	}})
	app.Use(accesslog.New("auth-service"))
	app.Use(recover.New())
	app.Use(func(c fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.Context(), 12*time.Second)
		defer cancel()
		c.SetContext(ctx)
		return c.Next()
	})
	app.Get("/health", func(c fiber.Ctx) error {
		if err := db.DB.Ping(c.Context()); err != nil {
			return fiber.NewError(503, "Database belum siap.")
		}
		return c.JSON(fiber.Map{"service": "auth-service", "status": "ok"})
	})
	auth := app.Group("/api/v1/auth")
	auth.Post("/login", limiter.New(limiter.Config{Max: 10, Expiration: time.Minute, KeyGenerator: func(c fiber.Ctx) string { return c.Get("X-Client-IP", c.IP()) }, LimitReached: func(c fiber.Ctx) error {
		return fiber.NewError(429, "Terlalu banyak percobaan. Coba lagi dalam satu menit.")
	}}), s.login)
	auth.Post("/logout", s.logout)
	auth.Put("/password", s.changePassword)
	internal := app.Group("/internal", s.internal)
	internal.Post("/sessions/verify", s.verify)
	internal.Put("/credentials/:id", s.createCredential)
	internal.Delete("/credentials/:id", s.deleteCredential)
	internal.Put("/credentials/:id/password", s.resetPassword)
	internal.Delete("/sessions/user/:id", s.revokeUser)
	return app
}
func (s *Server) internal(c fiber.Ctx) error {
	if subtle.ConstantTimeCompare([]byte(c.Get("X-Service-Token")), []byte(s.Config.InternalToken)) != 1 {
		return fiber.ErrUnauthorized
	}
	return c.Next()
}

func (s *Server) revokeUser(c fiber.Ctx) error {
	if _, e := uuid.Parse(c.Params("id")); e != nil {
		return fiber.ErrBadRequest
	}
	if e := s.Store.RevokeUser(c.Context(), c.Params("id")); e != nil {
		return e
	}
	return c.SendStatus(204)
}
func (s *Server) resetPassword(c fiber.Ctx) error {
	if _, e := uuid.Parse(c.Params("id")); e != nil {
		return fiber.ErrBadRequest
	}
	var in struct {
		Password string `json:"password"`
	}
	if c.Bind().JSON(&in) != nil || len(in.Password) < 12 || len(in.Password) > 72 {
		return fiber.NewError(422, "Kata sandi harus terdiri dari 12–72 byte.")
	}
	if _, e := s.Store.Password(c.Context(), c.Params("id")); errors.Is(e, pgx.ErrNoRows) {
		return fiber.ErrNotFound
	} else if e != nil {
		return e
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(in.Password), 12)
	if e != nil {
		return e
	}
	if e = s.Store.ChangePassword(c.Context(), c.Params("id"), string(hash)); e != nil {
		return e
	}
	return c.SendStatus(204)
}
func (s *Server) user(ctx context.Context, path string) (User, int, error) {
	var u User
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Config.UserURL+path, nil)
	if err != nil {
		return u, 0, err
	}
	req.Header.Set("X-Service-Token", s.Config.UserToken)
	resp, err := s.Client.Do(req)
	if err != nil {
		return u, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return u, resp.StatusCode, nil
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 32*1024)).Decode(&u)
	return u, resp.StatusCode, err
}
func (s *Server) login(c fiber.Ctx) error {
	var in struct {
		Identifier string `json:"identifier"`
		Email      string `json:"email"`
		Password   string `json:"password"`
	}
	if c.Bind().JSON(&in) != nil || len(in.Password) > 72 || in.Password == "" {
		return fiber.NewError(422, "Email, NIM, NIP, atau NIDN serta kata sandi wajib diisi.")
	}
	loginID := strings.TrimSpace(in.Identifier)
	if loginID == "" {
		loginID = strings.TrimSpace(in.Email)
	}
	if loginID == "" || len(loginID) > 254 {
		return fiber.NewError(422, "Email, NIM, NIP, atau NIDN serta kata sandi wajib diisi dengan benar.")
	}
	u, status, err := s.user(c.Context(), "/internal/users/by-identifier?q="+url.QueryEscape(loginID))
	if err != nil || (status != 200 && status != 404) {
		return fiber.NewError(503, "Layanan pengguna belum tersedia. Silakan coba kembali.")
	}
	hash := s.dummyHash
	credentialFound := false
	if status == 200 {
		h, e := s.Store.Password(c.Context(), u.ID)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return fiber.ErrServiceUnavailable
		}
		if e == nil {
			hash = []byte(h)
			credentialFound = true
		}
	}
	valid := bcrypt.CompareHashAndPassword(hash, []byte(in.Password)) == nil
	if status != 200 || !u.IsActive || !credentialFound || !valid {
		return fiber.NewError(401, "Email/NIM/NIP/NIDN atau kata sandi salah, atau akun tidak aktif.")
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expiry := time.Now().Add(8 * time.Hour)
	if old := c.Cookies(CookieName); old != "" {
		if err = s.Store.Revoke(c.Context(), old); err != nil {
			return err
		}
	}
	if err = s.Store.CreateSession(c.Context(), token, u.ID, expiry); err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: CookieName, Value: token, Path: "/", Expires: expiry, MaxAge: 8 * 60 * 60, HTTPOnly: true, Secure: s.Config.CookieSecure, SameSite: "Strict"})
	req, _ := http.NewRequestWithContext(c.Context(), http.MethodPost, s.Config.UserURL+"/internal/users/"+u.ID+"/login", bytes.NewReader(nil))
	req.Header.Set("X-Service-Token", s.Config.UserToken)
	if resp, e := s.Client.Do(req); e == nil {
		resp.Body.Close()
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"user": u, "expires_at": expiry})
}
func (s *Server) logout(c fiber.Ctx) error {
	if t := c.Cookies(CookieName); t != "" {
		if err := s.Store.Revoke(c.Context(), t); err != nil {
			return err
		}
	}
	c.Cookie(&fiber.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), HTTPOnly: true, Secure: s.Config.CookieSecure, SameSite: "Strict"})
	return c.SendStatus(204)
}
func (s *Server) verify(c fiber.Ctx) error {
	var in struct {
		Token string `json:"token"`
	}
	if c.Bind().JSON(&in) != nil || len(in.Token) != 43 {
		return fiber.ErrUnauthorized
	}
	id, e := s.Store.Session(c.Context(), in.Token)
	if errors.Is(e, pgx.ErrNoRows) {
		return fiber.ErrUnauthorized
	}
	if e != nil {
		return fiber.ErrServiceUnavailable
	}
	return c.JSON(fiber.Map{"user_id": id})
}
func (s *Server) createCredential(c fiber.Ctx) error {
	if _, err := uuid.Parse(c.Params("id")); err != nil {
		return fiber.ErrBadRequest
	}
	var in struct {
		Password string `json:"password"`
	}
	if c.Bind().JSON(&in) != nil || len(in.Password) < 12 || len(in.Password) > 72 {
		return fiber.NewError(422, "Kata sandi harus terdiri dari 12–72 byte.")
	}
	h, e := bcrypt.GenerateFromPassword([]byte(in.Password), 12)
	if e != nil {
		return e
	}
	if e = s.Store.CreateCredential(c.Context(), c.Params("id"), string(h)); e != nil {
		return e
	}
	return c.SendStatus(201)
}
func (s *Server) deleteCredential(c fiber.Ctx) error {
	if _, e := uuid.Parse(c.Params("id")); e != nil {
		return fiber.ErrBadRequest
	}
	if e := s.Store.DeleteCredential(c.Context(), c.Params("id")); e != nil {
		return e
	}
	return c.SendStatus(204)
}
func (s *Server) changePassword(c fiber.Ctx) error {
	id, e := s.Store.Session(c.Context(), c.Cookies(CookieName))
	if errors.Is(e, pgx.ErrNoRows) {
		return fiber.ErrUnauthorized
	}
	if e != nil {
		return fiber.ErrServiceUnavailable
	}
	u, status, e := s.user(c.Context(), "/internal/users/"+id)
	if e != nil || status != 200 {
		return fiber.ErrServiceUnavailable
	}
	if !u.IsActive {
		return fiber.ErrUnauthorized
	}
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if c.Bind().JSON(&in) != nil || len(in.New) < 12 || len(in.New) > 72 || len(in.Current) > 72 {
		return fiber.NewError(422, "Kata sandi baru harus terdiri dari 12–72 byte.")
	}
	h, e := s.Store.Password(c.Context(), id)
	if e != nil {
		return e
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte(in.Current)) != nil {
		return fiber.NewError(422, "Kata sandi saat ini tidak sesuai.")
	}
	next, e := bcrypt.GenerateFromPassword([]byte(in.New), 12)
	if e != nil {
		return e
	}
	if e = s.Store.ChangePassword(c.Context(), id, string(next)); e != nil {
		return e
	}
	c.Cookie(&fiber.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), HTTPOnly: true, Secure: s.Config.CookieSecure, SameSite: "Strict"})
	return c.SendStatus(204)
}
