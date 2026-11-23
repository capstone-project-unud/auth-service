package main

import (
	"capstone/auth-service/internal/config"
	"capstone/auth-service/internal/httpapi"
	"capstone/auth-service/internal/store"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	_ = godotenv.Load()
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pc, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Invalid database configuration")
	}
	pc.MaxConns = 12
	pc.MinConns = 2
	db, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		log.Fatal("Cannot initialize database")
	}
	defer db.Close()
	if db.Ping(ctx) != nil {
		log.Fatal("Cannot connect to database")
	}
	app := httpapi.New(cfg, store.Store{DB: db})
	stop, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer done()
	go func() { <-stop.Done(); _ = app.ShutdownWithTimeout(10 * time.Second) }()
	host := os.Getenv("BIND_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	if err = app.Listen(host + ":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
