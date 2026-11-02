package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DatabaseURL, Port, InternalToken, UserToken, UserURL string
	CookieSecure                                         bool
}

func Load() (Config, error) {
	c := Config{DatabaseURL: os.Getenv("DATABASE_URL"), Port: os.Getenv("PORT"), InternalToken: os.Getenv("AUTH_INTERNAL_TOKEN"), UserToken: os.Getenv("USER_INTERNAL_TOKEN"), UserURL: strings.TrimRight(os.Getenv("USER_SERVICE_URL"), "/")}
	c.CookieSecure, _ = strconv.ParseBool(os.Getenv("COOKIE_SECURE"))
	if c.Port == "" {
		c.Port = "8081"
	}
	if c.DatabaseURL == "" || len(c.InternalToken) < 32 || len(c.UserToken) < 32 || c.UserURL == "" {
		return c, fmt.Errorf("DATABASE_URL, USER_SERVICE_URL and internal tokens (32+ characters) are required")
	}
	return c, nil
}
