// Package example a example plugin.
package UsersBlocker

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type Path struct {
	Prefix      string `json:"prefix,omitempty"`
	MustContain string `json:"mustContain,omitempty"`
}

type Config struct {
	UserIds []string `json:"userIds,omitempty"`
	Paths   []Path   `json:"paths,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		UserIds: make([]string, 0),
		Paths:   make([]Path, 0),
	}
}

type UsersBlocker struct {
	next   http.Handler
	userId []string
	paths  []Path
	name   string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.UserIds) == 0 {
		return nil, fmt.Errorf("UserIds cannot be empty")
	}

	for _, path := range config.Paths {
		if path.Prefix == "" {
			return nil, fmt.Errorf("Paths.Prefix cannot be empty")
		}
	}

	return &UsersBlocker{
		next:   next,
		name:   name,
		userId: config.UserIds,
		paths:  config.Paths,
	}, nil
}

func (a *UsersBlocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	userId := req.Header["X-Auth-User-Id"][0]

	var isUserBlocked bool

	for _, id := range a.userId {
		if id == userId {
			isUserBlocked = true
		}
	}

	if !isUserBlocked {
		a.next.ServeHTTP(rw, req)
		return
	}

	for _, path := range a.paths {
		isPathBlocked := strings.HasPrefix(req.URL.Path, path.Prefix)

		if isPathBlocked && path.MustContain != "" {
			isPathBlocked = !strings.Contains(req.URL.Path, path.MustContain)
		}

		if isPathBlocked {
			http.Error(rw, "Forbidden", http.StatusForbidden)
			return
		}
	}

	a.next.ServeHTTP(rw, req)
}
