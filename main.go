package traefik_users_blocker_plugin

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type Path struct {
	Base string `json:"base,omitempty"`
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
		if path.Base == "" {
			return nil, fmt.Errorf("Paths.Base cannot be empty")
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

	message := fmt.Sprintf("{requestPath: %s, userId: %s}\n", req.URL.Path, userId)
	os.Stdout.WriteString(message)

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
		isPathMatched := strings.HasPrefix(req.URL.Path, path.Base)

		if isPathMatched {
			message := fmt.Sprintf("blocked path %s (matched with %s) for user %s", req.URL.Path, path.Base, userId)
			os.Stdout.WriteString(message)
			http.Error(rw, message, http.StatusForbidden)
			return
		}
	}

	a.next.ServeHTTP(rw, req)
}
