package traefik_users_blocker_plugin

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type Rule struct {
	AllowedSubPaths []string `json:"allowedSubPaths,omitempty"`
}

type Path struct {
	Path string `json:"base,omitempty"`
	Rule Rule   `json:"rule,omitempty"`
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
		if path.Path == "" {
			return nil, fmt.Errorf("Paths.Path cannot be empty")
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
		isPathMatched := strings.HasPrefix(req.URL.Path, path.Path)

		if !isPathMatched {
			a.next.ServeHTTP(rw, req)
			return
		}

		if len(path.Rule.AllowedSubPaths) == 0 {
			message := fmt.Sprintf("blocked path %s (matched with %s) for user %s", req.URL.Path, path.Path, userId)
			os.Stdout.WriteString(message)
			http.Error(rw, message, http.StatusForbidden)
			return
		}

		for _, allowedSubPath := range path.Rule.AllowedSubPaths {
			isAllowedSubPathMatched := strings.HasPrefix(req.URL.Path, path.Path+allowedSubPath)
			if !isAllowedSubPathMatched {
				message := fmt.Sprintf("blocked path %s (matched with %s) for user %s", req.URL.Path, path.Path+path.Path+allowedSubPath, userId)
				os.Stdout.WriteString(message)
				http.Error(rw, message, http.StatusForbidden)
				return
			}
		}
	}

	a.next.ServeHTTP(rw, req)
}
