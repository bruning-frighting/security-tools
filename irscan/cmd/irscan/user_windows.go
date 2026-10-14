//go:build windows

package main

import "os/user"

func currentUserName() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}
