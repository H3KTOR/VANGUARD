//go:build !windows

package database

import "syscall"

func setUmask(m int) int { return syscall.Umask(m) }
