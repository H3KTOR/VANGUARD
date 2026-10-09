//go:build windows

package database

func setUmask(m int) int { return 0 }
