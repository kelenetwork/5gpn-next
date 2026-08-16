//go:build !linux

package main

// disableTHP 在非 Linux 平台无操作：透明大页是 Linux 特有机制。
func disableTHP() {}
