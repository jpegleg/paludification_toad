//go:build !linux && !openbsd
// +build !linux,!openbsd

package main

func availableRAMBytes() int64 {
        return defaultAvailRAMBytes
}
