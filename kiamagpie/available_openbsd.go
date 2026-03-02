//go:build openbsd
// +build openbsd

package main

import "golang.org/x/sys/unix"

func availableRAMBytes() int64 {
        if v, err := unix.SysctlUint64("hw.usermem64"); err == nil && v > 0 {
                return int64(v)
        }
        if v, err := unix.SysctlUint64("hw.physmem64"); err == nil && v > 0 {
                return int64(v)
        }
        if v, err := unix.SysctlUint32("hw.physmem"); err == nil && v > 0 {
                return int64(v)
        }
        return defaultAvailRAMBytes
}
