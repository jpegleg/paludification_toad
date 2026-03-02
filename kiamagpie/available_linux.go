//go:build linux
// +build linux

package main

import "golang.org/x/sys/unix"

func availableRAMBytes() int64 {
        var info unix.Sysinfo_t
        if err := unix.Sysinfo(&info); err == nil {
                unit := int64(info.Unit)
                if unit <= 0 {
                        unit = 1
                }
                free := int64(info.Freeram) * unit
                if free > 0 {
                        return free
                }
        }
        return defaultAvailRAMBytes
}
