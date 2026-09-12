package app

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func readHiddenLine(prompt string, reader *bufio.Reader) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := os.Stdin.Fd()
	var original syscall.Termios
	_, _, getErrno := syscall.Syscall6(
		syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&original)), 0, 0, 0,
	)
	terminal := getErrno == 0
	if terminal {
		updated := original
		updated.Lflag &^= syscall.ECHO
		_, _, setErrno := syscall.Syscall6(
			syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS),
			uintptr(unsafe.Pointer(&updated)), 0, 0, 0,
		)
		terminal = setErrno == 0
		if terminal {
			defer syscall.Syscall6(
				syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS),
				uintptr(unsafe.Pointer(&original)), 0, 0, 0,
			)
		}
	}
	line, err := reader.ReadString('\n')
	if terminal {
		fmt.Fprintln(os.Stderr)
	}
	return strings.TrimSpace(line), err
}
