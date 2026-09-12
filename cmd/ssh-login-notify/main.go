package main

import (
	"os"

	"github.com/lijiext/ssh-login-notify/internal/app"
)

func main() {
	os.Exit(app.Main(os.Args[1:]))
}
