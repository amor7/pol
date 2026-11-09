// Command pol forwards TCP ports from one server to another through a single
// encrypted HTTP/2 connection. See README.md.
package main

import (
	"os"

	"github.com/amor7/pol/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
