// sshkeytx — transactional, lockout-safe authorized_keys changes over SSH.
package main

import (
	"os"

	"github.com/caoer/sshkeytx/internal/cli"
)

func main() {
	os.Exit(cli.Main())
}
