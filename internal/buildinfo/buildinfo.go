// Package buildinfo holds what the release build stamps into the binary.
package buildinfo

// Version is set with -ldflags "-X github.com/amor7/pol/internal/buildinfo.Version=v1.2.3".
var Version = "dev"

// Repo is where releases are downloaded from.
const Repo = "amor7/pol"
