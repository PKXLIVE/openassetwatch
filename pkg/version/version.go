package version

import "fmt"

var (
	Name   = "OpenAssetWatch"
	Number = "0.1.0-foundation"
	Commit = "dev"
)

func String() string {
	return fmt.Sprintf("%s %s (%s)", Name, Number, Commit)
}
