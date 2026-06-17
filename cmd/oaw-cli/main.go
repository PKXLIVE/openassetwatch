package main

import (
	"flag"
	"fmt"

	"github.com/openassetwatch/openassetwatch/pkg/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	fmt.Println("OpenAssetWatch CLI foundation")
}
