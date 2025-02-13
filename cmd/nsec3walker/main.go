package main

import (
	"fmt"
	nsec3walker "github.com/vitezslav-lindovsky/nsec3walker/internal"
	"log"
)

func main() {
	config, err := nsec3walker.NewConfig()

	if err != nil {
		log.Fatalf("Error - %v\n", err)
	}

	if config.Help {
		return
	}

	if config.Domain == "" {
		log.Fatal("Provide a domain to walk.")
	}

	output, err := nsec3walker.NewOutput(config.FilePathPrefix)

	if err != nil {
		log.Fatal(err)
	}

	nw := nsec3walker.NewNSec3Walker(config, output)

	if config.DebugDomain != "" {
		err = nw.RunDebug(config.DebugDomain)

		x := nsec3walker.NewRangeIndex()
		fmt.Println(x)

	} else {
		err = nw.Run()
	}

	output.Close()

	if err != nil {
		output.Fatal(err)
	}
}
