package nsec3walker

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

const (
	GenericServers        = "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53"
	LogCounterIntervalSec = 30
	QuitAfterMin          = 15
)

type Config struct {
	DebugDomain           string
	Domain                string
	DomainDnsServers      []string
	FilePathPrefix        string
	GenericDnsServers     []string
	Help                  bool
	LogCounterIntervalSec uint
	QuitAfterMin          uint
	StopOnChange          bool
	Verbose               bool
}

func NewConfig() (config Config, err error) {
	long := "A tool for traversing NSEC3 DNS hashes for a specified domain using its authoritative NS servers.\n"
	long += "It will run until no hashes are received for X (default %d) minutes.\nSTDOUT - hashes\nSTDERR - logging\n"
	long = fmt.Sprintf(long, QuitAfterMin)

	var rootCmd = &cobra.Command{
		Use:           filepath.Base(os.Args[0]) + " [flags] domain",
		Short:         "NSEC3 Walker - Discover and traverse NSEC3 DNS hashes",
		Long:          long,
		Args:          cobra.ArbitraryArgs,
		SilenceErrors: true,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				config.Help = true
				_ = cmd.Help()

				return
			}

			if len(args) > 0 {
				config.Domain = args[0]
			}
		},
	}

	var genericServerInput string
	var domainServerInput string

	rootCmd.Flags().StringVar(&genericServerInput, "resolver", GenericServers, "Comma-separated list of generic DNS resolvers")
	rootCmd.Flags().StringVar(&domainServerInput, "domain-ns", "", "Comma-separated list of custom authoritative NS servers for the domain")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().BoolVarP(&config.Help, "help", "h", false, "Help!")
	rootCmd.Flags().UintVar(&config.LogCounterIntervalSec, "progress", LogCounterIntervalSec, "Counters print interval in seconds")
	rootCmd.Flags().UintVar(&config.QuitAfterMin, "quit-after", QuitAfterMin, "Quit after X minutes of no new hashes")
	rootCmd.Flags().StringVar(&config.DebugDomain, "debug-domain", "", "Will print debug info for a specified domain")
	rootCmd.Flags().StringVarP(&config.FilePathPrefix, "output", "o", "", "Path and prefix for output files. ../directory/prefix")
	rootCmd.Flags().BoolVar(&config.StopOnChange, "stop-on-change", false, "Will stop the walker if the zone changed")

	if err := rootCmd.Execute(); err != nil {
		return config, err
	}

	if config.Help {
		return config, nil
	}

	config.GenericDnsServers = parseDnsServers(genericServerInput)
	config.DomainDnsServers = parseDnsServers(domainServerInput)

	if len(config.DomainDnsServers) == 0 {
		config.DomainDnsServers, err = getAuthNsServers(config.Domain, config.GenericDnsServers)
	}

	if config.FilePathPrefix != "" {
		config.FilePathPrefix, err = GetOutputFilePrefix(config.FilePathPrefix, config.Domain)
	}

	return
}
