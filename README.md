# NSEC3 Walker

A DNS zone hash collection tool that implements NSEC3 walking.
This tool retrieves DNS zone hashes which can later be cracked to discover existing (sub)domains.
Written in Go, working on Windows, MacOS, and Linux.

## Install

The project includes a Makefile supporting Linux, MacOS, and Windows builds. The default target is `make all`.

Available make targets:
```shell
make [all,linux,linux_amd64,linux_arm64,mac,mac_amd64,mac_arm64,windows,clean]
```

## Usage Examples

To scan an entire top-level domain:
```shell
go run main.go cz > cz.hash 2> cz.log
```

To scan a specific domain:
```shell
go run main.go seznam.cz > seznam.cz.hash 2> seznam.cz.log
```

Output handling:
- All NSEC3 hashes are written to STDOUT
- Logging information is written to STDERR

## Command Line Options

```shell
Usage:
  nsec3walker [flags] domain

Flags:
      --debug-domain string   Will print debug info for a specified domain
      --domain-ns string      Comma-separated list of custom authoritative NS servers for the domain
  -h, --help                  Help!
  -o, --output string         Path and prefix for output files. ../directory/prefix
      --progress uint         Counters print interval in seconds (default 30)
      --quit-after uint       Quit after X minutes of no new hashes (default 15)
      --resolver string       Comma-separated list of generic DNS resolvers (default "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53")
      --stop-on-change        Will stop the walker if the zone changed
  -v, --verbose               Enable verbose output

```

## Hash Cracking

The collected hashes can be cracked using `hashcat` with mode 8300.
The following example demonstrates cracking domains up to 10 characters long:

```shell
hashcat -m 8300 -a 3 --increment --custom-charset1 "?l?d-" cz.hash "?1?1?1?1?1?1?1?1?1?1"
```
