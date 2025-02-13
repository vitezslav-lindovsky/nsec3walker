package nsec3walker

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
)

type Output struct {
	files *Files
}

func NewOutput(filePrefix string) (output *Output, err error) {
	output = &Output{}

	if filePrefix != "" {
		output.files, err = NewFiles(filePrefix)
	}

	return
}

func (o *Output) Hash(hash string, nsec Nsec3Params) {
	msg := fmt.Sprintf("%s:.%s:%s:%d\n", hash, nsec.domain, nsec.salt, nsec.iterations)

	if !o.isFileOutput() {
		fmt.Print(msg)

		return
	}

	err := o.files.HashFile.Write(msg)

	if err != nil {
		log.Fatal(err)
	}
}

func (o *Output) Log(message string) {
	log.Println(message)

	if o.isFileOutput() {
		err := o.files.LogFile.Write(message + "\n")

		if err != nil {
			log.Fatal(err)
		}

	}
}

func (o *Output) Fatal(err error) {
	log.Fatal(err)
}

func (o *Output) isFileOutput() bool {
	return o.files != nil
}

func (o *Output) Map(hash Nsec3Record, salt string, iterations uint16) {
	if !o.isFileOutput() {
		return
	}

	var types []string

	for _, t := range hash.Types {
		types = append(types, dns.TypeToString[t])
	}

	msg := "%s;%s;%s;%d;%s\n"
	msg = fmt.Sprintf(msg, hash.Start, hash.End, salt, iterations, strings.Join(types, ","))

	err := o.files.MapFile.Write(msg)

	if err != nil {
		log.Fatal(err)
	}
}

func (o *Output) Close() {
	o.files.Close()
}
