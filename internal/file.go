package nsec3walker

import (
	"bufio"
	"os"
	"path/filepath"
	"time"
)

const (
	// TODO increase once I have Context and signal handling
	BuffSizeHash = 0
	BuffSizeMap  = 0
	PermFile     = 0644
	PermDir      = 0755
	SuffixHash   = ".hash"
	SuffixLog    = ".log"
	SuffixMap    = ".map"
)

type File struct {
	Name       string
	Pointer    *os.File
	Writer     *bufio.Writer
	BuffSizeKb int // BuffSizeKb size in bytes; 0 for auto-flush
}

type Files struct {
	HashFile *File
	LogFile  *File
	MapFile  *File
}

func NewFile(name string, buffSizeKb int) (file *File, err error) {
	fp, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, PermFile)

	if err != nil {
		return
	}

	buffSize := 0

	if buffSizeKb > 0 {
		buffSize = buffSizeKb * 1024
	}

	writer := bufio.NewWriterSize(fp, buffSize)

	file = &File{
		Name:       name,
		Pointer:    fp,
		Writer:     writer,
		BuffSizeKb: buffSizeKb,
	}

	return
}

func NewFiles(fileAbs string) (files *Files, err error) {
	files = &Files{}

	files.HashFile, err = NewFile(fileAbs+SuffixHash, BuffSizeHash)

	if err != nil {
		return
	}

	files.MapFile, err = NewFile(fileAbs+SuffixMap, BuffSizeMap)

	if err != nil {
		_ = files.HashFile.Close()

		return
	}

	files.LogFile, err = NewFile(fileAbs+SuffixLog, 0)

	if err != nil {
		_ = files.HashFile.Close()
		_ = files.MapFile.Close()
	}

	return
}

func (f *File) Write(data string) error {
	_, err := f.Writer.WriteString(data)

	if err != nil {
		return err
	}

	if f.BuffSizeKb == 0 {
		return f.Flush()
	}

	return nil
}

func (f *File) Flush() error {
	return f.Writer.Flush()
}

func (f *File) Close() error {
	if err := f.Flush(); err != nil {
		return err
	}

	return f.Pointer.Close()
}

func (fi *Files) Close() {
	_ = fi.HashFile.Close()
	_ = fi.MapFile.Close()
	_ = fi.LogFile.Close()
}

func GetOutputFilePrefix(path string, domain string) (absPath string, err error) {
	absPath, err = getAbsolutePath(path, domain)
	// check if its existing and/or writable?

	return
}

func getAbsolutePath(path string, domain string) (absPath string, err error) {
	absPath = filepath.Clean(absPath)
	absPath, err = filepath.Abs(path)

	if err != nil {
		return
	}

	info, err := os.Stat(absPath)

	if os.IsNotExist(err) {
		dir := filepath.Dir(absPath)

		if _, err = os.Stat(dir); err == nil {
			return
		}

		err = os.MkdirAll(dir, PermDir)

		return
	}

	if info.IsDir() {

		return filepath.Join(absPath, createFilePrefix(domain)), nil
	}

	return absPath, nil
}

func createFilePrefix(domain string) (prefix string) {
	date := time.Now().Format("2006_01_02-15_04") // 2025_02_24-13_59

	return domain + "-" + date
}
