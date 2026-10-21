// Writes the files below SRC as stored and as deflated archives with Go's
// archive/zip, which streams every entry with a data descriptor.
//
//	go run ZipProducer.go SRC OUT
package main

import (
	"archive/zip"
	"io/fs"
	"os"
	"path/filepath"
)

func write(src, path string, method uint16) error {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	w := zip.NewWriter(out)
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		e, err := w.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(name), Method: method})
		if err != nil {
			return err
		}
		_, err = e.Write(data)
		return err
	})
	if err != nil {
		return err
	}
	return w.Close()
}

func main() {
	for name, method := range map[string]uint16{"go_store.zip": zip.Store, "go_deflate.zip": zip.Deflate} {
		if err := write(os.Args[1], filepath.Join(os.Args[2], name), method); err != nil {
			panic(err)
		}
	}
}
