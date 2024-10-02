package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/text/encoding/unicode"
)

type FileType int

const (
	ELF FileType = iota
	PE
)

type CompressionFlag int

const (
	NON_COMPRESSED CompressionFlag = iota
	COMPRESSED
)

type NuitkaExecutable struct {
	path         string
	fileType     FileType
	fPtr         *os.File
	streamReader io.Reader
	compressFlag CompressionFlag
	outputDir    string
}

func (ne *NuitkaExecutable) New(path, outputDir string) {
	ne.path = path
	ne.outputDir = outputDir
}

func (ne *NuitkaExecutable) Check() bool {
	var err error
	ne.fPtr, err = os.Open(ne.path)
	if err != nil {
		fmt.Printf("[!] Couldn't open %s\n", ne.path)
		return false
	}
	fmt.Println("[+] Processing", ne.path)

	// Rudimentary file check logic
	var magic = make([]byte, 4)
	ne.fPtr.Read(magic)
	if magic[0] == 0x4d && magic[1] == 0x5a {
		ne.fileType = PE
		fmt.Println("[+] File type: PE")
	} else if magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46 {
		fmt.Println("[+] File type: ELF")
		ne.fileType = ELF
	} else {
		fmt.Println("[!] Unsupported file type")
		return false
	}

	var streamPosition int64
	if ne.fileType == PE {
		streamPosition = LocateRCDataEnd(ne.path)
		if streamPosition == -1 {
			fmt.Println("[!] Failed to locate Nuitka data in PE resources")
			return false
		}
		streamPosition, _ = ne.fPtr.Seek(streamPosition-8, io.SeekStart)
	} else {
		streamPosition, _ = ne.fPtr.Seek(-8, io.SeekEnd)
	}

	var payLoadSize int64
	var payloadSizeBuf = make([]byte, 8)
	ne.fPtr.Read(payloadSizeBuf)
	binary.Read(bytes.NewReader(payloadSizeBuf), binary.LittleEndian, &payLoadSize)
	fmt.Println("[+] Payload size:", payLoadSize, "bytes")

	payLoadStartPos := streamPosition - payLoadSize
	ne.fPtr.Seek(payLoadStartPos, io.SeekStart)

	var nuitkaMagic = make([]byte, 3)
	ne.fPtr.Read(nuitkaMagic)

	if nuitkaMagic[0] == 'K' && nuitkaMagic[1] == 'A' {
		if nuitkaMagic[2] == 'X' {
			ne.compressFlag = NON_COMPRESSED
			fmt.Println("[+] Payload compression: false")
			return true
		} else if nuitkaMagic[2] == 'Y' {
			ne.compressFlag = COMPRESSED
			fmt.Println("[+] Payload compression: true")
			return true
		}
	}

	fmt.Println("[!] Nuitka magic header mismatch")
	return false
}

func (ne *NuitkaExecutable) readFileName() string {
	var buffer []byte
	if ne.fileType == PE {
		buffer = make([]byte, 2)
	} else {
		buffer = make([]byte, 1)
	}

	var fileName string

	for {
		ne.readChunk(buffer)
		if buffer[0] == 0 {
			break
		}
		fileName += string(buffer)
	}
	if ne.fileType == PE {
		utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		fileName, _ = utf16.String(fileName)
	}
	return fileName
}

func (ne *NuitkaExecutable) dumpFile(fileSize uint64, outpath string) {
	dir, _ := filepath.Split(outpath)
	os.MkdirAll(dir, 0755)

	f, err := os.Create(outpath)
	if err != nil {
		fmt.Println("[!] Couldn't write", outpath)
		return
	}

	remaining := int64(fileSize)

	for {
		nBytes, _ := io.CopyN(f, ne.streamReader, remaining)
		remaining -= nBytes
		if remaining == 0 {
			break
		}
	}
	f.Close()
}

func (ne *NuitkaExecutable) readChunk(buf []byte) {
	var read = 0

	for {
		nBytes, _ := ne.streamReader.Read(buf[read:])
		read += nBytes
		if read == len(buf) {
			break
		}
	}
}

func (ne *NuitkaExecutable) Extract() {
	if ne.compressFlag == COMPRESSED {
		var err error
		ne.streamReader, err = zstd.NewReader(ne.fPtr)
		if err != nil {
			fmt.Println("[!] Couldn't initialize zstd for decompression")
			return
		}
	} else {
		ne.streamReader = ne.fPtr
	}

	fmt.Println("[+] Beginning extraction...")
	os.Mkdir(ne.outputDir, 0755)

	total_files := 0

	for {
		fn := ne.readFileName()
		if fn == "" {
			break
		}
		if ne.fileType == ELF {
			var fileFlags = make([]byte, 1)
			ne.readChunk(fileFlags)
		}

		var fileSize uint64
		var fileSizeBuffer = make([]byte, 8)
		ne.readChunk(fileSizeBuffer)
		fileSize = binary.LittleEndian.Uint64(fileSizeBuffer)

		// Basic path sanitization
		ne.outputDir = strings.ReplaceAll(ne.outputDir, "..", "__")
		var outpath = filepath.Join(ne.outputDir, fn)
		ne.dumpFile(fileSize, outpath)
		total_files += 1
	}
	fmt.Println("[+] Total files:", total_files)
	fmt.Println("[+] Successfully extracted to", ne.outputDir)
}

func main() {
	// Updated flag handling
	outputDir := flag.String("output", "", "Specify the output directory for extracted files.")
	flag.Parse()

	if len(flag.Args()) == 0 || *outputDir == "" {
		fmt.Println("Usage: nuitka-extractor <output_directory> -output <filename>")
		return
	}

	// Using the new argument order
	ne := NuitkaExecutable{}
	ne.New(flag.Args()[0], *outputDir) // Here, we take the file path as the second argument
	if ne.Check() {
		ne.Extract()
	}
}
