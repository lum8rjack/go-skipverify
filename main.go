package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

var supportedPatches = map[string]Patches{
	"AMD64": Patches{
		VersionPatches: []VersionPatch{
			{GoVersion: "1.11",
				OldBytes: []byte{0x00, 0x0F, 0x85, 0xB3, 0x04, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x0F, 0x84, 0xB3, 0x04, 0x00, 0x00},
			},
			{GoVersion: "1.12",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x43, 0x05, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x43, 0x05, 0x00, 0x00},
			},
			{GoVersion: "1.13",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x32, 0x05, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x32, 0x05, 0x00, 0x00},
			},
			{GoVersion: "1.14",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x48, 0x05, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x48, 0x05, 0x00, 0x00},
			},
			{GoVersion: "1.15",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x3A, 0x06, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x3A, 0x06, 0x00, 0x00},
			},
			{GoVersion: "1.16",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x5A, 0x06, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x5A, 0x06, 0x00, 0x00},
			},
			{GoVersion: "1.17",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x7F, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x7F, 0x01, 0x00, 0x00},
			},
			{GoVersion: "1.18",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x7C, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x7C, 0x01, 0x00, 0x00},
			},
			{GoVersion: "1.19",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x7B, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x7B, 0x01, 0x00, 0x00},
			},
			{GoVersion: "1.20",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x84, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x84, 0x01, 0x00, 0x00},
			},
			{GoVersion: "1.21",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x82, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x82, 0x01, 0x00, 0x00},
			},
			{GoVersion: "1.22",
				OldBytes: []byte{0x00, 0x00, 0x0F, 0x85, 0x82, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x00, 0x00, 0x0F, 0x84, 0x82, 0x01, 0x00, 0x00},
			},
			{GoVersion: "1.23",
				OldBytes: []byte{0x41, 0x80, 0xBA, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x7E, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x41, 0x80, 0xBA, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x7E, 0x01, 0x00, 0x00},
			},
			{GoVersion: "1.24",
				OldBytes: []byte{0x41, 0x80, 0xBA, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x7E, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x41, 0x80, 0xBA, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x7E, 0x01, 0x00, 0x00},
			},
			{GoVersion: "1.25",
				OldBytes: []byte{0x41, 0x80, 0xBA, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x7E, 0x01, 0x00, 0x00},
				NewBytes: []byte{0x41, 0x80, 0xBA, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x7E, 0x01, 0x00, 0x00},
			},
		},
	},
	"ARM64": Patches{
		VersionPatches: []VersionPatch{
			{GoVersion: "1.23",
				OldBytes: []byte{0x0A, 0x81, 0x42, 0x39, 0x6A, 0x08, 0x00, 0x37, 0x01, 0x09, 0x40, 0xF9, 0x61, 0x00, 0x00, 0xB5},
				NewBytes: []byte{0x0A, 0x81, 0x42, 0x39, 0x6A, 0x08, 0x00, 0x36, 0x01, 0x09, 0x40, 0xF9, 0x61, 0x00, 0x00, 0xB5},
			},
			{GoVersion: "1.24",
				OldBytes: []byte{0x0A, 0x81, 0x42, 0x39, 0x6A, 0x08, 0x00, 0x37, 0x01, 0x09, 0x40, 0xF9, 0x61, 0x00, 0x00, 0xB5},
				NewBytes: []byte{0x0A, 0x81, 0x42, 0x39, 0x6A, 0x08, 0x00, 0x36, 0x01, 0x09, 0x40, 0xF9, 0x61, 0x00, 0x00, 0xB5},
			},
			{GoVersion: "1.25",
				OldBytes: []byte{0x0A, 0x81, 0x42, 0x39, 0xEA, 0x07, 0x00, 0x37, 0x01, 0x09, 0x40, 0xF9, 0x61, 0x00, 0x00, 0xB5},
				NewBytes: []byte{0x0A, 0x81, 0x42, 0x39, 0xEA, 0x07, 0x00, 0x36, 0x01, 0x09, 0x40, 0xF9, 0x61, 0x00, 0x00, 0xB5},
			},
		},
	},
}

type Patches struct {
	VersionPatches []VersionPatch
}

type VersionPatch struct {
	GoVersion string
	OldBytes  []byte
	NewBytes  []byte
}

type BinaryFile struct {
	Filename string
	OS       string
	Arch     string
}

func main() {
	inFile := flag.String("in", "", "Input file")
	outFile := flag.String("out", "", "Output file")
	flag.Parse()

	if *inFile == "" && *outFile == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	var fileDetails BinaryFile
	var majorVersion string

	if *inFile != "" {
		version, err := checkGoVersion(*inFile)
		if err != nil {
			log.Fatalf("Error checking Go version: %v", err)
		}

		if version == "" {
			log.Fatal("Go not detected")
		}

		fmt.Printf("Go version: %s\n", version)
		s := strings.Split(version, ".")
		if len(s) <= 1 {
			log.Fatalln("Invalid Go version")
		}

		majorVersion = fmt.Sprintf("%s.%s", s[0], s[1])
		majorVersion = strings.Replace(majorVersion, "go1", "1", 1)
		fmt.Printf("Major Go version: %s\n", majorVersion)

		fileDetails, err = getPeDetails(*inFile)
		if err != nil {
			fileDetails, err = getElfDetails(*inFile)
			if err != nil {
				fileDetails, err = getMachoDetails(*inFile)
				if err != nil {
					log.Fatalf("Error getting binary details: %v", err)
				}
			}
		}
	}

	fmt.Printf("File: %s\nOS: %s\nArch: %s\n", fileDetails.Filename, fileDetails.OS, fileDetails.Arch)

	if *outFile != "" {
		isSupported := false
		for supportedArch, _ := range supportedPatches {
			if fileDetails.Arch == supportedArch {
				for _, patch := range supportedPatches[supportedArch].VersionPatches {
					if patch.GoVersion == majorVersion {
						isSupported = true
						fmt.Printf("Patching for version: %s %s\n", supportedArch, patch.GoVersion)
						err := patchData(*inFile, *outFile, patch.OldBytes, patch.NewBytes)
						if err != nil {
							log.Fatalf("Error patching file: %v\n", err)
						}
						fmt.Printf("Successfully patched and saved to: %s\n", *outFile)
					}
				}
			}
		}

		if !isSupported {
			log.Fatalln("Unsupported binary (arch or Go version)")
		}
	}
}

func patchData(filename string, newfile string, oldbytes []byte, newbytes []byte) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	occur := bytes.Count(data, oldbytes)
	if occur == 0 {
		return errors.New("The required bytes for the patch was not found in the binary")
	}

	if occur > 1 {
		e := fmt.Sprintf("The patch was found more than once (%d times)\n", occur)
		return errors.New(e)
	}

	newdata := bytes.ReplaceAll(data, oldbytes, newbytes)

	if len(data) != len(newdata) {
		e := fmt.Sprintf("Patching lengths dont match: %d vs %d \n", len(data), len(newdata))
		return errors.New(e)
	}

	if bytes.Equal(data, newdata) {
		e := fmt.Sprintln("No patch found")
		return errors.New(e)
	}

	err = os.WriteFile(newfile, newdata, 0644)

	return err
}

func checkGoVersion(filename string) (string, error) {
	version := ""
	r := regexp.MustCompile(`go1\.[0-9]+(\.[0-9]+)`)
	data, err := os.ReadFile(filename)
	if err != nil {
		return version, err
	}

	result := r.FindAll(data, 1)
	if len(result) > 0 {
		version = string(result[0])
	}

	return version, nil
}

func getPeDetails(filename string) (BinaryFile, error) {
	bf := BinaryFile{
		Filename: filename,
		OS:       "Windows",
		Arch:     "unknown",
	}

	f, err := pe.Open(filename)
	if err != nil {
		return bf, err
	}
	defer f.Close()

	switch f.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		bf.Arch = "i386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		bf.Arch = "AMD64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		bf.Arch = "ARM64"
	default:
		bf.Arch = "unknown"
	}

	return bf, nil
}

func getElfDetails(filename string) (BinaryFile, error) {
	bf := BinaryFile{
		Filename: filename,
		OS:       "Linux",
		Arch:     "unknown",
	}

	f, err := elf.Open(filename)
	if err != nil {
		return bf, err
	}
	defer f.Close()

	switch f.FileHeader.Machine {
	case elf.EM_386:
		bf.Arch = "i386"
	case elf.EM_X86_64:
		bf.Arch = "AMD64"
	case elf.EM_AARCH64:
		bf.Arch = "ARM64"
	default:
		bf.Arch = "unknown"
	}

	return bf, nil
}

func getMachoDetails(filename string) (BinaryFile, error) {
	bf := BinaryFile{
		Filename: filename,
		OS:       "macOS",
		Arch:     "unknown",
	}

	f, err := macho.Open(filename)
	if err != nil {
		return bf, err
	}
	defer f.Close()

	bf.Arch = f.Cpu.String()
	a := strings.Split(f.Cpu.String(), "Cpu")
	if len(a) == 2 {
		bf.Arch = strings.ToUpper(a[1])
	}

	return bf, nil
}
