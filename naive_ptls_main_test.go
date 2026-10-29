//go:build with_purego && linux && amd64

package cronet

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	libraryPath, err := filepath.Abs("lib/linux_amd64/libcronet.so")
	if err == nil {
		if _, statErr := os.Stat(libraryPath); statErr != nil {
			fmt.Fprintln(os.Stderr, "skip PTLS tests: build or package linux/amd64 first:", statErr)
			os.Exit(0)
		}
		err = LoadLibrary(libraryPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "load libcronet:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
