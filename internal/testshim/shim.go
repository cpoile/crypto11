//go:build crypto11_testshim

// Package testshim reads the test forwarding module in the same process as crypto11.
package testshim

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
static void *library;
static unsigned long (*counter)(unsigned long);
static void (*fault)(unsigned long, unsigned long);
static int open_shim(char *path) {
 library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
 if (!library) return 0;
 counter = dlsym(library, "test_counter");
 fault = dlsym(library, "test_fault");
 return counter && fault;
}
static unsigned long read_counter(unsigned long i) { return counter(i); }
static void set_fault(unsigned long i, unsigned long code) { fault(i, code); }
*/
import "C"
import "unsafe"

// Open intentionally retains the module so counters survive last-owner finalization.
func Open(path string) bool {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	return C.open_shim(p) != 0
}
func Counter(index uint) uint    { return uint(C.read_counter(C.ulong(index))) }
func Fault(operation, code uint) { C.set_fault(C.ulong(operation), C.ulong(code)) }
