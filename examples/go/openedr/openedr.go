package openedr

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

type Scanner struct {
	dll            *syscall.LazyDLL
	fnInit         *syscall.LazyProc
	fnScanFile     *syscall.LazyProc
	fnScanBytes    *syscall.LazyProc
	fnScanURL      *syscall.LazyProc
	fnCheckReg     *syscall.LazyProc
	fnScanEvtx     *syscall.LazyProc
	fnScanSysEvts  *syscall.LazyProc
	fnCheckHosts   *syscall.LazyProc
	fnRestoreHosts *syscall.LazyProc
	fnFreeString   *syscall.LazyProc
}

func NewScanner(dllPath string, rulesDir string) (*Scanner, error) {
	dll := syscall.NewLazyDLL(dllPath)
	s := &Scanner{
		dll:          dll,
		fnInit:       dll.NewProc("openedr_static_init"),
		fnScanFile:   dll.NewProc("openedr_static_scan_file"),
		fnScanBytes:  dll.NewProc("openedr_static_scan_bytes"),
		fnScanURL:    dll.NewProc("openedr_static_scan_url"),
		fnCheckReg:   dll.NewProc("openedr_static_check_registry"),
		fnScanEvtx:   dll.NewProc("openedr_static_scan_evtx"),
		fnScanSysEvts: dll.NewProc("openedr_static_scan_system_events"),
		fnCheckHosts: dll.NewProc("openedr_static_check_hosts_file"),
		fnRestoreHosts: dll.NewProc("openedr_static_restore_hosts_file"),
		fnFreeString: dll.NewProc("openedr_static_free_string"),
	}

	var pDir uintptr
	if rulesDir != "" {
		b, _ := syscall.BytePtrFromString(rulesDir)
		pDir = uintptr(unsafe.Pointer(b))
	}

	r1, _, _ := s.fnInit.Call(pDir)
	if int32(r1) != 0 {
		return nil, errors.New("failed to initialize openedr static scanner engine")
	}

	return s, nil
}

func (s *Scanner) ptrToStringAndFree(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	defer s.fnFreeString.Call(ptr)

	// Scan until null terminator
	var bytes []byte
	p := unsafe.Pointer(ptr)
	for {
		b := *(*byte)(p)
		if b == 0 {
			break
		}
		bytes = append(bytes, b)
		p = unsafe.Pointer(uintptr(p) + 1)
	}
	return string(bytes)
}

func (s *Scanner) ScanFile(filePath string) (string, error) {
	b, err := syscall.BytePtrFromString(filePath)
	if err != nil {
		return "", err
	}
	r1, _, _ := s.fnScanFile.Call(uintptr(unsafe.Pointer(b)))
	return s.ptrToStringAndFree(r1), nil
}

func (s *Scanner) ScanBytes(data []byte, virtualName string) (string, error) {
	if len(data) == 0 {
		return "", errors.New("empty data slice")
	}
	bName, _ := syscall.BytePtrFromString(virtualName)
	r1, _, _ := s.fnScanBytes.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(bName)),
	)
	return s.ptrToStringAndFree(r1), nil
}

func (s *Scanner) ScanURL(url string) (string, error) {
	b, err := syscall.BytePtrFromString(url)
	if err != nil {
		return "", err
	}
	r1, _, _ := s.fnScanURL.Call(uintptr(unsafe.Pointer(b)))
	return s.ptrToStringAndFree(r1), nil
}

func (s *Scanner) CheckRegistry(regPath string) (string, error) {
	b, err := syscall.BytePtrFromString(regPath)
	if err != nil {
		return "", err
	}
	r1, _, _ := s.fnCheckReg.Call(uintptr(unsafe.Pointer(b)))
	return s.ptrToStringAndFree(r1), nil
}

// nullStr returns a NULL pointer for empty strings (DLL treats NULL as default).
func nullStr(str string) (uintptr, []byte) {
	if str == "" {
		return 0, nil
	}
	b, err := syscall.BytePtrFromString(str)
	if err != nil {
		return 0, nil
	}
	return uintptr(unsafe.Pointer(b)), b
}

func (s *Scanner) ScanEvtx(evtxPath string) (string, error) {
	b, err := syscall.BytePtrFromString(evtxPath)
	if err != nil {
		return "", err
	}
	r1, _, _ := s.fnScanEvtx.Call(uintptr(unsafe.Pointer(b)))
	return s.ptrToStringAndFree(r1), nil
}

func (s *Scanner) ScanSystemEvents() (string, error) {
	r1, _, _ := s.fnScanSysEvts.Call()
	return s.ptrToStringAndFree(r1), nil
}

func (s *Scanner) CheckHostsFile(hostsPath string) (string, error) {
	p, b := nullStr(hostsPath)
	r1, _, _ := s.fnCheckHosts.Call(p)
	runtime.KeepAlive(b)
	return s.ptrToStringAndFree(r1), nil
}

func (s *Scanner) RestoreHostsFile(hostsPath string, createBackup bool) (string, error) {
	p, b := nullStr(hostsPath)
	backup := uintptr(0)
	if createBackup {
		backup = 1
	}
	r1, _, _ := s.fnRestoreHosts.Call(p, backup)
	runtime.KeepAlive(b)
	return s.ptrToStringAndFree(r1), nil
}
