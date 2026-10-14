//go:build windows

package collect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Windows registry collector, implemented with direct advapi32 calls.
//
// No child processes: PLAN.md 5.4 requires native APIs over spawning reg.exe, both because
// spawning is noisy on a host under investigation and because command-line arguments of the
// scanner's own children pollute the very telemetry an analyst is reviewing.
//
// VERIFICATION STATUS: this file is COMPILE- AND VET-VERIFIED ONLY. It has never been
// executed. Smart App Control on the build host blocks all unsigned binaries, so no Windows
// build of irscan can run in this environment (DECISIONS.md B-001). Every check that depends
// on it is therefore capped at FIXTURE_TESTED and is exercised through FakeRegistry.

var (
	advapi32          = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW = advapi32.NewProc("RegOpenKeyExW")
	procRegEnumKeyExW = advapi32.NewProc("RegEnumKeyExW")
	procRegEnumValueW = advapi32.NewProc("RegEnumValueW")
	procRegQueryInfo  = advapi32.NewProc("RegQueryInfoKeyW")
	procRegCloseKey   = advapi32.NewProc("RegCloseKey")
)

const (
	hkeyClassesRoot   = 0x80000000
	hkeyCurrentUser   = 0x80000001
	hkeyLocalMachine  = 0x80000002
	hkeyUsers         = 0x80000003
	hkeyCurrentConfig = 0x80000005

	// KEY_READ. Deliberately read-only: no KEY_SET_VALUE, no KEY_CREATE_SUB_KEY. The tool
	// has no code path that could write to the registry even if asked.
	keyRead = 0x20019
	// KEY_WOW64_64KEY forces the 64-bit view so a 32-bit build cannot be silently
	// redirected into Wow6432Node and miss 64-bit persistence.
	keyWow6464 = 0x0100

	errSuccess      = 0
	errFileNotFound = 2
	errAccessDenied = 5
	errNoMoreItems  = 259
	errMoreData     = 234

	regSZ       = 1
	regExpandSZ = 2
	regBinary   = 3
	regDWord    = 4
	regMultiSZ  = 7
	regQWord    = 11
)

var hiveByName = map[string]uintptr{
	"HKLM": hkeyLocalMachine, "HKEY_LOCAL_MACHINE": hkeyLocalMachine,
	"HKCU": hkeyCurrentUser, "HKEY_CURRENT_USER": hkeyCurrentUser,
	"HKU": hkeyUsers, "HKEY_USERS": hkeyUsers,
	"HKCR": hkeyClassesRoot, "HKEY_CLASSES_ROOT": hkeyClassesRoot,
	"HKCC": hkeyCurrentConfig, "HKEY_CURRENT_CONFIG": hkeyCurrentConfig,
}

type WindowsRegistry struct{}

func NewWindowsRegistry() *WindowsRegistry { return &WindowsRegistry{} }

func (w *WindowsRegistry) Name() string { return "registry:windows-advapi32" }

func (w *WindowsRegistry) Available() (bool, string) { return true, "" }

func (w *WindowsRegistry) openKey(hive, path string) (syscall.Handle, error) {
	root, ok := hiveByName[strings.ToUpper(strings.TrimRight(hive, `\`))]
	if !ok {
		return 0, fmt.Errorf("unknown registry hive %q", hive)
	}
	p, err := syscall.UTF16PtrFromString(strings.Trim(path, `\`))
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	r, _, _ := procRegOpenKeyExW.Call(
		root, uintptr(unsafe.Pointer(p)), 0, keyRead|keyWow6464,
		uintptr(unsafe.Pointer(&h)),
	)
	switch r {
	case errSuccess:
		return h, nil
	case errAccessDenied:
		return 0, fmt.Errorf("%w: opening %s\\%s", ErrPermission, hive, path)
	case errFileNotFound:
		return 0, fmt.Errorf("registry key not found: %s\\%s", hive, path)
	default:
		return 0, fmt.Errorf("RegOpenKeyEx(%s\\%s) failed with code %d", hive, path, r)
	}
}

func (w *WindowsRegistry) KeyExists(hive, path string) bool {
	h, err := w.openKey(hive, path)
	if err != nil {
		return false
	}
	procRegCloseKey.Call(uintptr(h))
	return true
}

func (w *WindowsRegistry) OpenKey(hive, path string) (RegKeyInfo, error) {
	h, err := w.openKey(hive, path)
	if err != nil {
		return RegKeyInfo{}, err
	}
	defer procRegCloseKey.Call(uintptr(h))

	info := RegKeyInfo{Path: strings.TrimRight(hive, `\`) + `\` + strings.Trim(path, `\`)}

	var subKeyCount, maxSubKeyLen, valueCount, maxValueNameLen, maxValueLen uint32
	var ft syscall.Filetime
	r, _, _ := procRegQueryInfo.Call(
		uintptr(h), 0, 0, 0,
		uintptr(unsafe.Pointer(&subKeyCount)),
		uintptr(unsafe.Pointer(&maxSubKeyLen)),
		0,
		uintptr(unsafe.Pointer(&valueCount)),
		uintptr(unsafe.Pointer(&maxValueNameLen)),
		uintptr(unsafe.Pointer(&maxValueLen)),
		0,
		uintptr(unsafe.Pointer(&ft)),
	)
	if r == errSuccess {
		// The key's last-write time is frequently the only timestamp available for
		// registry-based persistence, so it is captured whenever the API supplies it.
		info.LastWrite = time.Unix(0, ft.Nanoseconds()).UTC()
		info.LastWriteKnown = !info.LastWrite.IsZero()
	}

	info.SubKeys = w.enumSubKeys(h, maxSubKeyLen)
	info.Values = w.enumValues(h, maxValueNameLen, maxValueLen)
	sort.Strings(info.SubKeys)
	sort.Slice(info.Values, func(i, j int) bool { return info.Values[i].Name < info.Values[j].Name })
	return info, nil
}

func (w *WindowsRegistry) enumSubKeys(h syscall.Handle, maxLen uint32) []string {
	if maxLen == 0 {
		maxLen = 256
	}
	buf := make([]uint16, maxLen+2)
	var out []string
	for i := uint32(0); ; i++ {
		n := uint32(len(buf))
		r, _, _ := procRegEnumKeyExW.Call(
			uintptr(h), uintptr(i),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)),
			0, 0, 0, 0,
		)
		if r == errNoMoreItems {
			break
		}
		if r == errMoreData {
			buf = make([]uint16, len(buf)*2)
			i--
			continue
		}
		if r != errSuccess {
			break
		}
		out = append(out, syscall.UTF16ToString(buf[:n]))
	}
	return out
}

func (w *WindowsRegistry) enumValues(h syscall.Handle, maxNameLen, maxDataLen uint32) []RegValue {
	if maxNameLen == 0 {
		maxNameLen = 256
	}
	if maxDataLen == 0 {
		maxDataLen = 1024
	}
	nameBuf := make([]uint16, maxNameLen+2)
	dataBuf := make([]byte, maxDataLen+8)
	var out []RegValue

	for i := uint32(0); ; i++ {
		nameLen := uint32(len(nameBuf))
		dataLen := uint32(len(dataBuf))
		var valType uint32
		r, _, _ := procRegEnumValueW.Call(
			uintptr(h), uintptr(i),
			uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
			0,
			uintptr(unsafe.Pointer(&valType)),
			uintptr(unsafe.Pointer(&dataBuf[0])), uintptr(unsafe.Pointer(&dataLen)),
		)
		if r == errNoMoreItems {
			break
		}
		if r == errMoreData {
			nameBuf = make([]uint16, len(nameBuf)*2)
			dataBuf = make([]byte, len(dataBuf)*2)
			i--
			continue
		}
		if r != errSuccess {
			break
		}
		out = append(out, decodeRegValue(
			syscall.UTF16ToString(nameBuf[:nameLen]), valType, dataBuf[:dataLen]))
	}
	return out
}

func decodeRegValue(name string, typ uint32, data []byte) RegValue {
	v := RegValue{Name: name}
	switch typ {
	case regSZ, regExpandSZ:
		v.Type = RegSZ
		if typ == regExpandSZ {
			v.Type = RegExpandSZ
		}
		v.String = utf16BytesToString(data)
	case regMultiSZ:
		v.Type = RegMultiSZ
		for _, s := range strings.Split(utf16BytesToString(data), "\x00") {
			if s != "" {
				v.Multi = append(v.Multi, s)
			}
		}
		v.String = strings.Join(v.Multi, " | ")
	case regDWord:
		v.Type = RegDWord
		if len(data) >= 4 {
			v.Number = uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 |
				uint64(data[3])<<24
		}
		v.String = strconv.FormatUint(v.Number, 10)
	case regQWord:
		v.Type = RegQWord
		if len(data) >= 8 {
			for i := 0; i < 8; i++ {
				v.Number |= uint64(data[i]) << (8 * i)
			}
		}
		v.String = strconv.FormatUint(v.Number, 10)
	case regBinary:
		v.Type = RegBinary
		v.BinaryLen = len(data)
		// Binary payloads are not retained: they are frequently large, rarely
		// triage-relevant as raw bytes, and keeping them would breach the evidence budget.
		// Length plus a hash is what an analyst can actually use.
		v.String = fmt.Sprintf("[REG_BINARY %d bytes, sha256=%s]", len(data), sha256Hex(data))
	default:
		v.Type = RegOtherType
		v.BinaryLen = len(data)
		v.String = fmt.Sprintf("[type %d, %d bytes]", typ, len(data))
	}
	return v
}

func utf16BytesToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	// Trim the trailing NUL that REG_SZ values carry.
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16Decode(u))
}

func utf16Decode(u []uint16) []rune {
	out := make([]rune, 0, len(u))
	for i := 0; i < len(u); i++ {
		switch {
		case u[i] >= 0xD800 && u[i] < 0xDC00 && i+1 < len(u) &&
			u[i+1] >= 0xDC00 && u[i+1] < 0xE000:
			r := (rune(u[i]-0xD800) << 10) | rune(u[i+1]-0xDC00) + 0x10000
			out = append(out, r)
			i++
		default:
			out = append(out, rune(u[i]))
		}
	}
	return out
}

// UserHives enumerates loaded per-user hives under HKU.
//
// Enumerating HKU rather than reading HKCU is deliberate: HKCU only reflects the account
// running the scan, so an HKCU-only check would miss Run-key persistence planted under every
// other user on the box -- which is where it usually is.
func (w *WindowsRegistry) UserHives() ([]UserHive, error) {
	info, err := w.OpenKey("HKU", "")
	if err != nil {
		return nil, err
	}
	var out []UserHive
	for _, sid := range info.SubKeys {
		// Skip the _Classes companion hives and the non-SID well-known entries.
		if strings.HasSuffix(sid, "_Classes") || !strings.HasPrefix(sid, "S-1-") {
			continue
		}
		h := UserHive{SID: sid, Root: sid}
		// Best-effort username resolution from the ProfileList. A failure here is cosmetic.
		if pl, perr := w.OpenKey("HKLM",
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid); perr == nil {
			for _, v := range pl.Values {
				if strings.EqualFold(v.Name, "ProfileImagePath") {
					parts := strings.Split(strings.ReplaceAll(v.String, "/", `\`), `\`)
					h.Username = parts[len(parts)-1]
				}
			}
		}
		out = append(out, h)
	}
	return out, nil
}
