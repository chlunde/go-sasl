// +build gssapi
// +build linux darwin

package internal

/*
#cgo linux CFLAGS: -DGOOS_linux
#cgo linux LDFLAGS: -lgssapi_krb5 -lkrb5
#cgo darwin CFLAGS: -DGOOS_darwin
#cgo darwin LDFLAGS: -framework GSS
#include "gss_sasl.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// NameKind is the type of name used to canonicalize a credential.
type NameKind int

const (
	NTUserName = iota
	NTHostBasedService
)

// CredUsage is the way that a credential will be used.
type CredUsage int

const (
	Initiate = iota
	Accept
	Both
)

func AcquireCred(username, password string, nameKind NameKind, credUsage CredUsage) (*Cred, error) {
	var cusername *C.char
	var cpassword *C.char
	if username != "" {
		cusername = C.CString(username)
		defer C.free(unsafe.Pointer(cusername))
		if password != "" {
			cpassword = C.CString(password)
			defer C.free(unsafe.Pointer(cpassword))
		}
	}

	cred := &Cred{}

	var ckindOID C.gss_OID
	switch nameKind {
	case NTUserName:
		ckindOID = C.GSS_C_NT_USER_NAME
	case NTHostBasedService:
		ckindOID = C.GSS_C_NT_HOSTBASED_SERVICE
	default:
		return nil, fmt.Errorf("unrecognized NameKind")
	}

	var cusageOID C.gss_cred_usage_t
	switch credUsage {
	case Initiate:
		cusageOID = C.GSS_C_INITIATE
	case Accept:
		cusageOID = C.GSS_C_ACCEPT
	case Both:
		cusageOID = C.GSS_C_BOTH
	default:
		return nil, fmt.Errorf("unrecognized CredUsage")
	}

	var majorStatus C.OM_uint32
	var minorStatus C.OM_uint32
	status := C.gssapi_acquire_cred(&majorStatus, &minorStatus, cusername, cpassword, ckindOID, cusageOID, &cred.wrapped)
	if status != C.GSSAPI_OK {
		return nil, getError("unable to acquire credential", majorStatus, minorStatus)
	}

	return cred, nil
}

type Cred struct {
	name    string
	wrapped C.gss_cred_id_t
}

func (c *Cred) Release() {
	C.gssapi_release_cred(&c.wrapped)
}

func (c *Cred) Name() (string, error) {
	if c.name != "" {
		// Use what the user provided us if they provided something at all.
		// This ensures that we'll fail if the user thought they were
		// authenticating as someone else.
		return c.name, nil
	}

	// Otherwise, get it from the ticket.
	var cname *C.char
	var majorStatus C.OM_uint32
	var minorStatus C.OM_uint32
	status := C.gssapi_display_name(&majorStatus, &minorStatus, c.wrapped, &cname)
	if status != C.GSSAPI_OK {
		return "", getError("unable to get display name", majorStatus, minorStatus)
	}
	defer C.free(unsafe.Pointer(cname))
	c.name = C.GoString((*C.char)(unsafe.Pointer(cname)))
	return c.name, nil
}

func NewCtx(cred *Cred, spn string, delegate bool) *Ctx {
	return &Ctx{
		spn:      spn,
		cred:     cred,
		delegate: delegate,
	}
}

type Ctx struct {
	spn      string
	cred     *Cred
	delegate bool

	complete bool
	wrapped  C.gss_ctx_id_t
}

func (c *Ctx) Delete() {
	C.gssapi_delete_sec_context(&c.wrapped)
}

func (c *Ctx) Complete() bool {
	return c.complete
}

func (c *Ctx) Init(challenge []byte) ([]byte, error) {
	var buf unsafe.Pointer
	var bufLen C.size_t
	var outBuf unsafe.Pointer
	var outBufLen C.size_t

	if len(challenge) > 0 {
		buf = unsafe.Pointer(&challenge[0])
		bufLen = C.size_t(len(challenge))
	}

	cspn := C.CString(c.spn)
	defer C.free(unsafe.Pointer(cspn))

	var majorStatus C.OM_uint32
	var minorStatus C.OM_uint32
	var flags C.OM_uint32 = C.GSS_C_MUTUAL_FLAG | C.GSS_C_SEQUENCE_FLAG
	if c.delegate {
		flags |= C.GSS_C_DELEG_FLAG
	}

	status := C.gssapi_init_sec_context(&majorStatus, &minorStatus, c.cred.wrapped, &c.wrapped, cspn, flags, buf, bufLen, &outBuf, &outBufLen)
	if outBuf != nil {
		defer C.free(outBuf)
	}

	switch status {
	case C.GSSAPI_OK:
		c.complete = true
	case C.GSSAPI_CONTINUE:
	default:
		return nil, getError("unable to initialize security context", majorStatus, minorStatus)
	}

	return C.GoBytes(outBuf, C.int(outBufLen)), nil
}

func (c *Ctx) WrapMessage(msg []byte) ([]byte, error) {
	var buf unsafe.Pointer
	var bufLen C.size_t
	var outBuf unsafe.Pointer
	var outBufLen C.size_t

	buf = unsafe.Pointer(&msg[0])
	bufLen = C.size_t(len(msg))

	var majorStatus C.OM_uint32
	var minorStatus C.OM_uint32
	status := C.gssapi_wrap_msg(&majorStatus, &minorStatus, c.wrapped, buf, bufLen, &outBuf, &outBufLen)
	if status != C.GSSAPI_OK {
		return nil, getError("unable to wrap message", majorStatus, minorStatus)
	}

	if outBuf != nil {
		defer C.free(outBuf)
	}

	return C.GoBytes(outBuf, C.int(outBufLen)), nil
}

func getError(prefix string, majorStatus, minorStatus C.OM_uint32) error {
	var desc *C.char

	status := C.gssapi_error_desc(majorStatus, minorStatus, &desc)
	if status != C.GSSAPI_OK {
		if desc != nil {
			C.free(unsafe.Pointer(desc))
		}

		return fmt.Errorf("%s: (%v, %v)", prefix, int32(majorStatus), int32(minorStatus))
	}
	defer C.free(unsafe.Pointer(desc))

	return fmt.Errorf("%s: %v(%v,%v)", prefix, C.GoString(desc), int32(majorStatus), int32(minorStatus))
}
