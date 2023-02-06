package guard

import (
	"encoding/binary"
	"errors"
	//"gvisor.dev/gvisor/pkg/log"
)

const (
	EVP_GCM_TLS_EXPLICIT_IV_LEN = 8
	EVP_GCM_TLS_TAG_LEN         = 16
	ApplicationData             = byte(23)
	ChangeCipherSpec            = byte(20)
	Handshake                   = byte(22)
	Alert                       = byte(21)
)

type TLSRecord struct {
	// Type of Record
	ContentType byte
	// Protocol major version
	ProtMajor byte
	// Minor protocol version
	ProtMinor byte
	// Record length
	Length uint16
	// Record Data of size Length
	//AppData AEADApplicationData
	// The data in the record
	Data []byte
}

// Define the Application Record Type
type AEADApplicationData struct {
	// Additional data
	AddlData [13]byte
	// Explicit Nonce
	ExplicitIV [EVP_GCM_TLS_EXPLICIT_IV_LEN]byte
	// Ciphertext
	CipherText []byte
	// Tag
	Tag [EVP_GCM_TLS_TAG_LEN]byte
}

func TLSParseBytes(data []byte) ([]TLSRecord, error) {
	//log.Infof("[TLSParseBytes] Parsing TLSRecords")
	if data[0] != ApplicationData && data[0] != ChangeCipherSpec && data[0] != Handshake && data[0] != Alert {
		return nil, errors.New("Not a TLSRecord")
	}

	if len(data) < 5 {
		return nil, errors.New("Too Short")
	}

	var retSlice []TLSRecord
	l := 0
	prev_l := -1
	for {
		if l >= len(data) || prev_l == l {
			break
		}

		var ret TLSRecord
		ret.ContentType = data[l+0]
		ret.ProtMajor = data[l+1]
		ret.ProtMinor = data[l+2]
		ret.Length = binary.BigEndian.Uint16(data[l+3 : l+5])
		//ret.Data = make([]byte, ret.Length)
		//if ret.ContentType == ApplicationData {
		//	ret.AppData = parseAEADApplicationData(data[l+5 : l+5+int(ret.Length)])
		//}
		if l+5+int(ret.Length) <= len(data) {
			ret.Data = append(ret.Data, data[l+5:l+5+int(ret.Length)]...)
		} else {
			break
		}

		retSlice = append(retSlice, ret)
		prev_l = l
		l += int(ret.Length) + 5
	}
	//log.Infof("[TLSParseBytes] Finished parsing TLSRecords")
	return retSlice, nil
}

func parseAEADApplicationData(data []byte) AEADApplicationData {
	var ret AEADApplicationData
	if len(data) < 13+EVP_GCM_TLS_EXPLICIT_IV_LEN+EVP_GCM_TLS_TAG_LEN {
		return ret
	}

	//copy(ret.AddlData[:], data[:13])
	copy(ret.ExplicitIV[:], data[:EVP_GCM_TLS_EXPLICIT_IV_LEN])
	ret.CipherText = append(ret.CipherText, data[EVP_GCM_TLS_EXPLICIT_IV_LEN:]...)
	copy(ret.Tag[:], ret.CipherText[len(ret.CipherText)-EVP_GCM_TLS_TAG_LEN:])
	return ret
}
