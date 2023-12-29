package bomSniffer

const (
	Utf8 = iota
	LittleEndian
	BigEndian
	Unknown
)

type bomSignature struct {
	sig     []byte
	bomType int
}

var bomSignatures = []bomSignature{
	{[]byte{0xEF, 0xBB, 0xBF}, Utf8},
	{[]byte{0xFF, 0xFE}, LittleEndian},
	{[]byte{0xFE, 0xFF}, BigEndian},
}

func Sniff(bSlice []byte) int {
	for _, signature := range bomSignatures {
		if len(signature.sig) > len(bSlice) {
			//we should probably be getting at least enough bytes for each encoding type, but if not skip
			continue
		}
		for i, b := range signature.sig {
			if b != bSlice[i] {
				//sig failed to match
				continue
			}
		}
		return signature.bomType
	}
	return Unknown
}
