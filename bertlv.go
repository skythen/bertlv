// Package bertlv implements parsing and building of BER-TLV structures.
package bertlv

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

const (
	packageTag string = "skythen/bertlv"
)

// BerTag represents the tag of a BER-TLV structure.
type BerTag []byte

// BerTLV represents a BER-TLV structure.
type BerTLV struct {
	Tag      BerTag
	Value    []byte
	children []BerTLV
}

// BerTLVs is a slice of BerTLV.
type BerTLVs []BerTLV

// Builder is used for building BER-TLV structures. Use the Add functions to add data.
// You can nest Builders to create constructed BER-TLV structures.
type Builder struct {
	position int
	bytes    []byte
}

// NewBerTLV returns a new BerTLV.
// If the BerTag of the BerTLV indicates a constructed structure, the value is recursively parsed and checked.
// Child BerTLV structures can then be retrieved with Children and FirstChild.
// Any errors that occur while parsing child TLVs are returned.
func NewBerTLV(t BerTag, v []byte) (*BerTLV, error) {
	if t.IsConstructed() {
		cpy := v

		children := make([]BerTLV, 0)

		for len(cpy) > 0 {
			tlv, tlvLen, err := parseBerTLV(cpy)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("%s: failed to create new BerTLV because of invalid content of constructed object with tag %02X", packageTag, t))
			}

			children = append(children, tlv)
			cpy = cpy[tlvLen:]
		}

		return &BerTLV{Tag: t, Value: v, children: children}, nil
	}

	return &BerTLV{Tag: t, Value: v}, nil
}

// NewOneByteTag returns a new BerTag with a one byte BER tag.
// The encoding of the tag is not checked to make it easier to use with the builder pattern.
// If the encoding of a BerTag needs to be checked, use the CheckEncoding function.
func NewOneByteTag(b byte) BerTag {
	return []byte{b}
}

// NewTwoByteTag returns a new BerTag with a two byte BER tag.
// The encoding of the tag is not checked to make it easier to use with the builder pattern.
// If the encoding of a BerTag needs to be checked, use the CheckEncoding function.
func NewTwoByteTag(fb byte, sb byte) BerTag {
	return []byte{fb, sb}
}

// NewThreeByteTag returns a new BerTag with a three byte BER tag.
// The encoding of the tag is not checked to make it easier to use with the builder pattern.
// If the encoding of a BerTag needs to be checked, use the CheckEncoding function.
func NewThreeByteTag(fb byte, sb byte, tb byte) BerTag {
	return []byte{fb, sb, tb}
}

// Parse parses the given byte slice and returns BerTLVs (a slice of BerTLV).
// If the slice contains constructed TLV structures, these structures are parsed recursively.
// Any errors that occur while parsing are returned.
func Parse(b []byte) (BerTLVs, error) {
	if len(b) == 0 {
		return BerTLVs{}, fmt.Errorf("%s: failed to parse BER-TLVs - tlv has length 0", packageTag)
	}

	var result []BerTLV

	for len(b) > 0 {
		tlvs, tlvLen, err := parseBerTLV(b)
		if err != nil {
			return BerTLVs{}, err
		}

		result = append(result, tlvs)
		b = b[tlvLen:]
	}

	return result, nil
}

func parseBerTLV(b []byte) (BerTLV, int, error) {
	var (
		tLen int
		t    BerTag
		lLen int
		l    int
	)

	// parse tag
	// get length of tag
	t, err := parseTag(b)
	if err != nil {
		return BerTLV{}, 0, errors.Wrap(err, fmt.Sprintf("%s: failed to parse BER-TLV - invalid tag: %02X", packageTag, b))
	}

	tLen = len(t)

	// parse length
	// get length of length
	l, lLen, err = parseLength(b[tLen:])
	if err != nil {
		return BerTLV{}, 0, errors.Wrap(err, fmt.Sprintf("%s: failed to parse BER-TLV - tag %02X: invalid length encoding ", packageTag, t))
	}

	endIndex := len(b) - 1
	indicatedEndIndex := tLen + lLen + l - 1

	if indicatedEndIndex > endIndex {
		return BerTLV{}, 0, fmt.Errorf("%s: failed to parse BER-TLV - tag %02X: indicated length of value is out of bounds. indicated end index: %d : actual end index %d", packageTag, t, indicatedEndIndex, endIndex)
	}

	// parse value
	v := b[tLen+lLen : tLen+lLen+l]

	var result BerTLV

	if len(v) > 0 {
		result = BerTLV{
			Tag:   t,
			Value: v,
		}
	} else {
		return BerTLV{Tag: t}, tLen + lLen, nil
	}

	// check if tlv is constructed and contains a tlv structure
	if t.IsConstructed() {
		result.children = make([]BerTLV, 0)

		cv := v

		for len(cv) > 0 {
			tChild, cLen, err := parseBerTLV(cv)
			if err != nil {
				return BerTLV{}, 0, errors.Wrap(err, fmt.Sprintf("%s: failed to parse BER-TLV - tag %02X: error while parsing child TLV of constructed object", packageTag, t))
			}

			result.children = append(result.children, tChild)
			cv = cv[cLen:]
		}
	}

	return result, tLen + lLen + l, nil
}

func parseTag(b []byte) (BerTag, error) {
	if b[0]&0x1F == 0x1F {
		if len(b) < 2 {
			return BerTag{}, errors.New("failed to parse tag - first byte indicates that tag is encoded with more than one byte, but following byte are missing")
		}

		if b[1]&0x80 == 0x80 {
			if len(b) < 3 {
				return BerTag{}, errors.New("failed to parse tag - first two byte indicate that tag is encoded with three byte, but following byte are missing")
			}

			return NewThreeByteTag(b[0], b[1], b[2]), nil
		}

		return NewTwoByteTag(b[0], b[1]), nil
	}

	return NewOneByteTag(b[0]), nil
}

func parseLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("failed to parse length - is empty")
	}
	// one byte length encoding for values smaller than 127
	if b[0] <= 0x7F {
		return int(b[0]), 1, nil
	}

	// two byte length encoding for values between 128 - 255
	if b[0] == 0x81 {
		if len(b)-1 <= 0 {
			return 0, 0, errors.New("failed to parse length - first byte indicates that length is encoded with two byte, but following byte are missing")
		}

		return int(b[1]), 2, nil
	}

	// three byte length encoding for values between 256 - 65535
	if b[0] == 0x82 {
		if len(b)-2 <= 0 {
			return 0, 0, errors.New("failed to parse length - first byte indicates that length is encoded with three byte, but following byte are missing")
		}

		return int(binary.BigEndian.Uint16(b[1:3])), 3, nil
	}

	return 0, 0, errors.New("failed to parse length - if length is greater than 127, first byte must indicate encoding of length")
}

func buildLen(l int) []byte {
	if l == 0 {
		return []byte{0x00}
	}

	if l <= 127 {
		return []byte{byte(l)}
	}

	if l <= 255 {
		return []byte{0x81, byte(l)}
	}

	return []byte{0x82, (byte)(l>>8) & 0xFF, (byte)(l & 0xFF)}
}

// CheckEncoding checks if the encoding of the BerTag - that is the indication of subsequent tag bytes - is correct.
// If the encoding is correct, CheckEncoding returns nil, otherwise an error with details is returned.
func (t BerTag) CheckEncoding() error {
	l := len(t)

	if l > 3 {
		return fmt.Errorf("tags must consist of a maximum of three byte, found %d", len(t))
	}

	if l == 1 {
		if t[0]&0x1F == 0x1F {
			return errors.New("t consists of one byte but indicates that more byte follow")
		}
	} else {
		if t[0]&0x1F != 0x1F {
			return fmt.Errorf("t consists of %d byte but first byte does not indicate that more byte follow", len(t))
		}

		if l == 2 {
			if t[1]&0x80 == 0x80 {
				return errors.New("t consists of 2 byte but indicates that more byte follow")
			}
		} else {
			if t[1]&0x80 != 0x80 {
				return errors.New("t consists of 3 byte but second byte does not indicate that more byte follow")
			}
		}
	}

	return nil
}

// IsConstructed returns true if the first byte of a BerTag indicates a constructed TLV structure (b6 is set), otherwise false.
func (t BerTag) IsConstructed() bool {
	if len(t) == 0 {
		return false
	}

	return t[0]&0x20 != 0
}

// Bytes returns a []byte containing the byte representation of BerTLVs.
// BerTLV.Bytes is called sequentially on the fields of the underlying BerTLV slice (starting with index 0).
func (t BerTLVs) Bytes() []byte {
	var b []byte
	for _, tlv := range t {
		b = append(b, tlv.Bytes()...)
	}

	return b
}

// FindAllWithTag returns a []BerTLV with all BerTLV that are contained in the underlying BerTLV slice whose
// tag matches the given BerTag in the order they are found (starting with index 0).
// Returns nil if no matching BerTLV are found.
// Please note that child structures of constructed BER-TLVs are not evaluated.
// Use BerTLV.Children or BerTLV.FirstChild to search for child structures in the returned BerTLV.
func (t BerTLVs) FindAllWithTag(tag BerTag) []BerTLV {
	var berTLVS []BerTLV

	for _, tlv := range t {
		if bytes.Equal(tlv.Tag, tag) {
			berTLVS = append(berTLVS, tlv)
		}
	}

	return berTLVS
}

// FindFirstWithTag returns the first BerTLV of the underlying BerTLV slice whose tag matches the given BerTag.
// Returns nil if no matching BerTLV is found.
// Please note that child structures of constructed BER-TLVs are not evaluated.
// Use BerTLV.Children or BerTLV.FirstChild to search for child structures in the returned BerTLV.
func (t BerTLVs) FindFirstWithTag(tag BerTag) *BerTLV {
	for _, tlv := range t {
		if bytes.Equal(tlv.Tag, tag) {
			return &tlv
		}
	}

	return nil
}

// Bytes returns a byte slice containing the byte representation of BerTLV (Tag | Length | Value).
// If the value of a BerTLV exceeds a length of 65535 it gets truncated.
func (ber BerTLV) Bytes() []byte {
	var (
		tLen int
		lLen int
		lVal int
		t    []byte
		l    []byte
	)

	lVal = len(ber.Value)

	if lVal > 65535 {
		ber.Value = ber.Value[:65535]
		lVal = 65535
	}

	l = buildLen(lVal)
	tLen = len(ber.Tag)

	if tLen > 0 && tLen <= 3 {
		t = ber.Tag
	} else if tLen == 0 {
		// fill empty tag
		t = []byte{0x00}
		tLen = 1
	} else {
		// truncate tag to three byte
		tLen = 3
		t = ber.Tag[:tLen]
	}

	lLen = len(l)

	result := make([]byte, 0, tLen+lLen+lVal)
	result = append(result, t...)
	result = append(result, l...)
	result = append(result, ber.Value...)

	return result
}

// BytesLength returns the length of the byte representation of the BerTLV.
// If the value of a BerTLV exceeds a length of 65535 it gets truncated.
func (ber BerTLV) BytesLength() int {
	lVal := len(ber.Value)
	if lVal > 65535 {
		lVal = 65535
	}

	return len(ber.Tag) + len(buildLen(lVal)) + lVal
}

// Children returns a BerTLV slice with all child BerTLV that are contained in the constructed BerTLV.
// If a tag is passed, child TLVs are filtered by the given tag and added to the result in the order they are found.
// Returns nil if no matching BerTLV are found or the BerTLV is not constructed.
// Please note that child BerTLV of constructed children are not evaluated.
func (ber BerTLV) Children(tag BerTag) []BerTLV {
	var berTLVS []BerTLV

	if len(tag) == 0 {
		return ber.children
	}

	if !ber.Tag.IsConstructed() {
		return nil
	}

	for _, tlv := range ber.children {
		if bytes.Equal(tlv.Tag, tag) {
			berTLVS = append(berTLVS, tlv)
		}
	}

	return berTLVS
}

// FirstChild returns the first child BerTLV that is contained in the constructed BerTLV.
// If a tag is passed, child TLVs are filtered by the given tag and the first matching child is returned.
// Returns nil if no matching BerTLV are found or the BerTLV is not constructed.
// Please note that child BerTLV of constructed children are not evaluated.
func (ber BerTLV) FirstChild(tag BerTag) *BerTLV {
	if len(tag) == 0 && len(ber.children) != 0 {
		return &ber.children[0]
	}

	if !ber.Tag.IsConstructed() {
		return nil
	}

	for _, tlv := range ber.children {
		if bytes.Equal(tlv.Tag, tag) {
			return &tlv
		}
	}

	return nil
}

// String calls BerTLV.Bytes and returns the upper-case hex encoded representation of the BerTLV.
func (ber BerTLV) String() string {
	return strings.ToUpper(hex.EncodeToString(ber.Bytes()))
}

// AddByte adds the given tag with the given value to the Builder.
// The length is added automatically.
func (bu Builder) AddByte(tag BerTag, val byte) *Builder {
	bu.bytes = append(bu.bytes, tag...)
	bu.position += len(tag)

	bu.bytes = append(bu.bytes, 1)
	bu.position++

	bu.bytes = append(bu.bytes, val)
	bu.position++

	return &bu
}

// AddBytes adds the given tag with the given value to the Builder.
// The length is added automatically.
// If the value exceeds a length of 65535 it gets truncated.
func (bu Builder) AddBytes(tag BerTag, v []byte) *Builder {
	// tag
	bu.bytes = append(bu.bytes, tag...)
	bu.position += len(tag)

	// (truncate if > 65535)
	if len(v) > 65535 {
		v = v[:65535]
	}

	if len(v) == 0 {
		bu.bytes = append(bu.bytes, []byte{0x00}...)
		bu.position++

		return &bu
	}

	// length
	numLByte := prependLengthBytes(&v)

	bu.position += numLByte

	// value
	bu.bytes = append(bu.bytes, v...)
	bu.position += len(v)

	return &bu
}

func prependLengthBytes(b *[]byte) int {
	l := buildLen(len(*b))

	*b = append(l, *b...)

	return len(l)
}

// AddEmpty adds the given tag without a value field to the Builder.
func (bu Builder) AddEmpty(tag BerTag) *Builder {
	return bu.AddBytes(tag, []byte{})
}

// AddRaw adds the given bytes without further checks to the Builder.
func (bu Builder) AddRaw(b []byte) *Builder {
	bu.bytes = append(bu.bytes, b...)

	return &bu
}

// BuildBerTLVs calls Parse on the contents of the Builder and returns the resulting BerTLVs.
// Any errors that occur while parsing are returned.
func (bu Builder) BuildBerTLVs() (BerTLVs, error) {
	return Parse(bu.bytes)
}

// Bytes returns the byte representation of the contents of the Builder.
func (bu Builder) Bytes() []byte {
	return bu.bytes
}
