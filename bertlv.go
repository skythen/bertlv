// Package bertlv implements parsing and building of BER-TLV objects.
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

// BerTag is the 1,2 or 3 byte tag of a BER-TLV structure.
type BerTag []byte

// BerTLV is a BER-TLV structure.
type BerTLV struct {
	Tag      BerTag   // Tag of the BER-TLV structure.
	Value    []byte   // Value of the BER-TLV structure.
	children []BerTLV // Nested BER-TLV objects that may be contained in Value.
}

// BerTLVs is a slice of BerTLV.
type BerTLVs []BerTLV

// NewBerTLV returns a new BerTLV.
// If the BerTag of the BerTLV indicates a constructed structure, the value is recursively parsed and checked.
// Child BerTLV objects can then be retrieved with BerTLV.Children and BerTLV.FirstChild.
func NewBerTLV(tag BerTag, value []byte) (*BerTLV, error) {
	if !tag.IsConstructed() {
		return &BerTLV{Tag: tag, Value: value}, nil
	}

	children := make([]BerTLV, 0)

	for index := 0; index < len(value); {
		tlv, lenParsed, err := parseFirstBerTLV(value[index:])
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("%s: tag %02X invalid content", packageTag, tag))
		}

		children = append(children, tlv)
		index += lenParsed
	}

	return &BerTLV{Tag: tag, Value: value, children: children}, nil
}

// NewOneByteTag returns a new BerTag with a one byte BER tag.
// The encoding of the tag is not checked to make it easier to use with the builder pattern.
// If the encoding of a BerTag needs to be checked, use the BerTag.CheckEncoding function.
func NewOneByteTag(b byte) BerTag {
	return []byte{b}
}

// NewTwoByteTag returns a new BerTag with a two byte BER tag.
// The encoding of the tag is not checked to make it easier to use with the builder pattern.
// If the encoding of a BerTag needs to be checked, use the BerTag.CheckEncoding function.
func NewTwoByteTag(fb byte, sb byte) BerTag {
	return []byte{fb, sb}
}

// NewThreeByteTag returns a new BerTag with a three byte BER tag.
// The encoding of the tag is not checked to make it easier to use with the builder pattern.
// If the encoding of a BerTag needs to be checked, use the BerTag.CheckEncoding function.
func NewThreeByteTag(fb byte, sb byte, tb byte) BerTag {
	return []byte{fb, sb, tb}
}

// Parse recursively parses BER-TLV encoded bytes and returns BerTLVs.
func Parse(b []byte) (BerTLVs, error) {
	if len(b) == 0 {
		return nil, errors.Errorf("%s: TLV has length 0", packageTag)
	}

	var result []BerTLV

	for index := 0; index < len(b); {
		tlvs, lenParsed, err := parseFirstBerTLV(b[index:])
		if err != nil {
			return BerTLVs{}, errors.Wrap(err, fmt.Sprintf("%s: invalid TLV starting at index %d", packageTag, index))
		}

		result = append(result, tlvs)
		index += lenParsed
	}

	return result, nil
}

func parseFirstBerTLV(b []byte) (berTLV BerTLV, lenParsed int, err error) {
	tag, err := parseTag(b)
	if err != nil {
		return BerTLV{}, 0, errors.Wrap(err, fmt.Sprintf("invalid tag at start: %02X", b))
	}

	leftIndex := len(tag)

	length, lLen, err := parseLength(b[leftIndex:])
	if err != nil {
		return BerTLV{}, 0, errors.Wrap(err, fmt.Sprintf("tag %02X: invalid length encoding", tag))
	}

	leftIndex += lLen

	indicatedEndIndex := leftIndex + length - 1

	if endIndex := len(b) - 1; indicatedEndIndex > endIndex {
		return BerTLV{}, 0, errors.Errorf("tag %02X: indicated length of value is out of bounds - indicated end index: %d actual end index %d", tag, indicatedEndIndex, endIndex)
	}

	value := b[leftIndex : leftIndex+length]
	if len(value) == 0 {
		return BerTLV{Tag: tag}, leftIndex, nil
	}

	leftIndex += length

	result := BerTLV{Tag: tag, Value: value}

	if tag.IsConstructed() {
		result.children = make([]BerTLV, 0, len(value)/2)

		for valueIndex := 0; valueIndex < len(value); {
			var child BerTLV

			child, lenParsed, err = parseFirstBerTLV(value[valueIndex:])
			if err != nil {
				return BerTLV{}, 0, errors.Wrap(err, fmt.Sprintf("tag %02X: invalid child object", tag))
			}

			result.children = append(result.children, child)
			valueIndex += lenParsed
		}
	}

	return result, leftIndex, nil
}

func parseTag(b []byte) (BerTag, error) {
	if b[0]&0x1F != 0x1F {
		return NewOneByteTag(b[0]), nil
	}

	if len(b) < 2 {
		return BerTag{}, errors.New("indicated tag encoding with with more than one byte, but following bytes are missing")
	}

	if b[1]&0x80 != 0x80 {
		return NewTwoByteTag(b[0], b[1]), nil
	}

	if len(b) < 3 {
		return BerTag{}, errors.New("indicated tag encoding with three bytes, but following bytes are missing")
	}

	return NewThreeByteTag(b[0], b[1], b[2]), nil
}

func parseLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("missing length")
	}

	// one byte length encoding for values smaller than 127
	if b[0] <= 0x7F {
		return int(b[0]), 1, nil
	}

	// two byte length encoding for values between 128 - 255
	if b[0] == 0x81 {
		if len(b)-1 <= 0 {
			return 0, 0, errors.New("indicated length encoding with two bytes, but following byte are missing")
		}

		return int(b[1]), 2, nil
	}

	// three byte length encoding for values between 256 - 65535
	if b[0] == 0x82 {
		if len(b)-2 <= 0 {
			return 0, 0, errors.New("indicated length encoding with three bytes, but following bytes are missing")
		}

		return int(binary.BigEndian.Uint16(b[1:3])), 3, nil
	}

	return 0, 0, errors.New("if length is greater than 127, first byte must indicate encoding of length")
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
		return errors.Errorf("tags must consist of a maximum of three bytes, got %d", len(t))
	}

	if l == 1 {
		if t[0]&0x1F == 0x1F {
			return errors.New("tag consists of one byte but indicates that more bytes follow")
		}

		return nil
	}

	if t[0]&0x1F != 0x1F {
		return errors.Errorf("tag consists of %d byte but first byte does not indicate that more bytes follow", len(t))
	}

	if l == 2 {
		if t[1]&0x80 == 0x80 {
			return errors.New("tag consists of 2 byte but indicates that more bytes follow")
		}
	} else {
		if t[1]&0x80 != 0x80 {
			return errors.New("tag consists of 3 byte but second byte does not indicate that more bytes follow")
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

type Class int

const (
	Universal       Class = iota
	Application     Class = iota
	ContextSpecific Class = iota
	Private         Class = iota
)

func (t BerTag) Class() Class {
	switch t[0] & 0xC0 {
	case 0x40:
		return Application
	case 0x80:
		return ContextSpecific
	case 0xC0:
		return Private
	default:
		return Universal
	}
}

// Bytes returns BerTLVs as BER-TLV encoded bytes.
func (t BerTLVs) Bytes() []byte {
	var b []byte

	for _, tlv := range t {
		b = append(b, tlv.Bytes()...)
	}

	return b
}

// FindAllWithTag returns all first order BerTLV of BerTLVs whose tag matches the given BerTag
// in the order they are found (starting with index 0).
//
// Return nil if no matching BerTLV is found.
//
// Use BerTLV.Children or BerTLV.FirstChild to search for child objects in the returned BerTLV.
func (t BerTLVs) FindAllWithTag(tag BerTag) []BerTLV {
	berTLVs := make([]BerTLV, 0, len(t))

	for _, tlv := range t {
		if bytes.Equal(tlv.Tag, tag) {
			berTLVs = append(berTLVs, tlv)
		}
	}

	if len(berTLVs) == 0 {
		return nil
	}

	return berTLVs
}

// FindFirstWithTag returns the first found first order BerTLV whose tag matches the given BerTag.
//
// Return nil if no matching BerTLV is found.
//
// Use BerTLV.Children or BerTLV.FirstChild to search for child objects in the returned BerTLV.
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
		tagLen    int
		lengthLen int
		valueLen  int
		tag       []byte
		length    []byte
	)

	valueLen = len(ber.Value)

	if valueLen > 65535 {
		ber.Value = ber.Value[:65535]
		valueLen = 65535
	}

	length = buildLen(valueLen)
	tagLen = len(ber.Tag)

	if tagLen > 0 && tagLen <= 3 {
		tag = ber.Tag
	} else if tagLen == 0 {
		// fill empty tag
		tag = []byte{0x00}
		tagLen = 1
	} else {
		// truncate tag to three byte
		tagLen = 3
		tag = ber.Tag[:tagLen]
	}

	lengthLen = len(length)

	result := make([]byte, 0, tagLen+lengthLen+valueLen)
	result = append(result, tag...)
	result = append(result, length...)
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

// Children returns all child BerTLV that are contained in the constructed BerTLV.
//
// If a tag is passed, first order child TLVs are filtered by the given tag and added to the result in the order they are found.
//
// Returns nil if no matching BerTLV are found or the BerTLV is not constructed.
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

// FirstChild returns the first found first order child BerTLV that is contained in the constructed BerTLV.
//
// If a tag is passed, child TLVs are filtered by the given tag and the first matching child is returned.
//
// Returns nil if no matching BerTLV are found or the BerTLV is not constructed.
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

// String calls BerTLV.Bytes and returns hex encoded (upper-case) result.
func (ber BerTLV) String() string {
	return strings.ToUpper(hex.EncodeToString(ber.Bytes()))
}

// Builder for BER-TLV objects. Use the 'Add' functions to add data.
// Nested Builders can be used to create constructed BER-TLV objects.
type Builder struct {
	bytes []byte
}

// AddByte adds the given tag with the given value to the Builder.
// The length is added automatically.
func (bu Builder) AddByte(tag BerTag, val byte) *Builder {
	bu.bytes = append(bu.bytes, tag...)
	bu.bytes = append(bu.bytes, 1)
	bu.bytes = append(bu.bytes, val)

	return &bu
}

// AddBytes adds the given tag with the given value to the Builder.
// The length is added automatically.
// If the value exceeds a length of 65535 it gets truncated.
func (bu Builder) AddBytes(tag BerTag, v []byte) *Builder {
	// tag
	bu.bytes = append(bu.bytes, tag...)

	if len(v) == 0 {
		bu.bytes = append(bu.bytes, []byte{0x00}...)

		return &bu
	}

	// truncate if > 65535
	if len(v) > 65535 {
		v = v[:65535]
	}

	prependLengthBytes(&v)

	// value
	bu.bytes = append(bu.bytes, v...)

	return &bu
}

func prependLengthBytes(b *[]byte) {
	l := buildLen(len(*b))

	*b = append(l, *b...)
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
