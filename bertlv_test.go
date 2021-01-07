package bertlv

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestNewBerTLV(t *testing.T) {
	tests := []struct {
		name        string
		inputTag    BerTag
		inputValue  []byte
		expected    *BerTLV
		expectError bool
	}{
		{name: "Happy path: primitive tlv",
			inputTag:   NewOneByteTag(0x0A),
			inputValue: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: &BerTLV{
				Tag:   NewOneByteTag(0x0A),
				Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			},
			expectError: false,
		},
		{name: "Happy path: constructed tlv (one child)",
			inputTag:   NewOneByteTag(0x2A),
			inputValue: []byte{0x10, 0x03, 0x03, 0x04, 0x05},
			expected: &BerTLV{
				Tag:   NewOneByteTag(0x2A),
				Value: []byte{0x10, 0x03, 0x03, 0x04, 0x05},
				children: []BerTLV{
					{
						Tag:   NewOneByteTag(0x10),
						Value: []byte{0x03, 0x04, 0x05},
					},
				},
			},
			expectError: false,
		},
		{name: "Unhappy path: constructed tlv with invalid child",
			inputTag:    NewOneByteTag(0x2A),
			inputValue:  []byte{0x10, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := NewBerTLV(tc.inputTag, tc.inputValue)

			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())
				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")
				return
			}

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestNewOneByteTag(t *testing.T) {
	tests := []struct {
		name      string
		inputByte byte
		expected  BerTag
	}{
		{name: "one byte tag",
			inputByte: 0x0A,
			expected:  BerTag{0x0A},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := NewOneByteTag(tc.inputByte)

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestNewTwoByteTag(t *testing.T) {
	tests := []struct {
		name       string
		inputByte1 byte
		inputByte2 byte
		expected   BerTag
	}{
		{name: "two byte tag",
			inputByte1: 0x20,
			inputByte2: 0x0A,
			expected:   BerTag{0x20, 0x0A},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := NewTwoByteTag(tc.inputByte1, tc.inputByte2)

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestNewThreeByteTag(t *testing.T) {
	tests := []struct {
		name       string
		inputByte1 byte
		inputByte2 byte
		inputByte3 byte
		expected   BerTag
	}{
		{name: "three byte tag",
			inputByte1: 0x20,
			inputByte2: 0x80,
			inputByte3: 0x0A,
			expected:   BerTag{0x20, 0x80, 0x0A},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := NewThreeByteTag(tc.inputByte1, tc.inputByte2, tc.inputByte3)

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParse(t *testing.T) {
	oneByteLenData := make([]byte, 127)
	twoByteLenData := make([]byte, 255)
	threeByteLenData := make([]byte, 65535)

	tests := []struct {
		name        string
		inputBytes  []byte
		expected    BerTLVs
		expectError bool
	}{
		{name: "Happy path: 1B Tag, 1B Len, primitive",
			inputBytes: append([]byte{0x51, 0x7F}, oneByteLenData...),
			expected: []BerTLV{{
				Tag:   NewOneByteTag(0x51),
				Value: oneByteLenData,
			}},
			expectError: false,
		},
		{name: "Happy path: 1B Tag, empty",
			inputBytes: []byte{0x51, 0x00},
			expected: []BerTLV{{
				Tag: NewOneByteTag(0x51),
			}},
			expectError: false,
		},
		{name: "Happy path: 1B Tag, 1B Len, constructed 1C",
			inputBytes: []byte{0x71, 0x05, 0x90, 0x03, 0x01, 0x02, 0x03},
			expected: []BerTLV{{
				Tag:   NewOneByteTag(0x71),
				Value: []byte{0x90, 0x03, 0x01, 0x02, 0x03},
				children: []BerTLV{{
					Tag:   NewOneByteTag(0x90),
					Value: []byte{0x01, 0x02, 0x03},
				}},
			}},
			expectError: false,
		},
		{name: "Happy path: 1B Tag, 1B Len, constructed with 2C",
			inputBytes: []byte{0x71, 0x0C, 0x90, 0x03, 0x01, 0x02, 0x03, 0x0F, 0x05, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB},
			expected: []BerTLV{{
				Tag:   NewOneByteTag(0x71),
				Value: []byte{0x90, 0x03, 0x01, 0x02, 0x03, 0x0F, 0x05, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB},
				children: []BerTLV{
					{
						Tag:   NewOneByteTag(0x90),
						Value: []byte{0x01, 0x02, 0x03},
					}, {
						Tag:   NewOneByteTag(0x0F),
						Value: []byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB},
					}},
			}},
			expectError: false,
		},
		{name: "Happy path: 1B Tag, 1B Len, level 2 constructed with 2C",
			inputBytes: []byte{0x71, 0x10, 0xB0, 0x0E, 0x0F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0E, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01},
			expected: []BerTLV{{
				Tag:   NewOneByteTag(0x71),
				Value: []byte{0xB0, 0x0E, 0x0F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0E, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01},
				children: []BerTLV{
					{
						Tag:   NewOneByteTag(0xB0),
						Value: []byte{0x0F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0E, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01},
						children: []BerTLV{
							{
								Tag:   NewOneByteTag(0x0F),
								Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
							},
							{
								Tag:   NewOneByteTag(0x0E),
								Value: []byte{0x05, 0x04, 0x03, 0x02, 0x01},
							},
						},
					},
				},
			}},
			expectError: false,
		},
		{name: "Happy path: 2B Tag, empty",
			inputBytes: []byte{0x5F, 0x05, 0x00},
			expected: []BerTLV{{
				Tag: NewTwoByteTag(0x5F, 0x05),
			}},
			expectError: false,
		},
		{name: "Happy path: 2B Tag, 2B Len, primitive ",
			inputBytes: append([]byte{0x5F, 0x05, 0x81, 0xFF}, twoByteLenData...),
			expected: []BerTLV{{
				Tag:   NewTwoByteTag(0x5F, 0x05),
				Value: twoByteLenData,
			}},
			expectError: false,
		},
		{name: "Happy path: 3B Tag, empty",
			inputBytes: []byte{0x5F, 0x80, 0x05, 0x00},
			expected: []BerTLV{{
				Tag: NewThreeByteTag(0x5F, 0x80, 0x05),
			}},
			expectError: false,
		},
		{name: "Happy path: 3B Tag, 3B Len, primitive ",
			inputBytes: append([]byte{0x5F, 0x80, 0x05, 0x82, 0xFF, 0xFF}, threeByteLenData...),
			expected: []BerTLV{{
				Tag:   NewThreeByteTag(0x5F, 0x80, 0x05),
				Value: threeByteLenData,
			}},
			expectError: false,
		},
		{name: "Unhappy path: nil or empty tlv",
			inputBytes:  nil,
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid tag, wrong length",
			inputBytes:  []byte{0x7F, 0x01, 0x01},
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid tag, two byte encoding indicated but not enough byte",
			inputBytes:  []byte{0x1F},
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid tag, three byte encoding indicated but not enough byte",
			inputBytes:  []byte{0x1F, 0x80},
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid length, empty",
			inputBytes:  []byte{0x90, 0x03, 0x01, 0x02, 0x03, 0x91},
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid length, > 127 byte indicated but second byte is missing",
			inputBytes:  []byte{0x90, 0x03, 0x01, 0x02, 0x03, 0x91, 0x81},
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid length, > 255 byte indicated but third byte is missing",
			inputBytes:  []byte{0x90, 0x03, 0x01, 0x02, 0x03, 0x91, 0x82, 0x00},
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid length, > 255 byte indicated but two byte are missing",
			inputBytes:  []byte{0x90, 0x03, 0x01, 0x02, 0x03, 0x91, 0x82},
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid length, > 127 byte but first byte does not indicate encoding with more byte ",
			inputBytes:  []byte{0x90, 0x03, 0x01, 0x02, 0x03, 0x91, 0x8F},
			expected:    BerTLVs{},
			expectError: true,
		},
		{name: "Unhappy path: invalid child of constructed tlv ",
			inputBytes:  []byte{0xB0, 0x01, 0x80},
			expected:    BerTLVs{},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := Parse(tc.inputBytes)
			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())
				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")
				return
			}

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBerTag_CheckEncoding(t *testing.T) {
	tests := []struct {
		name        string
		input       BerTag
		expectError bool
	}{
		{name: "Unhappy path: invalid tag length",
			input:       []byte{0x01, 0x02, 0x03, 0x04},
			expectError: true},
		{name: "Unhappy path: one byte tag indicates more byte",
			input:       NewOneByteTag(0x1F),
			expectError: true},
		{name: "Unhappy path: two byte tag, first byte does not indicate more byte",
			input:       NewTwoByteTag(0x1E, 0x30),
			expectError: true},
		{name: "Unhappy path: two byte tag, second byte indicates more byte",
			input:       NewTwoByteTag(0x1F, 0x80),
			expectError: true},
		{name: "Unhappy path: three byte tag, first byte does not indicate more byte",
			input:       NewThreeByteTag(0x1C, 0x80, 0x10),
			expectError: true},
		{name: "Unhappy path: three byte tag, second byte does not indicate more byte",
			input:       NewThreeByteTag(0x1F, 0x70, 0x10),
			expectError: true},
		{name: "Happy path: one byte tag",
			input:       NewOneByteTag(0x80),
			expectError: false},
		{name: "Happy path: two byte tag",
			input:       NewTwoByteTag(0x1F, 0x7F),
			expectError: false},
		{name: "Happy path: three byte tag",
			input:       NewThreeByteTag(0x1F, 0x80, 0x90),
			expectError: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.CheckEncoding()
			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())
				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")
				return
			}
		})
	}
}

func TestIsConstructed(t *testing.T) {
	fmt.Println(BerTag([]byte{}).IsConstructed())
}

func TestBerTLVs_Bytes(t *testing.T) {
	oneByteLenData := make([]byte, 127)
	twoByteLenData := make([]byte, 255)
	threeByteLenData := make([]byte, 65535)

	tests := []struct {
		name     string
		berTLVs  BerTLVs
		expected []byte
	}{
		{name: "one byte tag, empty, one BerTLV",
			berTLVs: []BerTLV{
				{
					Tag:   NewOneByteTag(0x0A),
					Value: nil,
				},
			},
			expected: []byte{0x0A, 0x00},
		},
		{name: "one byte tag, one byte length, one BerTLV",
			berTLVs: []BerTLV{
				{
					Tag:   NewOneByteTag(0x0A),
					Value: oneByteLenData,
				},
			},
			expected: append([]byte{0x0A, 0x7F}, oneByteLenData...),
		},
		{name: "two byte tag, two byte length, one BerTLV",
			berTLVs: []BerTLV{
				{
					Tag:   NewTwoByteTag(0x1F, 0x0A),
					Value: twoByteLenData,
				},
			},
			expected: append([]byte{0x1F, 0x0A, 0x81, 0xFF}, twoByteLenData...),
		},
		{name: "three byte tag, three byte length, one BerTLV",
			berTLVs: []BerTLV{
				{
					Tag:   NewThreeByteTag(0x1F, 0x80, 0x0A),
					Value: threeByteLenData,
				},
			},
			expected: append([]byte{0x1F, 0x80, 0x0A, 0x82, 0xFF, 0xFF}, threeByteLenData...),
		},
		{name: "one byte tag, one byte length, multiple BerTLV",
			berTLVs: []BerTLV{
				{
					Tag:   NewOneByteTag(0x0A),
					Value: []byte{0x01, 0x02, 0x03},
				},
				{
					Tag:   NewOneByteTag(0x0B),
					Value: []byte{0x04, 0x05, 0x06},
				},
				{
					Tag:   NewOneByteTag(0x0C),
					Value: []byte{0x07, 0x08, 0x09},
				},
			},
			expected: []byte{0x0A, 0x03, 0x01, 0x02, 0x03, 0x0B, 0x03, 0x04, 0x05, 0x06, 0x0C, 0x03, 0x07, 0x08, 0x09},
		},
		{name: "one byte tag, one byte length, multiple BerTLV",
			berTLVs: []BerTLV{
				{
					Tag:   NewOneByteTag(0x0A),
					Value: []byte{0x01, 0x02, 0x03},
				},
				{
					Tag:   NewOneByteTag(0x0B),
					Value: []byte{0x04, 0x05, 0x06},
				},
				{
					Tag:   NewOneByteTag(0x0C),
					Value: []byte{0x07, 0x08, 0x09},
				},
			},
			expected: []byte{0x0A, 0x03, 0x01, 0x02, 0x03, 0x0B, 0x03, 0x04, 0x05, 0x06, 0x0C, 0x03, 0x07, 0x08, 0x09},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.berTLVs.Bytes()

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBerTLVs_FindAllWithTag(t *testing.T) {
	simpleChildTlv1 := BerTLV{
		Tag:      NewOneByteTag(0x0F),
		Value:    []byte{0x01, 0x02, 0x03},
		children: []BerTLV{},
	}

	simpleChildTlv2 := BerTLV{
		Tag:      NewOneByteTag(0x0F),
		Value:    []byte{0x04, 0x05, 0x06},
		children: []BerTLV{},
	}

	tests := []struct {
		name     string
		berTLVs  BerTLVs
		inputTag BerTag
		expected []BerTLV
	}{
		{name: "Find all (1)",
			berTLVs: []BerTLV{{
				Tag:   NewOneByteTag(0x20),
				Value: simpleChildTlv1.Bytes(),
			}},
			inputTag: NewOneByteTag(0x20),
			expected: []BerTLV{{
				Tag:   NewOneByteTag(0x20),
				Value: simpleChildTlv1.Bytes(),
			},
			},
		},
		{name: "Find all (2)",
			berTLVs: []BerTLV{
				{
					Tag:   NewOneByteTag(0x20),
					Value: simpleChildTlv1.Bytes(),
				},
				{
					Tag:   NewOneByteTag(0x20),
					Value: simpleChildTlv2.Bytes(),
				},
			},
			inputTag: NewOneByteTag(0x20),
			expected: []BerTLV{
				{
					Tag:   NewOneByteTag(0x20),
					Value: simpleChildTlv1.Bytes(),
				}, {
					Tag:   NewOneByteTag(0x20),
					Value: simpleChildTlv2.Bytes(),
				}},
		},
		{name: "Find nothing",
			berTLVs: []BerTLV{{
				Tag:   NewOneByteTag(0x20),
				Value: simpleChildTlv1.Bytes(),
			}},
			inputTag: NewOneByteTag(0x19),
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.berTLVs.FindAllWithTag(tc.inputTag)

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBerTLVs_FindFirstWithTag(t *testing.T) {
	simpleChildTlv1 := BerTLV{
		Tag:      NewOneByteTag(0x0F),
		Value:    []byte{0x01, 0x02, 0x03},
		children: []BerTLV{},
	}
	simpleChildTlv2 := BerTLV{
		Tag:      NewOneByteTag(0x0F),
		Value:    []byte{0x04, 0x05, 0x06},
		children: []BerTLV{},
	}

	tests := []struct {
		name     string
		berTLVs  BerTLVs
		inputTag BerTag
		expected *BerTLV
	}{
		{name: "Find first and only",
			berTLVs: []BerTLV{{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1},
			}},
			inputTag: NewOneByteTag(0x20),
			expected: &BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1},
			},
		},
		{name: "Find first of multiple",
			berTLVs: []BerTLV{
				{
					Tag:      NewOneByteTag(0x20),
					Value:    simpleChildTlv1.Bytes(),
					children: []BerTLV{simpleChildTlv1},
				},
				{
					Tag:      NewOneByteTag(0x20),
					Value:    simpleChildTlv1.Bytes(),
					children: []BerTLV{simpleChildTlv2},
				}},
			inputTag: NewOneByteTag(0x20),
			expected: &BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1},
			},
		},
		{name: "Find nothing",
			berTLVs: []BerTLV{{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1, simpleChildTlv2},
			}},
			inputTag: NewOneByteTag(0x19),
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.berTLVs.FindFirstWithTag(tc.inputTag)

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBerTLV_Bytes(t *testing.T) {
	oneByteLenData := make([]byte, 127)
	twoByteLenData := make([]byte, 255)
	threeByteLenData := make([]byte, 65535)
	tooLongLenData := make([]byte, 65536)

	tests := []struct {
		name     string
		berTLV   BerTLV
		expected []byte
	}{
		{name: "Happy path: nil tag filled with zero tag",
			berTLV: BerTLV{
				Tag:   []byte{},
				Value: oneByteLenData,
			},
			expected: append([]byte{0x00, 0x7F}, oneByteLenData...),
		},
		{name: "Happy path: truncate tag",
			berTLV: BerTLV{
				Tag:   []byte{0x01, 0x02, 0x03, 0x04},
				Value: oneByteLenData,
			},
			expected: append([]byte{0x01, 0x02, 0x03, 0x7F}, oneByteLenData...),
		},
		{name: "Happy path: simple tag, zero inputValue",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x80),
				Value: nil,
			},
			expected: []byte{0x80, 0x00},
		},
		{name: "Happy path: simple tag, one byte length",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x80),
				Value: oneByteLenData,
			},
			expected: append([]byte{0x80, 0x7F}, oneByteLenData...),
		},
		{name: "Happy path: simple tag, two byte length",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x10),
				Value: twoByteLenData,
			},
			expected: append([]byte{0x10, 0x81, 0xFF}, twoByteLenData...),
		},
		{name: "Happy path: simple tag, three byte length",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x50),
				Value: threeByteLenData,
			},
			expected: append([]byte{0x50, 0x82, 0xFF, 0xFF}, threeByteLenData...),
		},
		{name: "Happy path: two byte tag, zero length",
			berTLV: BerTLV{
				Tag:   NewTwoByteTag(0xDF, 0x20),
				Value: nil,
			},
			expected: []byte{0xDF, 0x20, 0x00},
		},
		{name: "Happy path: two byte tag, one byte length",
			berTLV: BerTLV{
				Tag:   NewTwoByteTag(0xDF, 0x20),
				Value: oneByteLenData,
			},
			expected: append([]byte{0xDF, 0x20, 0x7F}, oneByteLenData...),
		},
		{name: "Happy path: two byte tag, two byte length",
			berTLV: BerTLV{
				Tag:   NewTwoByteTag(0xDF, 0x20),
				Value: twoByteLenData,
			},
			expected: append([]byte{0xDF, 0x20, 0x81, 0xFF}, twoByteLenData...),
		},
		{name: "Happy path: three byte tag, one byte length",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0xDF, 0x80, 0x20),
				Value: nil,
			},
			expected: []byte{0xDF, 0x80, 0x20, 0x00},
		},
		{name: "Happy path: three byte tag, one byte length",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0xDF, 0x80, 0x20),
				Value: oneByteLenData,
			},
			expected: append([]byte{0xDF, 0x80, 0x20, 0x7F}, oneByteLenData...),
		},
		{name: "Happy path: three byte tag, two byte length",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0xDF, 0x80, 0x20),
				Value: twoByteLenData,
			},
			expected: append([]byte{0xDF, 0x80, 0x20, 0x81, 0xFF}, twoByteLenData...),
		},
		{name: "Happy path: three byte tag, three byte length",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0xDF, 0x80, 0x20),
				Value: threeByteLenData,
			},
			expected: append([]byte{0xDF, 0x80, 0x20, 0x82, 0xFF, 0xFF}, threeByteLenData...),
		},
		{name: "Happy path: three byte tag, three byte length, truncate inputValue",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0xDF, 0x80, 0x20),
				Value: tooLongLenData,
			},
			expected: append([]byte{0xDF, 0x80, 0x20, 0x82, 0xFF, 0xFF}, tooLongLenData[:65535]...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.berTLV.Bytes()

			if !bytes.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBerTLV_BytesLength(t *testing.T) {
	oneByteLenData := make([]byte, 127)
	twoByteLenData := make([]byte, 255)
	threeByteLenData := make([]byte, 65535)
	tooLongLenData := make([]byte, 65536)

	tests := []struct {
		name     string
		berTLV   BerTLV
		expected int
	}{
		{name: "1B tag, empty",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x0A),
				Value: nil,
			},
			expected: 2,
		},
		{name: "1B tag 1B length",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x0A),
				Value: oneByteLenData,
			},
			expected: 129,
		},
		{name: "1B tag 2B length",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x0A),
				Value: twoByteLenData,
			},
			expected: 258,
		},
		{name: "1B tag 3B length",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x0A),
				Value: threeByteLenData,
			},
			expected: 65539,
		},
		{name: "2B tag, empty",
			berTLV: BerTLV{
				Tag:   NewTwoByteTag(0x1F, 0x0A),
				Value: nil,
			},
			expected: 3,
		},
		{name: "2B tag 1B length",
			berTLV: BerTLV{
				Tag:   NewTwoByteTag(0x1F, 0x0A),
				Value: oneByteLenData,
			},
			expected: 130,
		},
		{name: "2B tag 2B length",
			berTLV: BerTLV{
				Tag:   NewTwoByteTag(0x1F, 0x0A),
				Value: twoByteLenData,
			},
			expected: 259,
		},
		{name: "2B tag 3B length",
			berTLV: BerTLV{
				Tag:   NewTwoByteTag(0x1F, 0x0A),
				Value: threeByteLenData,
			},
			expected: 65540,
		},
		{name: "3B tag, empty",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0x1F, 0x80, 0x0A),
				Value: nil,
			},
			expected: 4,
		},
		{name: "3B tag 1B length",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0x1F, 0x80, 0x0A),
				Value: oneByteLenData,
			},
			expected: 131,
		},
		{name: "3B tag 2B length",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0x1F, 0x80, 0x0A),
				Value: twoByteLenData,
			},
			expected: 260,
		},
		{name: "3B tag 3B length",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0x1F, 0x80, 0x0A),
				Value: threeByteLenData,
			},
			expected: 65541,
		},
		{name: "truncate too long data",
			berTLV: BerTLV{
				Tag:   NewThreeByteTag(0x1F, 0x80, 0x0A),
				Value: tooLongLenData,
			},
			expected: 65541,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.berTLV.BytesLength()

			if received != tc.expected {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBerTLV_FirstChild(t *testing.T) {
	simpleChildTlv1 := BerTLV{
		Tag:   NewOneByteTag(0x0F),
		Value: []byte{0x01, 0x02, 0x03},
	}

	simpleChildTlv2 := BerTLV{
		Tag:      NewOneByteTag(0x0F),
		Value:    []byte{0x04, 0x05, 0x06},
		children: []BerTLV{},
	}

	tests := []struct {
		name     string
		tlv      BerTLV
		inputTag BerTag
		expected *BerTLV
	}{
		{name: "Find nothing, primitive",
			tlv: BerTLV{
				Tag:   NewOneByteTag(0x19),
				Value: simpleChildTlv1.Bytes(),
			},
			inputTag: simpleChildTlv1.Tag,
			expected: nil,
		},
		{name: "Find first and only, no filter",
			tlv: BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1},
			},
			inputTag: nil,
			expected: &simpleChildTlv1,
		},
		{name: "Find first and only",
			tlv: BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1},
			},
			inputTag: simpleChildTlv1.Tag,
			expected: &simpleChildTlv1,
		},
		{name: "Find first of multiple, no filter",
			tlv: BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1, simpleChildTlv2},
			},
			inputTag: nil,
			expected: &simpleChildTlv1,
		},
		{name: "Find first of multiple",
			tlv: BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1, simpleChildTlv2},
			},
			inputTag: simpleChildTlv1.Tag,
			expected: &simpleChildTlv1,
		},
		{name: "Find nothing, no filter",
			tlv: BerTLV{
				Tag:   NewOneByteTag(0x20),
				Value: simpleChildTlv1.Bytes(),
			},
			inputTag: NewOneByteTag(0x19),
			expected: nil,
		},
		{name: "Find nothing",
			tlv: BerTLV{
				Tag:   NewOneByteTag(0x20),
				Value: simpleChildTlv1.Bytes(),
			},
			inputTag: NewOneByteTag(0x19),
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.tlv.FirstChild(tc.inputTag)

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBerTLV_Children(t *testing.T) {
	simpleChildTlv1 := BerTLV{
		Tag:   NewOneByteTag(0x0F),
		Value: []byte{0x01, 0x02, 0x03},
	}

	simpleChildTlv2 := BerTLV{
		Tag:   NewOneByteTag(0x0F),
		Value: []byte{0x01, 0x02, 0x03},
	}

	tests := []struct {
		name     string
		berTLV   BerTLV
		inputTag BerTag
		expected []BerTLV
	}{
		{name: "Find all (1), no filter",
			berTLV: BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1},
			},
			inputTag: nil,
			expected: []BerTLV{simpleChildTlv1},
		},
		{name: "Find all (1)",
			berTLV: BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    simpleChildTlv1.Bytes(),
				children: []BerTLV{simpleChildTlv1},
			},
			inputTag: simpleChildTlv1.Tag,
			expected: []BerTLV{simpleChildTlv1},
		},
		{name: "Find all (2), no filter",
			berTLV: BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    append(simpleChildTlv1.Bytes(), simpleChildTlv2.Bytes()...),
				children: []BerTLV{simpleChildTlv1, simpleChildTlv2},
			},
			inputTag: nil,
			expected: []BerTLV{simpleChildTlv1, simpleChildTlv2},
		},
		{name: "Find all (2)",
			berTLV: BerTLV{
				Tag:      NewOneByteTag(0x20),
				Value:    append(simpleChildTlv1.Bytes(), simpleChildTlv2.Bytes()...),
				children: []BerTLV{simpleChildTlv1, simpleChildTlv2},
			},
			inputTag: simpleChildTlv1.Tag,
			expected: []BerTLV{simpleChildTlv1, simpleChildTlv2},
		},
		{name: "Find nothing, no filter",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x20),
				Value: simpleChildTlv1.Bytes(),
			},
			inputTag: nil,
			expected: nil,
		},
		{name: "Find nothing",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x20),
				Value: simpleChildTlv1.Bytes(),
			},
			inputTag: NewOneByteTag(0x19),
			expected: nil,
		},
		{name: "Find nothing, not constructed",
			berTLV: BerTLV{
				Tag:   NewOneByteTag(0x19),
				Value: simpleChildTlv1.Bytes(),
			},
			inputTag: simpleChildTlv1.Tag,
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.berTLV.Children(tc.inputTag)

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBerTLV_String(t *testing.T) {
	tests := []struct {
		name     string
		berTLV   BerTLV
		expected string
	}{
		{name: "to string",
			berTLV: BerTLV{
				Tag:   NewTwoByteTag(0x1F, 0x0A),
				Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			},
			expected: "1F0A050102030405",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.berTLV.String()

			if received != tc.expected {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBuilder_AddByte(t *testing.T) {
	tests := []struct {
		name      string
		inputTag  BerTag
		inputByte byte
		expected  []byte
	}{
		{name: "add byte",
			inputTag:  NewOneByteTag(0x0A),
			inputByte: 0xFF,
			expected:  []byte{0x0A, 0x01, 0xFF},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := Builder{}.AddByte(tc.inputTag, tc.inputByte).Bytes()

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBuilder_AddBytes(t *testing.T) {
	tooLongData := make([]byte, 65536)

	tests := []struct {
		name       string
		inputTag   BerTag
		inputBytes []byte
		expected   []byte
	}{
		{name: "add bytes",
			inputTag:   NewOneByteTag(0x0A),
			inputBytes: []byte{0xFF},
			expected:   []byte{0x0A, 0x01, 0xFF},
		},
		{name: "add bytes truncate",
			inputTag:   NewOneByteTag(0x0A),
			inputBytes: tooLongData,
			expected:   append([]byte{0x0A, 0x82, 0xFF, 0xFF}, tooLongData[:len(tooLongData)-1]...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := Builder{}.AddBytes(tc.inputTag, tc.inputBytes).Bytes()

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBuilder_AddEmpty(t *testing.T) {
	tests := []struct {
		name     string
		inputTag BerTag
		expected []byte
	}{
		{name: "add empty",
			inputTag: NewOneByteTag(0x0A),
			expected: []byte{0x0A, 0x00},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := Builder{}.AddEmpty(tc.inputTag).Bytes()

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBuilder_AddRaw(t *testing.T) {
	tests := []struct {
		name       string
		inputBytes []byte
		expected   []byte
	}{
		{name: "add raw",
			inputBytes: []byte{0xB0, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected:   []byte{0xB0, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := Builder{}.AddRaw(tc.inputBytes).Bytes()

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestBuilder_BuildBerTLVs(t *testing.T) {
	tests := []struct {
		name        string
		builder     *Builder
		expected    BerTLVs
		expectError bool
	}{
		{name: "Happy Path: build BerTLVs",
			builder: Builder{}.
				AddEmpty(NewOneByteTag(0x0A)).
				AddBytes(NewTwoByteTag(0x3F, 0x0A), []byte{0x10, 0x02, 0x01, 0x02}).
				AddByte(NewThreeByteTag(0x1F, 0x80, 0x0A), 0xFF),
			expected: []BerTLV{
				{
					Tag:   NewOneByteTag(0x0A),
					Value: nil,
				},
				{
					Tag:   NewTwoByteTag(0x3F, 0x0A),
					Value: []byte{0x10, 0x02, 0x01, 0x02},
					children: []BerTLV{
						{
							Tag:   NewOneByteTag(0x10),
							Value: []byte{0x01, 0x02},
						},
					},
				},
				{
					Tag:   NewThreeByteTag(0x1F, 0x80, 0x0A),
					Value: []byte{0xFF},
				},
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := tc.builder.BuildBerTLVs()

			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())
				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")
				return
			}

			if !reflect.DeepEqual(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}
