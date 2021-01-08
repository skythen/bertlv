# BER-TLV

[![Build Status](https://travis-ci.org/skythen/bertlv.svg?branch=master)](https://travis-ci.org/skythen/bertlv)
[![Coverage Status](https://coveralls.io/repos/github/skythen/bertlv/badge.svg?branch=master)](https://coveralls.io/github/skythen/bertlv?branch=master)
[![GoDoc](https://godoc.org/github.com/skythen/bertlv?status.svg)](http://godoc.org/github.com/skythen/bertlv)
[![Go Report Card](https://goreportcard.com/badge/github.com/skythen/bertlv)](https://goreportcard.com/report/github.com/skythen/bertlv)

Package bertlv implements parsing and building of BER-TLV structures.

Please note that this is not a complete implementation of the X.690 standard as it is agnostic about classes (Universal, Application, Context-specific, Private) and therefore does not check for correct encoding of tags/values.

`go get github.com/skythen/bertlv`

## Parse

You can parse BER-TLV encoded data from bytes:

```go
b := []byte{0x71, 0x10, 0xB0, 0x0E, 0x0F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0E, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01}
bertlvs, err := Parse(b)
```
### Constructed objects
You can check if a BerTLV is constructed and get first or all children or filter child objects by tag:
```go
if bertlvs[0].Tag.IsConstructed() {
    child := bertlvs[0].FirstChild(NewOneByteTag(0x0F))
}
```

## Create
You can create single BER-TLVs with NewBerTLV:
```go
val := []byte{0xB0, 0x0E, 0x0F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0E, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01}
bertlv, err := NewBerTLV(NewOneByteTag(0x71), val)
```

If you want to create complex constructed objects you use the Builder:
```go
builder := Builder{}
nestedBuilder := Builder{}
anotherNestedBuilder := Builder{}

berTlvs, err := builder.AddBytes(NewOneByteTag(0x71), 			     // first level, constructed object
    nestedBuilder.AddBytes(NewOneByteTag(0xB0), 		             // second level, constructed object
        anotherNestedBuilder.
            AddBytes(NewOneByteTag(0x0F), []byte{0x01, 0x02, 0x03, 0x04, 0x05}). // third level primitive object
            AddBytes(NewOneByteTag(0x0E), []byte{0x05, 0x04, 0x03, 0x02, 0x01}). // third level primitive object
        Bytes()).
    Bytes()).
BuildBerTLVs()
```

You can also use
- builder.AddEmpty() to add objects without value
- builder.AddByte() to add objects with a value that consists of a single byte
- builder.AddRaw() to add raw bytes
