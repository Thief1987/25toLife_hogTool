package main

import (
	"bytes"
	"encoding/binary"
)

func decrypt(b *bytes.Buffer) int {
	var (
		dec uint32
	)

	keygen()
	s := b.Len() / 4
	remain_bytes := b.Len() % 4
	for i := 0; i < int(s); i++ {
		a := make([]byte, 4)
		dec = key[0] ^ binary.LittleEndian.Uint32(b.Bytes())
		ReadUint32(b)
		binary.LittleEndian.PutUint32(a, dec)
		b.Write(a)
		keyshuffle(key[(key[22]&7)+5], dec, key[22]+key[(key[22]&7)+13])
		key[22]++

	}
	dec = 0
	if remain_bytes == 0 {
		return 0
	} else {
		for i := 0; i < remain_bytes; i++ {
			dec = dec + uint32(b.Bytes()[0])<<(8*i)
			b.ReadByte()
		}
		dec = dec ^ key[0]
		binary.Write(b, binary.LittleEndian, dec)
		return (4 - remain_bytes)
	}
}
