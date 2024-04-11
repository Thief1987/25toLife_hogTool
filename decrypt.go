package main

import (
	"bytes"
	"encoding/binary"
)

func decrypt(b bytes.Buffer) []byte {
	var (
		dec_buf bytes.Buffer
		dec     uint32
	)

	keygen()
	s := b.Len() / 4
	remain_bytes := b.Len() % 4
	for i := 0; i < int(s); i++ {
		dec = key[0] ^ ReadUint32(&b)
		binary.Write(&dec_buf, binary.LittleEndian, dec)
		keyshuffle(key[(key[22]&7)+5], dec, key[22]+key[(key[22]&7)+13])
		key[22]++
	}
	dec = 0
	if remain_bytes == 0 {
		return dec_buf.Bytes()
	} else {
		for i := 0; i < remain_bytes; i++ {
			dec = dec + uint32(b.Bytes()[0])<<(8*i)
			b.ReadByte()
		}
		dec = dec ^ key[0]
		binary.Write(&dec_buf, binary.LittleEndian, dec)
		return dec_buf.Bytes()[:(dec_buf.Len() - (4 - remain_bytes))]
	}
}
