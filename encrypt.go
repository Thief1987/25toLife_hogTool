package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func encrypt(d *bytes.Buffer) []byte {
	var (
		enc_buf  bytes.Buffer
		dec, enc uint32
	)

	keygen()
	s := d.Len() / 4
	remain_bytes := d.Len() % 4
	for i := 0; i < s; i++ {
		dec := ReadUint32(d)
		enc = key[0] ^ dec
		err := binary.Write(&enc_buf, binary.LittleEndian, enc)
		if err != nil {
			fmt.Println(err)
		}
		keyshuffle(key[(key[22]&7)+5], dec, key[22]+key[(key[22]&7)+13])
		key[22]++
	}
	if remain_bytes == 0 {
		return enc_buf.Bytes()
	} else {
		for i := 0; i < remain_bytes; i++ {
			dec = dec + uint32(d.Bytes()[0])<<(8*i)
			d.ReadByte()
		}
		enc = dec ^ key[0]
		binary.Write(&enc_buf, binary.LittleEndian, enc)
		return enc_buf.Bytes()[:(enc_buf.Len() - (4 - remain_bytes))]
	}
}
