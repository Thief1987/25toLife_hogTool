package main

import (
	"math/bits"
)

var (
	key = make([]uint32, 23)
	a   = []uint32{0, 0, 0, 0}
)

func keyshuffle(a1 uint32, a2 uint32, a3 uint32) {
	v4 := key[4]
	v5 := v4 + key[1]
	v6 := key[3]
	v7 := v6 + key[0]
	v8 := v7 ^ key[2]
	v9 := v5 ^ bits.RotateLeft32(v6, 15)
	v10 := v8 + bits.RotateLeft32(v4, 25)
	v11 := (v9 + a1) ^ bits.RotateLeft32(v7, 9)
	v12 := v10 ^ bits.RotateLeft32(v5, 10)
	v13 := v11 + bits.RotateLeft32(v8, 17)
	v14 := v12 + bits.RotateLeft32(v9, 30)
	v15 := v13 ^ bits.RotateLeft32(v10, 13)
	v16 := (a2 ^ v14) + bits.RotateLeft32(v11, 20)
	v17 := v15 + bits.RotateLeft32(v12, 11)
	v18 := v16 ^ bits.RotateLeft32(v13, 5)
	v19 := v17 ^ bits.RotateLeft32(v14, 15)
	v20 := v18 + bits.RotateLeft32(v15, 25)
	v21 := (v19 + a3) ^ bits.RotateLeft32(v16, 9)
	v22 := v20 ^ bits.RotateLeft32(v17, 10)
	v23 := v21 + bits.RotateLeft32(v18, 17)
	key[0] = bits.RotateLeft32(v21, 20)
	key[1] = bits.RotateLeft32(v22, 11)
	result := bits.RotateLeft32(v23, 5)
	key[3] = v22 + bits.RotateLeft32(v19, 30)
	key[4] = v23 ^ bits.RotateLeft32(v20, 13)
	key[2] = result
}

func keyInit() {

	v13 := key[5]
	v14 := key[7]
	key[1] = key[6]
	v15 := key[21]
	key[0] = v13
	v16 := key[8]
	key[2] = v14
	key[3] = v16
	key[4] = v15 + 64
	keyshuffle(0, 0, 0)
	v17 := key[5]
	v18 := key[6]
	v19 := key[7]
	v20 := key[8]
	key[5] = key[0] ^ key[9]
	v21 := key[1] ^ key[10]
	key[9] = v17
	key[6] = v21
	v22 := key[2] ^ key[11]
	key[10] = v18
	key[7] = v22
	key[8] = key[3] ^ key[12]
	key[11] = v19
	key[12] = v20
}

func keyextension() {
	v2 := a[1]
	v4 := a[0]
	v14 := -a[0]
	v5 := a[2]
	v6 := a[3]
	key[13] = a[0] + key[9]
	key[14] = v2 + key[10] + 4*key[21]
	key[15] = v5 + key[11]
	key[16] = v6 + key[12]
	key[17] = v14 + key[5]
	key[18] = 1 - v2 + key[6] + 4*key[21]
	key[19] = 2 - v5 + key[7]
	key[20] = 3 - v6 + key[8]
	v7 := v4 ^ key[8]
	v8 := v2 ^ key[9]
	v9 := v5 ^ key[10]
	key[1] = v8
	v10 := key[11]
	key[2] = v9
	v11 := key[12]
	key[0] = v7
	key[3] = v6 ^ v10
	key[4] = v11
	key[22] = 0
	for i := 0; i < 8; i++ {
		keyshuffle(key[(key[22]&7)+5], 0, key[22]+key[(key[22]&7)+13])
		key[22]++
	}
}

func keygen() {
	key = []uint32{0, 0, 0, 0, 0, 0x206D2749, 0x34482061, 0x20523058, 0x34633362,
		0x20337375, 0x306C2049, 0x63206576, 0x006B6330, 0, 0, 0, 0, 0, 0, 0, 0, 0x0000001F, 0}

	for i := 0; i < 8; i++ {
		keyInit()
	}
	keyextension()
}
