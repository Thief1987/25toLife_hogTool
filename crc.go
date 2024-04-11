// IDA dump
package main

var z3, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15, z16, z17, z18, z19, z20, z21, z22, z23, z24, z26 uint32

func CRCcalc(data []byte, s uint32, n uint32) uint32 {

	z3 = s
	z6 = 0x9E3779B9
	z7 = s
	z8 = 0x9E3779B9
	z26 = s / 0xC
	i := 0
	for z26 > 0 {
		z9 = z6 + uint32(data[4+i]) + ((uint32(data[5+i]) + ((uint32(data[6+i]) + (uint32(data[7+i]) << 8)) << 8)) << 8)
		z10 = n + uint32(data[8+i]) + ((uint32(data[9+i]) + ((uint32(data[10+i]) + (uint32(data[11+i]) << 8)) << 8)) << 8)
		z11 = (z10 >> 13) ^ (z8 + uint32(data[0+i]) + ((uint32(data[1+i]) + ((uint32(data[2+i]) + (uint32(data[3+i]) << 8)) << 8)) << 8) - z10 - z9)
		z12 = (z11 << 8) ^ (z9 - z10 - z11)
		z13 = (z12 >> 13) ^ (z10 - z12 - z11)
		z14 = (z13 >> 12) ^ (z11 - z13 - z12)
		z15 = (z14 << 16) ^ (z12 - z13 - z14)
		z16 = (z15 >> 5) ^ (z13 - z15 - z14)
		z8 = (z16 >> 3) ^ (z14 - z16 - z15)
		z6 = (z8 << 10) ^ (z15 - z16 - z8)
		n = (z6 >> 15) ^ (z16 - z6 - z8)
		z7 -= 12
		z26--
		i = i + 0xC
	}
	z3 = s
	z17 = z3 + n
	switch z7 {
	case 1:
		goto LABEL_16
	case 2:
		goto LABEL_15
	case 3:
		goto LABEL_14
	case 4:
		goto LABEL_13
	case 5:
		goto LABEL_12
	case 6:
		goto LABEL_11
	case 7:
		goto LABEL_10
	case 8:
		goto LABEL_9
	case 9:
		goto LABEL_8
	case 0xA:
		goto LABEL_7
	case 0xB:
		z17 += uint32(data[10+i]) << 24
	default:
		goto LABEL_17
	}

LABEL_7:
	z17 += uint32(data[9+i]) << 16
LABEL_8:
	z17 += uint32(data[8+i]) << 8
LABEL_9:
	z6 += uint32(data[7+i]) << 24
LABEL_10:
	z6 += uint32(data[6+i]) << 16
LABEL_11:
	z6 += uint32(data[5+i]) << 8
LABEL_12:
	z6 += uint32(data[4+i])
LABEL_13:
	z8 += uint32(data[3+i]) << 24
LABEL_14:
	z8 += uint32(data[2+i]) << 16
LABEL_15:
	z8 += uint32(data[1+i]) << 8
LABEL_16:
	z8 += uint32(data[0+i])
LABEL_17:
	z18 = (z17 >> 13) ^ (z8 - z17 - z6)
	z19 = (z18 << 8) ^ (z6 - z17 - z18)
	z20 = (z19 >> 13) ^ (z17 - z19 - z18)
	z21 = (z20 >> 12) ^ (z18 - z20 - z19)
	z22 = (z21 << 16) ^ (z19 - z20 - z21)
	z23 = (z22 >> 5) ^ (z20 - z22 - z21)
	z24 = (z23 >> 3) ^ (z21 - z23 - z22)

	return (((z24 << 10) ^ (z22 - z23 - z24)) >> 15) ^ (z23 - ((z24 << 10) ^ (z22 - z23 - z24)) - z24)
}
