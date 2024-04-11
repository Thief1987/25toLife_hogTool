package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
)

const hogMagic = 0x00020001

func ReadUint32(r io.Reader) uint32 {
	var buf bytes.Buffer
	io.CopyN(&buf, r, 4)
	return binary.LittleEndian.Uint32(buf.Bytes())
}

func HeaderInit(h *bytes.Buffer, o uint32, f uint32, s uint32, crc uint32, fl uint32) {
	binary.Write(h, binary.LittleEndian, uint32(hogMagic)) //Magic
	binary.Write(h, binary.LittleEndian, o)                //TOC offset
	binary.Write(h, binary.LittleEndian, fl)               //Encryption flag
	binary.Write(h, binary.LittleEndian, uint32(0))        //Header CRC
	binary.Write(h, binary.LittleEndian, f)                //Files count
	binary.Write(h, binary.LittleEndian, s)                //TOC size
	binary.Write(h, binary.LittleEndian, uint32(crc))      //TOC CRC
}

func padding(d *bytes.Buffer, base uint32) uint32 {
	len := d.Len()
	p := base - (uint32(len) % base)
	if p != base {
		for i := 0; i < int(p); i++ {
			binary.Write(d, binary.LittleEndian, uint8(0))
		}
	} else {
		p = 0
	}
	return uint32(p)
}

func repack(fn string, fl uint32) {
	var (
		name_buf, meta_buf, TOC_buf, data_buf, header_buf bytes.Buffer
		NT_size, p                                        uint32
	)
	filecount := 0
	new_arc, _ := os.Create(fn + "_new")
	defer new_arc.Close()
	err := os.Chdir(new_arc.Name()[:len(new_arc.Name())-len(path.Ext(new_arc.Name()))])
	if err != nil {
		new_arc.Close()
		os.Remove(fn + "_new")
		log.Fatal("Unpacked data doesn't exist, try to unpack original archive firstly")
	}
	meta, err := os.Open("metadata.bin")
	if err != nil {
		os.Chdir("../")
		new_arc.Close()
		os.Remove(fn + "_new")
		log.Fatal("metadata.bin doesn't exist, try to unpack original archive firstly")
	}
	defer meta.Close()
	io.Copy(&meta_buf, meta)
	baseoffset := ReadUint32(&meta_buf)
	files := ReadUint32(&meta_buf)
	TOC_size := ReadUint32(&meta_buf)
	DATAoffset := (baseoffset + TOC_size) + baseoffset - ((baseoffset + TOC_size) % baseoffset)
	NToffset := baseoffset + (files * 0x10)

	for i := 0; i < int(files); i++ {
		var f_buf bytes.Buffer
		n, _ := meta_buf.ReadString(0)
		name := strings.Replace(n, "\x00", "", -1)
		f, _ := os.Open(name)
		defer f.Close()
		info, _ := f.Stat()
		size := info.Size()
		if fl != 0 {
			io.Copy(&f_buf, f)
			f_buf.Write(encrypt(&f_buf))
		} else {
			io.Copy(&f_buf, f)
		}
		binary.Write(&TOC_buf, binary.LittleEndian, uint32(NToffset+NT_size))
		binary.Write(&TOC_buf, binary.LittleEndian, uint32(DATAoffset))
		binary.Write(&TOC_buf, binary.LittleEndian, uint32(size))
		binary.Write(&TOC_buf, binary.LittleEndian, CRCcalc(f_buf.Bytes(), uint32(f_buf.Len()), 0))
		name_buf.WriteString(name)
		binary.Write(&name_buf, binary.LittleEndian, uint8(0))
		NT_size = NT_size + uint32(len(name)) + 1
		data_buf.Write(f_buf.Bytes())
		if i != int(files-1) {
			p = padding(&data_buf, baseoffset)
		}
		fmt.Printf("0x%X       %v        %s\n", DATAoffset, size, name)
		DATAoffset = DATAoffset + uint32(size) + p
		filecount++

	}
	if fl != 0 {
		TOC_buf.Write(name_buf.Bytes())
		TOC_buf.Write(encrypt(&TOC_buf))
	} else {
		TOC_buf.Write(name_buf.Bytes())
	}
	TOC_crc := CRCcalc(TOC_buf.Bytes(), uint32(TOC_buf.Len()), 0)
	HeaderInit(&header_buf, baseoffset, files, TOC_size, TOC_crc, fl)
	header_crc := CRCcalc(header_buf.Bytes(), uint32(header_buf.Len()), 0)
	padding(&header_buf, baseoffset)
	new_arc.Write(header_buf.Bytes())
	padding(&TOC_buf, baseoffset)
	new_arc.Write(TOC_buf.Bytes())
	new_arc.Write(data_buf.Bytes())
	new_arc.Seek(0xC, 0)
	binary.Write(new_arc, binary.LittleEndian, header_crc)
	fmt.Printf("%v files succesfully packed", filecount)
}

func unpack(fn string) {
	var enc_buf, TOC_buf bytes.Buffer

	filecount := 0
	arc, err := os.Open(fn)
	if err != nil {
		log.Fatal("Wrong archive name")
	}
	defer arc.Close()
	os.Mkdir(arc.Name()[:len(arc.Name())-len(path.Ext(arc.Name()))], 0700)
	os.Chdir(arc.Name()[:len(arc.Name())-len(path.Ext(arc.Name()))])
	meta, _ := os.Create("metadata.bin")
	defer meta.Close()
	_ = ReadUint32(arc) //Magic
	baseoffset := ReadUint32(arc)
	enc_flag := ReadUint32(arc)
	_ = ReadUint32(arc) // Header CRC
	files := ReadUint32(arc)
	TOC_size := ReadUint32(arc)
	binary.Write(meta, binary.LittleEndian, baseoffset)
	binary.Write(meta, binary.LittleEndian, files)
	binary.Write(meta, binary.LittleEndian, TOC_size)
	arc.Seek(int64(baseoffset), 0)
	if enc_flag == 0x0000F00D {
		io.CopyN(&enc_buf, arc, int64(TOC_size))
		TOC_buf.Write(decrypt(enc_buf))
	} else {
		io.CopyN(&TOC_buf, arc, int64(TOC_size))
	}
	reader := bytes.NewReader(TOC_buf.Bytes())
	for i := 0; i < int(files); i++ {
		var name_buf bytes.Buffer
		name_off := ReadUint32(reader) - baseoffset
		offset := ReadUint32(reader)
		size := ReadUint32(reader)
		_ = ReadUint32(reader) // CRC
		savepos, _ := reader.Seek(0, 1)
		next_name_off := ReadUint32(reader) - baseoffset
		reader.Seek(int64(name_off), 0)
		if i == int(files-1) {
			io.CopyN(&name_buf, reader, int64(TOC_size)-int64(name_off)-1)
		} else {
			io.CopyN(&name_buf, reader, int64(next_name_off)-int64(name_off)-1)
		}
		p := strings.Replace(name_buf.String(), "\\", "/", -1)
		os.MkdirAll(path.Dir(p), 0700)
		f, _ := os.Create(name_buf.String())
		arc.Seek(int64(offset), 0)
		if enc_flag == 0x0000F00D {
			enc_buf.Reset()
			io.CopyN(&enc_buf, arc, int64(size))
			f.Write(decrypt(enc_buf))
		} else {
			io.CopyN(f, arc, int64(size))
		}
		f.Close()
		meta.WriteString(name_buf.String())
		binary.Write(meta, binary.LittleEndian, uint8(0))
		reader.Seek(savepos, 0)
		filecount++
		fmt.Printf("0x%X       %v        %s\n", offset, size, name_buf.String())
	}
	fmt.Printf("%v files succesfully extracted", filecount)
}
func main() {
	var enc_flag uint32

	args := os.Args
	if len(args) == 1 {
		log.Fatal("Usage:\n    unpack: -u archive_name\n    repack: -r archive_name -enc <- (optional flag, if you want to encrypt data in the archive)")
	}
	fmt.Println("Offset       Size                     Name   ")
	if args[1] == "-u" {
		unpack(args[2])
	} else if args[1] == "-r" {
		if len(args) > 3 {
			if args[3] == "-enc" {
				enc_flag = 0x0000F00D
			} else {
				enc_flag = 0
			}
			repack(args[2], enc_flag)
		} else {
			enc_flag = 0
			repack(args[2], enc_flag)
		}
	} else {
		log.Fatal("Unknown command\n Usage:\n    unpack: -u archive_name\n    repack: -r archive_name -enc <- (optional flag, if you want to encrypt data in the archive)")
	}
}
