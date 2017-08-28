// THIS FILE IS AUTOGENERATED, EDIT frame_opcodes.txt INSTEAD

package main

var frameOpcodeHigh2 = map[uint8]string{
	0x1: "DW_CFA_advance_loc",
	0x2: "DW_CFA_offset",
	0x3: "DW_CFA_restore",
}
var frameOpcodeLow6 = map[uint8]string{
	0:    "DW_CFA_nop",
	0x01: "DW_CFA_set_loc",
	0x02: "DW_CFA_advance_loc1",
	0x03: "DW_CFA_advance_loc2",
	0x04: "DW_CFA_advance_loc4",
	0x05: "DW_CFA_offset_extended",
	0x06: "DW_CFA_restore_extended",
	0x07: "DW_CFA_undefined",
	0x08: "DW_CFA_same_value",
	0x09: "DW_CFA_register",
	0x0a: "DW_CFA_remember_state",
	0x0b: "DW_CFA_restore_state",
	0x0c: "DW_CFA_def_cfa",
	0x0d: "DW_CFA_def_cfa_register",
	0x0e: "DW_CFA_def_cfa_offset",
	0x0f: "DW_CFA_def_cfa_expression",
	0x10: "DW_CFA_expression",
	0x11: "DW_CFA_offset_extended_sf",
	0x12: "DW_CFA_def_cfa_sf",
	0x13: "DW_CFA_def_cfa_offset_sf",
	0x14: "DW_CFA_val_offset",
	0x15: "DW_CFA_val_offset_sf",
	0x16: "DW_CFA_val_expression",
	0x1c: "DW_CFA_lo_user",
	0x3f: "DW_CFA_hi_user",
}
var frameOpcodeArgs = map[uint8]string{
	0x40: "",
	0x80: "u",
	0xc0: "",
	0x0:  "",
	0x1:  "8",
	0x2:  "1",
	0x3:  "2",
	0x4:  "4",
	0x5:  "uu",
	0x6:  "u",
	0x7:  "u",
	0x8:  "u",
	0x9:  "uu",
	0xa:  "",
	0xb:  "",
	0xc:  "uu",
	0xd:  "u",
	0xe:  "u",
	0xf:  "B",
	0x10: "uB",
	0x11: "us",
	0x12: "us",
	0x13: "s",
	0x14: "uu",
	0x15: "us",
	0x16: "uB",
	0x1c: "",
	0x3f: "",
}
