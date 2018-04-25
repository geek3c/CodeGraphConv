#!/usr/bin/env python

"""
resolve unknown functions based on function prologs pattern
"""

import idc
import idaapi
import idautils
import re

# TODO: fix ARM endian key
FUNCTION_PROLOGS = {
	"mipsl": 										# little endian
			r"([\x00-\xff]{2}\x1c\x3c)?"			# lui $gp, xxx
			r"[\x00-\xff]{2}\xbd\x27"				# addiu $sp, xxx
			r"([\x00-\xff]{2}\x9c\x27)?"			# li $gp, xxx
			r"[\x00-\xff]{2}\xbf\xaf",			    # sw $ra, xxx
	"mipsb": 										# bir endian
			r"(\x3c\x1c[\x00-\xff]{2})?"			# lui $gp, xxx
			r"\x27\xbd[\x00-\xff]{2}"				# addiu $sp, xxx
			r"(\x27\x9c[\x00-\xff]{2})?"			# li $gp, xxx
			r"\xaf\xbf[\x00-\xff]{2}",				# sw $ra, xxx
	"ARM":  r"[\x00-\xff]{2}\x2d\xe9",				# stmfd sp!, xxx (little endian)
	"ARMB": r"\xe9\x2d[\x00-\xff]{2}"				# stmfd sp!, xxx (big endian)
}


def get_proc_name():
	info = idaapi.get_inf_structure()
	# info.mf:  check endian
	return info.procName


def get_start_ea(segattr_type):
	ea = idc.BADADDR
	seg = idc.FirstSeg()

	while seg != idc.BADADDR:
		if idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE) == segattr_type:
			ea = seg
			break
		else:
			seg = idc.NextSeg(seg)

	return ea


def read_addr(addr, nums_of_bytes=16):
	# ignore endian by reading in byte unit
	res = []
	for index in range(nums_of_bytes):
		res.append(Byte(addr+index))
	return ''.join(map(lambda x: "%02x" % x ,res))


def resolve_unknown_functions():
	proc_name = get_proc_name()
	if proc_name.startswith("mips"):
		prolog_pattern = FUNCTION_PROLOGS.get(proc_name, "BAD ARCH")
	elif proc_name.startswith("ARM"):
		prolog_pattern = FUNCTION_PROLOGS.get(proc_name, "BAD ARCH")
	else:
		# TODO: support another arch
		return

	ea = get_start_ea(idaapi.SEG_CODE)
	if ea == idc.BADADDR:
		ea = idc.FirstSeg()
	cur_seg_end = idc.SegEnd(ea)

	while ea != idc.BADADDR:
		if ea < cur_seg_end and idc.GetSegmentAttr(ea, idc.SEGATTR_TYPE) == idaapi.SEG_CODE:
			if idc.GetFunctionFlags(ea) == -1:
				# not function
				raw_data_hex = read_addr(ea)
				if re.match(prolog_pattern, raw_data_hex.decode('hex')):
					idc.MakeFunction(ea)
			ea = ea + 4
		else:
			ea = idc.NextSeg(ea)
			cur_seg_end = idc.SegEnd(ea)


def main():
	resolve_unknown_functions()


main()
# exit ida
idc.Exit(0)
