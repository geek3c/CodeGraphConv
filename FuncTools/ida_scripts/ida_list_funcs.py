#!/usr/bin/env python
# -*- coding: utf-8 -*-
from idc import SegByBase, SegByName, SegStart, SegEnd, ARGV
from idautils import Functions
from idaapi import *
import json
import os


def is_func_in_section(func_addr, exec_ranges):
    for exec_range in exec_ranges:
        if func_addr >= exec_range[0] and func_addr < exec_range[1]:
            return True
    return False


def get_executable_range():
    executable_ranges = []
    seg = idc.FirstSeg()
    while seg != idc.BADADDR:
        if idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE) == idaapi.SEG_CODE:
            executable_ranges.append((idc.SegStart(seg), idc.SegEnd(seg)))
        seg = idc.NextSeg(seg)
    return executable_ranges


def get_section_range(type):
    # eg: .text/.bss/.rodata
    ea = SegByBase(SegByName(type))
    return SegStart(ea), SegEnd(ea)


def resolve_functions(save_path):
    # get executable range
    executable_ranges = []
    text_range = get_section_range('.text')
    if text_range[0] == idc.BADADDR:
        # no '.text'
        executable_ranges = get_executable_range()
    else:
        executable_ranges.append(text_range)

    funcs = Functions()
    all_func_start_addr = [f for f in funcs if is_func_in_section(f, executable_ranges)]
    json.dump(all_func_start_addr, open(save_path, 'w'))


def main():
    save_path = ARGV[1]
    resolve_functions(save_path)


main()
# exit ida
idc.Exit(0)
