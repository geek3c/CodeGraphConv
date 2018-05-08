#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys

IDA_ENGINE_PATH = "/usr/local/ida/idal64"
IDA_START = "./shell/ida_start.sh"


def generate_i64(binary_path, idb_store_path, ida_start=IDA_START, ida_engine_path=IDA_ENGINE_PATH):
    """
    生成二进制程序的 i64 文件并保存到指定目录(i64文件名可同时指定, 未指定则与二进制程序同名)
    :param binary_path: 二进制程序路径
    :param idb_store_path: i64 文件保存路径
    :param ida_start: 启动 ida 的脚本
    :param ida_engine_path: idal64 的路径
    :return: 生成的 i64 文件的路径
    """
    if os.path.exists(ida_engine_path):
        # ida 加载二进制文件并将 ida 的i64文件保存到指定位置
        os.system('%s %s %s %s' % (ida_start, ida_engine_path, binary_path, idb_store_path))
        # i64 文件保存在当前目录下时，其默认名字与二进制程序名相同
        if idb_store_path == "." or idb_store_path == "./":
            return os.path.basename(binary_path) + ".i64"
        elif idb_store_path[-4:] == ".i64":
            # 指定 i64 文件保存路径时, 输入带有文件名后缀 .i64
            return idb_store_path
        else:
            return idb_store_path + ".i64"


def help():
    print "使用方法:"
    print "python %s 二进制程序路径 idb文件保存路径" % sys.argv[0]


if __name__ == "__main__":
    if len(sys.argv) < 3:
        help()
        exit(-1)
    print generate_i64(sys.argv[1], sys.argv[2])
