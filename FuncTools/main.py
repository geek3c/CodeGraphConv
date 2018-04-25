#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import json
from ida_scripts import ida_utils


def get_functions(binary_path, save_dir):
    """
    获取二进制文件的所有函数地址(十进制表示)
    :param binary_path: 二进制文件路径
    :param save_dir: 结果保存的目录(在该目录下以二进制文件md5值创建子目录)
    :return: 二进制文件的所有函数地址
    """
    if not os.path.exists(binary_path):
        print "binary file do not exists."
        return
    # 执行系统命令获得二进制文件的md5(python对文件计算得到的md5值与shell计算的不同)
    bin_hash = os.popen("md5sum " + binary_path + "|cut -d ' ' -f 1").read().strip('\n')
    funcs_file = ida_utils.resolve_funcs(binary_path, save_dir, bin_hash, "sys.conf")
    all_functions = json.load(open(funcs_file, 'r')) if os.path.exists(funcs_file) else []
    return all_functions


if __name__ == "__main__":
    get_functions(sys.argv[1], sys.argv[2])
    print "Find function address task completed."
