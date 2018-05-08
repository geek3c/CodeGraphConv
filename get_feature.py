#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from .utils import generate_i64


def get_one_function_feature():
    pass


def get_all_function_feature(binary_path):
    i64_filepath = "./hahahaha"
    i64_path = generate_i64(binary_path, i64_filepath)
    print i64_path


def help():
    print "使用方法:"
    print "python %s 二进制程序路径" % sys.argv[0]


if __name__ == "__main__":
    print "从二进制程序中提取基本块层次的特征信息"
    print "step 1: 生成二进制程序对应的i64文件"

    if len(sys.argv) < 3:
        help()
        exit(-1)

    get_all_function_feature(sys.argv[1])
