#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import ConfigParser


def resolve_funcs(binary_path, save_dir, binary_hash, config_file):
    """
    分析二进制文件的所有函数地址
    :param binary_path: 二进制文件路径
    :param save_dir: 分析结果保存的目录
    :param binary_hash: 二进制文件hash
    :param config_file: 配置文件路径
    :return: 保存二进制文件所有函数地址的json文件路径
    """

    # 读取配置文件
    config = ConfigParser.ConfigParser()
    config.read(config_file)

    ida_engine_path = config.get('ida_config', 'IDA_ENGINE_PATH')
    idb_store_path = os.path.join(save_dir, binary_hash, config.get('ida_config', 'IDA_I64_PATH'))
    functions_path = os.path.join(save_dir, binary_hash, config.get('result_config', 'FUNCTIONS_INFO'))

    ida_start = config.get('scripts_config', 'IDA_START')
    ida_list_funcs = config.get('scripts_config', 'IDA_LIST_FUNCS')
    ida_resolve_unknows_funcs = config.get('scripts_config', 'IDA_RESOLVE_UNKNOWN_FUNCS')

    if os.path.exists(ida_engine_path):
        # load binary with ida
        os.system('%s %s %s %s' % (ida_start, ida_engine_path, binary_path, idb_store_path))
        # resolve unknown funcs
        os.system(
            "TVHEADLESS=1 %s -A -S'%s ' %s > /dev/null" % (ida_engine_path, ida_resolve_unknows_funcs, idb_store_path))
        # get all functions addr
        os.system("TVHEADLESS=1 %s -A -S'%s %s ' %s > /dev/null" % (
            ida_engine_path, ida_list_funcs, functions_path, idb_store_path))
        return functions_path
