#!/usr/bin/python
"""
This is the main entry point for My TA
"""
import ta_tenable_import_declare as sd

import os.path as op

import splunktaucclib.data_collection.ta_mod_input as ta_input
from ta_tenable_sc_data_collector import do_job_one_time as collector_cls


def ta_run():
    schema_file_path = op.join(
        op.dirname(op.abspath(__file__)), sd.ta_lib_name,
        "tenable_schema.sc_config.json")
    ta_input.main(collector_cls, schema_file_path, 'tenable_sc')


if __name__ == "__main__":
    ta_run()
