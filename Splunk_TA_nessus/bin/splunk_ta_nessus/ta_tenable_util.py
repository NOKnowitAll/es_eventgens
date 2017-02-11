import iso8601
import calendar
import re
import datetime
import time

from solnlib import time_parser


def extract_host(server_url):
    pattern = re.compile('(?:https?://)?([^ :]+)(?::\d+)?$')
    return pattern.search(server_url.lower()).groups()[0]


def iso8601_to_timestamp(iso8601_time):
    return calendar.timegm(iso8601.parse_date(iso8601_time).utctimetuple())


def get_30_days_ago_local_time(session_key):
    cur_time = time.time()
    before_time = cur_time - 30 * 24 * 60 * 60
    return timestamp_to_localtime(session_key, before_time)


def timestamp_to_localtime(session_key, timestamp):
    tp = time_parser.TimeParser(session_key)
    utc_str = timestamp_to_utc(timestamp)
    local_str = tp.to_local(utc_str)
    return local_str[0:19] + local_str[23:]

def timestamp_to_utc(timestamp):
    utc_time = datetime.datetime.utcfromtimestamp(timestamp)
    return utc_time.strftime('%Y-%m-%dT%H:%M:%S+0000')
