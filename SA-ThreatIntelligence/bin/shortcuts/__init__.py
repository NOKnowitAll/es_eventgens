import csv
import collections
import functools
import gzip
import json
import logging
import logging.handlers
import math
import os
import random
import re
import StringIO
import struct
import sys
import time

import splunk.util as util

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from SolnCommon.kvstore import KvStoreHandler

   
class Duration(object):
    
    DURATION_MAP = [
                ("y", 31556926),
                ("yr", 31556926),
                ("yrs", 31556926),
                ("year", 31556926),
                ("years", 31556926),
                ("mon", 2629744),
                ("M", 2629744),
                ("month", 2629744),
                ("months", 2629744),
                ("q", 3 * 2629744),
                ("qtr", 3 * 2629744),
                ("qtrs", 3 * 2629744),
                ("quarter", 3 * 2629744),
                ("quarters", 3 * 2629744),
                ("d", 86400),
                ("day", 86400),
                ("days", 86400),
                ("w", 7 * 86400),
                ("week", 7 * 86400),
                ("weeks", 7 * 86400),
                ("h", 3600),
                ("hr", 3600),
                ("hrs", 3600),
                ("hour", 3600),
                ("hours", 3600),
                ("m", 60),
                ("min", 60),
                ("minute", 60),
                ("minutes", 60),
                ("s", 1),
                ("sec", 1),
                ("secs", 1),
                ("second", 1),
                ("seconds", 1)
                ]


    @staticmethod
    def duration_from_readable(duration):
        """
        Takes a duration as a string (like "1d") and produces the duration in seconds.
        """
    
        # If the duration is an empty string, then the user is not using throttling
        if duration is None or ( isinstance(duration, basestring) and len(duration.strip()) == 0):
            return None
    
        # Create a regular expression that is capable of matching the duration
        regex = re.compile("\s*(?P<duration>[0-9]+)\s*(?P<units>([a-z]+))?",re.IGNORECASE)
        
        # Try to perform a match
        m = regex.match(str(duration))
    
        # If we did not get a match, then raise an exception
        if m is None:
            raise ValueError("Invalid duration specified (%s)." % (str(duration)) ) 
    
        # If we did get a match then extract the components
        units = m.groupdict()['units']
        duration = int(m.groupdict()['duration'])
    
        # Per-digest/per-event alerting cannot use zero or negative integers as the suppression window.
        if duration <= 0:
            raise ValueError("Duration cannot be negative or zero.") 

        # If units are None, then treat the duration as seconds
        if units is None:
            return duration
        
        # Get the multiplier from the duration map
        for duration_entry in Duration.DURATION_MAP:
        
            # If the units match the given entry, then return the value in seconds
            if duration_entry[0] == units:
                return duration_entry[1] * duration
         
        # We should never get here since the regex should have caught any 
        # units that do not correspond to a duration.
        raise ValueError("Invalid duration specified (%s)." % ( str(duration)) )


    @staticmethod
    def duration_to_readable(duration_seconds):
        """
        Takes a duration (in seconds) and produces a friendly string version (like "1d" for 1 day)
        """
    
        # If the duration is none, then return an empty string
        if duration_seconds is None:
            return ""
    
        # Iterate through the duration map and find
        for duration_entry in Duration.DURATION_MAP:
        
            # Get the number of seconds that a given duration unit corresponds to
            seconds = duration_entry[1]
        
            # Get a string that represents the duration
            if duration_seconds >= seconds and (duration_seconds % seconds) == 0:
                return str(duration_seconds / seconds) + duration_entry[0]
    
        # If no match could be found, then consider the duration in units of seconds
        return str(duration_seconds) + "s"


class NotableOwner(object):

    @classmethod
    def getOwners(cls, session_key, use_name_as_realname=False, prefer=None, reverse=False):
        '''Return list of Splunk users permitted to edit notable events.
        Parameters:
            session_key: (string) A Splunk session key.
            use_name_as_realname: (bool) Use the name as the realname, if realname is empty.
            prefer: (string) Force the first entry in the sort order to be this value. 
            reverse: (bool) Reverse the effect of "prefer" - the last will be first.
        '''
        
        def sort_with_preference(pref, rev, x, y):
            if x == pref:
                if rev:
                    return 1
                return -1
            elif y == pref:
                if rev:
                    return -1
                return 1
            else:
                return cmp(x, y)

        if prefer:
            cmp_fn = functools.partial(sort_with_preference, prefer, reverse)
        else:
            cmp_fn = cmp
            
        options = {'owner': 'nobody', 'app': 'SA-ThreatIntelligence', 'collection': 'notable_owners'}
        unused_response, content = KvStoreHandler.get(None, session_key, options)
        owners = json.loads(content)

        if use_name_as_realname:
            return collections.OrderedDict(sorted([(i.get('owner'), i.get('realname') or i.get('owner')) for i in owners], cmp=cmp_fn, key=lambda x: x[0]))
        else:
            return collections.OrderedDict(sorted([(i.get('owner'), i.get('realname', '')) for i in owners], cmp=cmp_fn, key=lambda x: x[0]))

class Severity(object):

    SEVERITIES = []
        
    @classmethod
    def getSeverities(cls, force_reload=False):

        # Return cached value unless this is the first such call,
        # or if force_reload is specified.
        if len(cls.SEVERITIES) == 0 or force_reload:
            headerElement = 'severity'

            # Find the urgency table within Splunk
            csvFile = make_splunkhome_path(["etc", "apps", "SA-ThreatIntelligence", "lookups", "urgency.csv"])
            # Read CSV file into the list, skipping the header line.
            with open(csvFile, 'rU') as f: 
                cls.SEVERITIES = set([row[0].lower() for row in csv.reader(f) if row[0] != headerElement])
                
        return cls.SEVERITIES

    @classmethod
    def from_readable_severity(cls, severity):
        """
        Takes the readable severity and returns the version that is saved in correlation searches.conf
        """
        if isinstance(severity, basestring):
            if severity.strip().lower() in cls.getSeverities():
                return severity.strip().lower()
        return 'unknown'
    
    
class Urgency(object):

    URGENCIES = []
        
    @classmethod
    def getUrgencies(cls, force_reload=False):

        # Return cached value unless this is the first such call,
        # or if force_reload is specified.
        if len(cls.URGENCIES) == 0 or force_reload:
            headerElement = 'urgency'

            # Find the urgency table within Splunk
            csvFile = make_splunkhome_path(["etc", "apps", "SA-ThreatIntelligence", "lookups", "urgency.csv"])
            # Read CSV file into the list, skipping the header line.
            with open(csvFile, 'rU') as f: 
                cls.URGENCIES = set([row[2].lower() for row in csv.reader(f) if row[2] != headerElement])
                
        return cls.URGENCIES

    @classmethod
    def from_readable_urgency(cls, urgency):
        """
        Takes the readable urgency and returns the version that is saved in correlation searches.conf
        """
        if isinstance(urgency, basestring):
            if urgency.strip().lower() in cls.getUrgencies():
                return urgency.strip().lower()
        return 'unknown'
