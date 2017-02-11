# Copyright (C) 2009-2015 Splunk Inc. All Rights Reserved.
#
# This file contains additional options for an inputs.conf file.  
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#

[threatlist://default]
* Configures an input for downloading a threat list or other source of threat
* intelligence from a remote site. Currently supports the following protocols:
*
*    1. HTTP [basic and digest authentication]
*    2. HTTPS [basic and digest authentication]
*    3. Local lookup table
*
* For HTTP/HTTPS content, the following content types are supported by the parser:
*
*    a. TAXII feeds (specified by the parameter "type = taxii")
*    b. Line-oriented text data (specified by any other value of the "type" parameter)
*
* All local lookup table content is regarded as line-oriented text data.
*
* Since the threatlist modular input type is used to download multiple types of
* threat content, certain fields are required only for certain types of content.
* Notably, all fields related to parsing are ONLY applicable to line-oriented data
* and will be completely ignored if the input is a TAXII feed. These fields are:
*
*    delim_regex        (defaults to ",")
*    extract_regex      (no default)
*    fields             (defaults to "description:$1,ip:$2")
*    ignore_regex       (defaults to "(^#|^\s*$)")
*    skip_header_lines  (defaults to 0)
*

delim_regex = <string>
* [Applicable to line oriented data] A regular expression used to delimit 
* the threat list. One of extract_regex OR delim_regex is required. If not 
* specified, defaults to the comma character (,). Ignored for TAXII feeds.

description = <string>
* [Optional] A description of the threat list.

extract_regex = <string>
* [Applicable to line oriented data] A regular expression matching groups that 
* will be extracted from the threat list. One of extract_regex OR delim_regex 
* is required. Does not have a default value. Ignored for TAXII feeds.

fields = <string>
* [Required for line oriented data] A comma-separated list of fields to be extracted from 
* the threat list by the parser, using the following format:
*
*	<fieldname>:$<number>,<field name>.$<number>
*
* If not specified, defaults to "description:$1,ip:$2". Ignored for TAXII feeds
* and other content.

ignore_regex = <string>
* [Required for line oriented data] A regular expression matching lines that will be 
* ignored in the threat list. If not specified, defaults to the following, which
* ignores blank lines and comments:
*
*	ignored_regex = (^#|^\s*$)
*
* Ignored for TAXII feeds.

initial_delay = <seconds>
* [DEFAULT_STANZA_ONLY, Optional] An initial delay in seconds imposed before the
* modular input begins downloading any files. This is used to alleviate startup 
* load.

master_host = <string>
* [DEFAULT_STANZA_ONLY] Defines the master host if search head pooling is enabled.
* Only the master host will perform threat list downloads. If SHP is enabled this
* MUST be non-empty AND match the name of a server in the pool.

max_age = <relative time>
* [Optional] A Splunk-style relative time string. Threat content older than 
* max_age will be aged out of any downstream KV store collections and/or lookup
* tables. Note that age is defined differently for different types of threat 
* content.
*
*    - For CSV or text-based threat content, this is usually the time of collection
*    - For TAXII feeds, this may be the time of the indicator item extracted from
*      the STIX or IOC document.
*
* In general this setting is less applicable to threat content such as TAXII 
* feeds which may extract timestamps from the content.
*
* If unset or set to 0, no expiration occurs.
*
* Note: "rt" is not supported for this parameter. Additionally note that this 
* parameter is non-functional in standalone installations of SA-ThreatIntelligence.
* It is provided as a hook for consumers of threat intelligence to utilize. 

post_args = <string>
* A list of POST arguments to be sent with the request. Applicable to HTTP(S)
* URLs only. Argument should be specified in one of the following formats:
*
*    key=value
*    key="value"
*
* An additional special syntax is provided for purposes of retrieving Splunk
* stored credentials:
*
*    key=$user:<username>$
*
* Example:
*
*    key=$user:api_username$
*
* If this form is used, the password corresponding to the stored credential
* will be retrieved and used as a POST argument. This is convenient in cases
* where an API key must be sent as a POST argument to complete the HTTP(S) 
* request, but true HTTP authentication is not required.
*
* For authentication to TAXII feeds, the following parameters are accepted:
*
*    collection     - The collection to be polled.
*    earliest       - A Splunk time qualifier. Filters results to only those 
*                     older than the time specified.
*    taxii_username - The name of a user used to authenticate to the TAXII server
*    taxii_password - A password used to authenticate to the TAXII server
*    cert_file      - An SSL certificate file. MUST reside in <appname>/auth/ in
*                     the same app as the inputs.conf stanza that defines the 
*                     TAXII feed download.
*    key_file       - An SSL private key file. MUST reside in <appname>/auth/ in
*                     the same app as the inputs.conf stanza that defines the 
*                     TAXII feed download.
*
* WARNING: SA-ThreatIntelligence excludes certificate files from being collected
* by the "splunk diag" command by default, via a stanza in server.conf. If you 
* are placing TAXII feed definitions in apps OTHER than SA-ThreatIntelligence,
* you MUST place a similar server.conf definition in your app to prevent
* inadvertend exposure of certificate information.
* 
* Example:
*
*    collection="admin.splunk" earliest="-1y" taxii_username="splunk" taxii_password="splunk" cert_file="splunk.crt" key_file="splunk.key"
*
* TAXII Authentication handling
*
* If taxii_username, taxii_password, cert_file, and key_file are provided, 
* AUTH_CERT_BASIC will be attempted (compatible with Soltra Edge devices).
*
* If taxii_username and taxii_password are not provided, but cert_file and 
* key_file are, AUTH_CERT will be attempted.
*
* If neither of the preceding are true, AUTH_BASIC will be attempted.

proxy_port = <integer>
* [API only, optional] A proxy server port.

proxy_server = <string>
* [API only, optional] A proxy server name.

proxy_user = <string>
* [API only, optional] A proxy server user name. If present, must correspond to a
* credential name in the secure credential store.

retries = <integer>
* [Optional] The number of times to attempt a specific download before marking
* the download as failed.

retry_interval = <seconds>
* [Required] The interval (in seconds) between retries.

skip_header_lines = <integer>
* [Applicable to line oriented data] The number of header lines to skip when 
* reading the threatlist. For any stanzas that use "lookup://<lookup_name>" to 
* specify a Splunk lookup table as a threatlist, this should usually be set to 1 
* to avoid reading processing the CSV header as a valid threatlist entry. Failure
* to set this will not impede processing, but may result in verbose errors in 
* the python_modular_input.log file when an attempt is made to read in a header
* line as data. Ignored for TAXII feeds.

site_user = <string>
* [Optional] The user used for authentication to the remote site. This is
* distinct from proxy credentials. If present, must correspond to a credential
* name in the secure credential store.

target = <string>
* [DEPRECATED] Target lookup table for the merge process. Used for processing 
* of legacy threatlist content only. Do not use in the definition of new stanzas. 

type = <string>
* [Required] Type of threat intelligence. Arbitrary. Intended to be used as a simple
* categorization mechanism for threat intelligence. Must be "taxii" for all 
* TAXII feeds.
*
* For legacy reasons, the following values are reserved and should not be used
* in customer-defined stanzas:
*
*    alexa
*    asn
*    mozilla_psl
*    tld

timeout = <seconds>
* [DEFAULT_STANZA_ONLY, Optional] The interval (in seconds) before a download 
* attempt times out. Defaults to 30 seconds if not specified.

url = <url>
* [Required] The remote URL to download. Must begin with one of the following:
* "http://", "https://", "lookup://". If "lookup://" is used, instead of
* downloading a remote file, the local lookup table referred to will be incorporated
* into the merged threatlist. In this case, download, interval, and proxy parameters
* are ignored.

weight = <integer>
* [Required] The weight assigned to the threatlist, between 1 and 100. A higher
* weight will result in higher risk score for being assigned to IPs that appear
* in Splunk events corresponding to values in the threatlist.


[threatlist_manager://default]
* Configures a modular input that merges information from all defined
* "threatlist" input stanzas.

master_host = <string>
* [DEFAULT_STANZA_ONLY] Defines the master host if search head pooling is enabled.
* Only the master host will perform threat list downloads. If SHP is enabled this
* MUST be non-empty AND match the name of a server in the pool.
