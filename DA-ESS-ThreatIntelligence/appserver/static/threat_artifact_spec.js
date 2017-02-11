'use strict';

define(["underscore"], function (_) {
	/**
  * Processes the submitted input tokens from the input field tokens defined in the caller, and return a single
  * output token representing each of the fields defined in the input tokens.
  *
  * @param submittedTokens A SplunkJS object containing all of the submitted tokens.
  *
  * @returns {string} Threat artifact search filter.
  *
        */
	function generateTokenFilter(submittedTokens) {
		var tokens = this.tokens,
		    tokenValue = void 0,
		    retFilter = '';

		for (var token in tokens) {
			if (Object.prototype.hasOwnProperty.call(tokens, token)) {

				var filter = '';

				// Check if token has been initialized.
				if (submittedTokens.has(token)) {
					tokenValue = submittedTokens.get(token);
				}

				if (tokenValue !== null && tokenValue !== undefined && tokenValue !== '' && tokens[token].length > 0) {

					filter += '(' + tokens[token][0] + '="' + tokenValue + '"';

					for (var i = 1; i < tokens[token].length; i++) {
						filter += ' OR ' + tokens[token][i] + '="' + tokenValue + '"';
					}

					retFilter += filter + ') AND ';
				}
			}
		}

		// Remove the " AND " on the end.
		retFilter = retFilter.slice(0, -5);

		return retFilter;
	}

	//
	// Threat Artifact Specification
	//

	return {
		hasOwn: Object.prototype.hasOwnProperty,

		/**
   * Threat Artifacts
   * @param name Human readable artifact name.
   * @param outputToken The token submitted for the collective user input for the artifact.
   * @param elements List of HTML elements for reference to field inputs.
   * @param tokens Mapping from field input token to associated threat collection fields:
   * 			<field_input_token>:[<threat_collection_field>]
   * @param getFilter Mapping to the method used to process the input tokens and return the outputToken.
   */
		ARTIFACTS: {
			THREAT_OVERVIEW: {
				name: _("Threat ID").t(),
				outputToken: 'threat_id_filter',
				elements: ['#threat_category', '#threat_group', '#malware_alias', '#threat_source_id', '#threat_source_path'],
				tokens: {
					'threat_category': ['threat_category'],
					'threat_group': ['threat_group'],
					'malware_alias': ['malware_alias'],
					'threat_source_id': ['source_id'],
					'threat_source_path': ['source_path']
				},
				getFilter: generateTokenFilter
			},
			NETWORK: {
				name: _("Network").t(),
				outputToken: 'network_filter',
				elements: ['#ip', '#domain', '#http_holder', '#http_referer', '#http_user_agent', '#http_cookie', '#http_header', '#http_data', '#http_url'],
				tokens: {
					'ip': ['ip'],
					'domain': ['domain'],
					'http_referer': ['http_referrer'],
					'http_user_agent': ['http_user_agent'],
					'http_cookie': ['cookie'],
					'http_header': ['header'],
					'http_data': ['data'],
					'http_url': ['url']
				},
				getFilter: generateTokenFilter
			},
			FILE: {
				name: _("File").t(),
				outputToken: 'file_filter',
				elements: ['#file_name', '#file_extension', '#file_path', '#file_hash'],
				tokens: {
					'file_name': ['file_name'],
					'file_extension': ['file_extension'],
					'file_path': ['file_path'],
					'file_hash': ['file_hash']
				},
				getFilter: generateTokenFilter
			},
			REGISTRY: {
				name: _("Registry").t(),
				outputToken: 'registry_filter',
				elements: ['#registry_hive', '#registry_path', '#registry_key_name', '#registry_value_name', '#registry_value_type', '#registry_value_text'],
				tokens: {
					'registry_hive': ['registry_hive'],
					'registry_path': ['registry_path'],
					'registry_key_name': ['registry_key_name'],
					'registry_value_name': ['registry_value_name'],
					'registry_value_type': ['registry_value_type'],
					'registry_value_text': ['registry_value_text']
				},
				getFilter: generateTokenFilter
			},
			SERVICE: {
				name: _("Service").t(),
				outputToken: 'service_filter',
				elements: ['#service_name', '#service_descriptive_name', '#service_description', '#service_type'],
				tokens: {
					'service_name': ['service'],
					'service_descriptive_name': ['descriptive_name'],
					'service_description': ['description'],
					'service_type': ['service_type']
				},
				getFilter: generateTokenFilter
			},
			USER: {
				name: _("User").t(),
				outputToken: 'user_filter',
				elements: ['#user_name', '#user_full_name', '#user_group_name', '#user_description'],
				tokens: {
					'user_name': ['user'],
					'user_full_name': ['full_name'],
					'user_group_name': ['group_name'],
					'user_description': ['description']
				},
				getFilter: generateTokenFilter
			},
			PROCESS: {
				name: _("Process").t(),
				outputToken: 'process_filter',
				elements: ['#process', '#process_arguments', '#handle_name', '#handle_type'],
				tokens: {
					'process': ['process'],
					'process_arguments': ['process_arguments'],
					'handle_name': ['process_handle_name'],
					'handle_type': ['process_handle_type']
				},
				getFilter: generateTokenFilter
			},
			CERTIFICATE: {
				name: _("Certificate").t(),
				outputToken: 'certificate_filter',
				elements: ['#certificate_serial_number', '#certificate_subject', '#certificate_issuer', '#certificate_valid_not_after', '#certificate_valid_not_before'],
				tokens: {
					'certificate_serial_number': ['certificate_serial', 'certificate_serial_clean', 'certificate_serial_dec'],
					'certificate_subject': ['certificate_subject'],
					'certificate_issuer': ['certificate_issuer'],
					'certificate_valid_not_after': ['certificate_end_time'],
					'certificate_valid_not_before': ['certificate_start_time']
				},
				getFilter: generateTokenFilter
			},
			EMAIL: {
				name: _("Email").t(),
				outputToken: 'email_filter',
				elements: ['#email_address', '#email_subject', '#email_body'],
				tokens: {
					'email_address': ['src_user', 'actual_src_user', 'recipient', 'actual_recipient'],
					'email_subject': ['subject'],
					'email_body': ['body']
				},
				getFilter: generateTokenFilter
			}
		},

		/**
   *
   * @returns {Object} An object that, for each artifact defined in <tt>this.ARTIFACTS</tt>, contains the
   * artifact 'name' as the key and an 'array' list of each of its elements as its value.
   *
            */
		getArtifactElements: function getArtifactElements() {
			var aggregatedElements = {};

			for (var artifact in this.ARTIFACTS) {
				if (this.hasOwn.call(this.ARTIFACTS, artifact)) {
					aggregatedElements[this.ARTIFACTS[artifact].name] = this.ARTIFACTS[artifact].elements;
				}
			}

			return aggregatedElements;
		}
	};
});
