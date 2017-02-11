define([
    'jquery',
    'underscore',
    'backbone',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/multidropdownview',
    'splunkjs/mvc/simpleform/input/dropdown',
    'splunkjs/mvc/simpleform/input/text',
    'splunkjs/mvc/sharedmodels',
    'sa-utils/js/util/Utils',
    'util/splunkd_utils',
    'splunk.util'
], function(
    $,
    _,
    Backbone,
    mvc,
    SearchManager,
    MultiDropdownView,
    DropdownInput,
    TextInput,
    SharedModels,
    esutils,
    splunkd_utils
) {
    return Backbone.View.extend({

        events: {
        	"click #create_capture": "save"
        },

    	/**
    	 * Setup defaults parameters.
    	 */
        defaults: {
        	insufficient_permission_message: 'You do not have the necessary capabilities required to perform this action. Please contact your Splunk administrator.',
        	stream_not_installed_message: 'The <a target="_blank" href="http://apps.splunk.com/app/1809/">Splunk App for Stream</a> is not installed; please install it in order to create captures.',
        	capture_already_exists_message: 'This Stream already exists.'
        },

        /**
         * Initialize the class.
         */
        initialize: function(options) {
        	this.options = _.extend({}, this.defaults, this.options);
        	this.insufficient_permission_message = this.options.insufficient_permission_message;
        	this.stream_not_installed_message = this.options.stream_not_installed_message;
        	this.capture_already_exists_message = this.options.capture_already_exists_message;

        	this.protocol_classes = null;

          return this;
        },

        /**
         * Determine if the Stream is installed.
         */
        isStreamInstalled: function(){

        	var uri = Splunk.util.make_url("/splunkd/__raw/servicesNS/nobody/system/apps/local/splunk_app_stream?output_mode=json");
        	var app_installed = false;

        	jQuery.ajax({
            	url:     uri,
                type:    'GET',
                async:   false,
                success: function(result) {
                	app_installed = true;
                }.bind(this)
            });

        	return app_installed;
        },

        /**
         * Determine if the user has sufficient permission.
         */
        doesUserHavePermission: function(){
        	return true;
        },

        /**
         * Show the given message.
         */
        renderMessage: function(type, message){

        	$(this.$el).html(
        			'<div style="margin: 32px;" class="alert alert-' + type + '">' +
                    '<i class="icon-alert"></i>' +
                    message +
                    '</div>'
        	);
        },

        /**
         * Render a message indicating that some action is taking place.
         */
        renderWorkingMessage: function(message){

        	$(this.$el).html(
        			'<div style="margin: 32px;" class="alert alert-info">' +
                    '<img style="position: absolute; left: 0;" alt="" src="data:image/gif;base64,R0lGODlhEAAQAPQAAP///wAAAPj4+Dg4OISEhAYGBiYmJtbW1qioqBYWFnZ2dmZmZuTk5JiYmMbGxkhISFZWVgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH+GkNyZWF0ZWQgd2l0aCBhamF4bG9hZC5pbmZvACH5BAAKAAAAIf8LTkVUU0NBUEUyLjADAQAAACwAAAAAEAAQAAAFUCAgjmRpnqUwFGwhKoRgqq2YFMaRGjWA8AbZiIBbjQQ8AmmFUJEQhQGJhaKOrCksgEla+KIkYvC6SJKQOISoNSYdeIk1ayA8ExTyeR3F749CACH5BAAKAAEALAAAAAAQABAAAAVoICCKR9KMaCoaxeCoqEAkRX3AwMHWxQIIjJSAZWgUEgzBwCBAEQpMwIDwY1FHgwJCtOW2UDWYIDyqNVVkUbYr6CK+o2eUMKgWrqKhj0FrEM8jQQALPFA3MAc8CQSAMA5ZBjgqDQmHIyEAIfkEAAoAAgAsAAAAABAAEAAABWAgII4j85Ao2hRIKgrEUBQJLaSHMe8zgQo6Q8sxS7RIhILhBkgumCTZsXkACBC+0cwF2GoLLoFXREDcDlkAojBICRaFLDCOQtQKjmsQSubtDFU/NXcDBHwkaw1cKQ8MiyEAIfkEAAoAAwAsAAAAABAAEAAABVIgII5kaZ6AIJQCMRTFQKiDQx4GrBfGa4uCnAEhQuRgPwCBtwK+kCNFgjh6QlFYgGO7baJ2CxIioSDpwqNggWCGDVVGphly3BkOpXDrKfNm/4AhACH5BAAKAAQALAAAAAAQABAAAAVgICCOZGmeqEAMRTEQwskYbV0Yx7kYSIzQhtgoBxCKBDQCIOcoLBimRiFhSABYU5gIgW01pLUBYkRItAYAqrlhYiwKjiWAcDMWY8QjsCf4DewiBzQ2N1AmKlgvgCiMjSQhACH5BAAKAAUALAAAAAAQABAAAAVfICCOZGmeqEgUxUAIpkA0AMKyxkEiSZEIsJqhYAg+boUFSTAkiBiNHks3sg1ILAfBiS10gyqCg0UaFBCkwy3RYKiIYMAC+RAxiQgYsJdAjw5DN2gILzEEZgVcKYuMJiEAOwAAAAAAAAAAAA==" />' +
        			message +
                    '</div>'
        	);
        },

        /**
         * Make a template snippet for holding an input.
         */
        makeInputTemplate: function(label, id, helpblock){

        	return '<div id="' + id + '-action-control-group" class="control-group">' +
                  '	<label class="control-label">' + label + '</label>' +
                  '		<div class="controls">' +
                  '			<div style="display: inline-block;" class="input input-dropdown" id="' + id + '" />' +
                  '			<span class="hide help-inline"></span>' +
                  '			<span class="help-block"> ' + helpblock + '</span>' +
                  '		</div>' +
                  '</div>';

        },

        /**
         * Make a description for the Stream.
         */
        makeDescription: function(){
        	return "Stream to/from " + this.getIP();
        },

        /**
         * Make modular alert param value.
         */
        makeModAlertParamValue: function(val){
            var v = _.isArray(val) ? val.join(",") : val;
            v = v.replace(/^"/, '\\"').replace(/([^\\])"/g, '$1\\"');
            return '"' + v + '"';
        },

        /**
         * Make the necessary streams.
         */
        makeStreams: function(fields, category, description, duration, streams){

            var promise = $.Deferred();
            var orig_sid = esutils.getURLParameter('orig_sid', ''),
                orig_rid = parseInt(esutils.getURLParameter('orig_rid', ''), 10) || 0,
                ip = this.getIP(),
                srch_orig = (orig_sid ? ', orig_sid="' + orig_sid + '", orig_rid=' + orig_rid : ''),
                srch = '| makeresults | eval ' + fields + '="' + ip + '"' + srch_orig;

            var params = {
                'action_name' : 'makestreams',
                'search' : srch,
                'action.makestreams.param.fields' : this.makeModAlertParamValue(fields),
                'action.makestreams.param.category' : this.makeModAlertParamValue(category),
                'action.makestreams.param.description' : this.makeModAlertParamValue(description),
                'action.makestreams.param.duration' : this.makeModAlertParamValue(duration),
                'action.makestreams.param.protocols' : this.makeModAlertParamValue(streams)
            };

            var uri = Splunk.util.make_url('/splunkd/__raw/services/alerts/modaction_adhoc');
            var stream_app_uri = Splunk.util.make_url('app/splunk_app_stream/streams#ephemeral/SplunkEnterpriseSecuritySuite');
            jQuery.ajax({
                url: uri,
                type: 'POST',
                data: params,
                success: (result) => {
                    promise.resolve('Stream successfully created<br /><p><a target="_blank" href=' + stream_app_uri + '>View streams</a></p>');
                },
                error: (jqXHR,textStatus,errorThrown) => {
                    promise.reject('Failed to create stream:');
                }
            });
            return promise;
        },

        /**
         * Validate the IP address.
         */
        validateIPAddress: function(ip){

        	var ip_re = /^([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})$/;

        	var match = ip_re.exec(ip);

        	// Doesn't match the regex
        	if( match === null ){
        		return false;
        	}

        	// Check each quad
        	var quad = null;

        	for( var c = 0; c < match.length; c++ ){
        		quad = parseInt(match[c], 10);

        		if( quad < 0 || quad > 255 ){
        			return false;
        		}
        	}

        	return true;
        },

        /**
         * Render a form for making a capture.
         */
        renderMakeCaptureForm: function(src_ip){

        	$(this.$el).html(
        			'<div style="margin: 32px;">' +
        			'<div style="padding-bottom: 16px"><strong>Initiate a capture using the Splunk App for Stream</strong></div>' +

        			//this.makeInputTemplate("Title", "title-input", "") +

        			this.makeInputTemplate("Description", "stream-description-input", "") +

        			this.makeInputTemplate("Protocols to capture", "protocols-dropdown", "") +

        			this.makeInputTemplate("Capture duration", "duration-dropdown", "") +

        			'<button class="btn active btn-primary" id="create_capture">Create capture</button>' +
        			'</div>'
        	);

            var protocols_dropdown = new MultiDropdownView({
                "id": "protocols_dropdown",
                "el": $('#protocols-dropdown', this.$el),
                "valueField": "protocols_id",
                "labelField": "protocol",
            	"choices": this.getProtocolClassesAsChoices()
            }, {tokens: true}).render();

            protocols_dropdown.on("change", function(newValue) {
            	this.validate();
            }.bind(this));

            // Make the durations drop-down
            var duration_dropdown = new DropdownInput({
                "id": "protocols_duration",
                "selectFirstChoice": false,
                "valueField": "capture_duration",
                "labelField": "capture",
                "showClearButton": false,
                "el": $('#duration-dropdown', this.$el),
            	"choices": [
                            {"label": "15 minutes", "value": "15m"},
                            {"label": "60 minutes", "value": "60m"},
                            {"label": "4 hours", "value": "4h"},
                            {"label": "8 hours", "value": "8h"},
                            {"label": "24 hours", "value": "24h"},
                            {"label": "7 days", "value": "7d"},
                            {"label": "30 days", "value": "30d"},
                            {"label": "180 days", "value": "180d"},
                            {"label": "1 year", "value": "1y"}
                     ]
            }, {tokens: true}).render();

            duration_dropdown.on("change", function(newValue) {
            	this.validate();
            }.bind(this));

        	// The name of the capture
            /*
        	var title_input = new TextInput({
                "id": "title_input",
                "searchWhenChanged": false,
                "el": $('#title-input', this.$el)
            }, {tokens: true}).render();

        	title_input.on("change", function(newValue) {
            	this.validate();
            }.bind(this));
            */

        	// The description of the capture
        	var description_input = new TextInput({
                "id": "description_input",
                "searchWhenChanged": false,
                "el": $('#stream-description-input', this.$el)
            }, {tokens: true}).render();

        	description_input.on("change", function(newValue) {
            	this.validate();
            }.bind(this));

        	// Set defaults
        	duration_dropdown.val("15m");
        	protocols_dropdown.val("All");
        	description_input.val(this.makeDescription());

        },

        /**
         * Validate the given field and update the UI to show that the validation failed if necessary.
         */
        validateField: function(field_selector, val, message, test_function){
            if( !test_function(val) ){
                $(".help-inline", field_selector).show().text(message);
                $(field_selector).addClass('error');
                return 1;
            }
            else{
                $(".help-inline", field_selector).hide();
                $(field_selector).removeClass('error');
                return 0;
            }
        },

        /**
         * Get the list of supported Streams.
         */
        fetchStreams: function(name){

        	var streams = [];

        	// Prepare the arguments
            var params = {output_mode: 'json', repository: 'true'};

            var uri = Splunk.util.make_url('/splunkd/__raw/services/splunk_app_stream/streams');

            // Fire off the request
            jQuery.ajax({
                url:     uri,
                type:    'GET',
                data:    params,
                success: function(result) {
                    if(result === undefined || result === null){
                    	console.error("Streams could not be obtained: " + result.message);
                    }
                    else{
                    	for( var c = 0; c < result.entry[0].content.length; c++){
                    		streams.push(result.entry[0].content[c].id);
                    	}
                    }
                }.bind(this),
                async: false
            });

            // Return the supported streams
            return streams;
        },

        /**
         * Determine if the provided duration is valid.
         */
        isValidDuration: function(val){

        	if( val === undefined || val === null ){
        		return false;
        	}

        	var intRegex = /^[0-9]+[hsmdy]?$/;

        	return intRegex.test(val);

        },

        /**
         * Validate the provided options.
         */
        validate: function(){

        	// Determine if we are making a new entry or editing a existing one
        	var is_new = this.search_name === null;

            // Record the number of failures
            var failures = 0;

            // Verify title
            /*
            failures += this.validateField( $('#title-input-action-control-group', this.$el), mvc.Components.get("title_input").val(), "Cannot be empty",
                    function(val){
            			if( val === undefined ){
            				return false;
            			}
            			else if( val.length !== 0 ){
            				return true;
            			}
            			else{
            				return false;
            			}
                    }.bind(this)
            );
            */

            // Verify description
            failures += this.validateField( $('#stream-description-input-action-control-group', this.$el), mvc.Components.get("description_input").val(), "Cannot be empty",
                    function(val){
		    			if( val === undefined ){
		    				return false;
		    			}
		    			else if( val.length !== 0 ){
		    				return true;
		    			}
		    			else{
		    				return false;
		    			}
                    }.bind(this)
            );

            // Verify packet capture protocols
            failures += this.validateField( $('#protocols-dropdown-action-control-group', this.$el), mvc.Components.get("protocols_dropdown").val(), "Define the protocols to capture",
                    function(val){
            			if( val && val.length <= 0 ){
            				return false;
            			}
            			else{
            				return true;
            			}
                    }.bind(this)
            );

            // Verify packet capture duration
            failures += this.validateField( $('#duration-dropdown-action-control-group', this.$el), mvc.Components.get("protocols_duration").val(), "Define the protocols to capture",
                    function(val){
            			if( !this.isValidDuration(val) ){
            				return false;
            			}
            			else{
            				return true;
            			}
                    }.bind(this)
            );

            // Return a boolean indicating the validation succeeded or not
            return failures === 0;

        },

        /**
         * Get the list of the protocol classes supported
         */
        getProtocolClasses: function(){

        	// Return the existing list if available
        	if( this.protocol_classes !== null ){
        		return this.protocol_classes;
        	}

        	// Fetch the supported streams
        	var streams = this.fetchStreams();

        	// Initialize the default classes
        	var protocol_classes = {
            		'All': ['udp', 'tcp', 'http', 'dns', 'smtp', 'imap', 'pop3', 'nfs', 'smb'],
            		'DNS': ['dns'],
            		'Email': ['smtp', 'imap', 'pop3'],
            		'HTTP': ['http'],
            		'SMB & NFS': ['nfs', 'smb']
            };

        	var filtered_protocol_classes = {};

        	// Prune unsupported classes
        	var protocol_class = null;
        	var new_protocol_class = null;

        	for( var key in protocol_classes){

        		new_protocol_class = [];

        		for(var x = 0; x < protocol_classes[key].length; x++){

        			// If the protocol is supported, include it
        			if( _.contains(streams, protocol_classes[key][x]) ){
        				new_protocol_class.push( protocol_classes[key][x] );
        			}
        		}

        		// If the new protocol class has at least one entry, include it
        		if( new_protocol_class.length > 0 ){
        			filtered_protocol_classes[key] = new_protocol_class;
        		}
        	}

        	// Return the classes
        	this.protocol_classes = filtered_protocol_classes;
        	return this.protocol_classes;

        },

        /**
         * Get the protocol classes as a list of choices for use in a dropdown input.
         */
        getProtocolClassesAsChoices: function(){
        	var protocol_classes = this.getProtocolClasses();
        	var choices = [];

        	for(var key in protocol_classes){
        		choices.push({
        			"label": key,
        			"value": key
        		});
        	}

        	return choices;
        },

        /**
         * Dereference protocol classes to the specific protocols in the class.
         */
        dereferenceProtocolClasses: function(selected_protocol_classes){

        	var protocol_classes = this.getProtocolClasses();

        	var protocols = [];
        	for (var c = 0; c < selected_protocol_classes.length; c++) {

        		if( protocol_classes[selected_protocol_classes[c]] ){
        			var protocols_included = protocol_classes[selected_protocol_classes[c]];

        			if( protocols_included.length > 0 ){
        				protocols.push.apply(protocols, protocols_included);
        			}
        		}
        	}

        	return protocols;
        },

        /**
         * Set the dialog such that it is showing saving progress.
         */
        showSaving: function(saving){

        	if(saving){
        		$("#create_capture", this.$el).text("Saving...");
            	$("#create_capture", this.$el).attr("disabled", "true");

        	}
        	else{
        		$("#create_capture", this.$el).text("Create Capture");
            	$("#create_capture", this.$el).removeAttr("disabled");
        	}

        },

        /**
         * Get the IP that we are to filter on.
         */
        getIP: function(){
        	var src_ip = esutils.getURLParameter('src_ip', '');
        	var dest_ip = esutils.getURLParameter('dest_ip', '');

        	// By default, use the src_ip
        	var ip = src_ip;

        	// Otherwise, use the dest_ip
        	if( src_ip === "" || src_ip === undefined || src_ip === null ){
        		ip = dest_ip;
        	}

        	return ip;
        },

        /**
         * Start the process of making the capture.
         */
        save: function(){

        	// Make sure that the options appear to be valid
        	if( !this.validate() ){
        		// Could not validate options
        		return;
        	}

        	this.showSaving(true);

        	$.when(this.makeStreams(
            esutils.getURLParameter('fields', ''),
            "security",
            mvc.Components.get("description_input").val(),
            mvc.Components.get("protocols_duration").val(),
            this.dereferenceProtocolClasses(mvc.Components.get("protocols_dropdown").val())
          )).done((result) => {
                this.renderMessage('info', result);
          }).fail((error) => {
                this.renderMessage('error', error);
          });
        },

        /**
         * Check to verify things such as permissions, availability of Stream, etc. Then render the form if everything checks out.
         */
        doChecksAndRender: function(){

        	// Make sure Stream is even installed.
        	if( !this.isStreamInstalled() ){
        		this.renderMessage('warning', this.stream_not_installed_message);
        		return this;
        	}

        	// Make sure an IP was provided.
        	var ip = this.getIP();
        	if( ip === "" || ip === undefined || ip === null ){
        		this.renderMessage('warning', "No IP was provided to make a filter on");
        		return this;
        	}

        	// Make sure the IP is valid
        	if( !this.validateIPAddress(ip) ){
        		this.renderMessage('warning', "Provided IP is invalid");
        		return this;
        	}

        	// Make sure the user has permission
        	if( !this.doesUserHavePermission() ){
        		this.renderMessage('warning', this.insufficient_permission_message);
        		return this;
        	}

          // Make sure fields is provided
          var fields = esutils.getURLParameter('fields', '');
          if (!fields) {
            this.renderMessage('error', 'Missing "fields" parameter.');
            return this;
          }

        	// Render the form
        	this.renderMakeCaptureForm(ip);
        },

        /**
         * Render the view.
         */
        render: function(){

        	this.renderWorkingMessage("Preparing...");

        	setTimeout(this.doChecksAndRender.bind(this), 300);

        }
    });
});
