
// Translations for en_US
i18n_register({"plural": function(n) { return n == 1 ? 0 : 1; }, "catalog": {}});

require.config({
    paths: {
        autopause_util: '../app/SA-Utils/js/util/autopause'
    }
});

require(['jquery', 'underscore', 'splunkjs/mvc', 'autopause_util', 'splunkjs/mvc/simplexml/ready!'],
        function($, _, mvc){

    function make_transport_token(value) {            
        // initialize additional tokens to empty strings
        var transport = '';
            
        // update tokens if value is positive
        if (value !== null && value !== '') {
            transport = 'All_Traffic.transport="' + value + '"';
        }

        // set new tokens
        submittedTokens.set('transport',transport);
    }
    
    // Get Submitted Tokens
    var submittedTokens = mvc.Components.get('submitted');
    
       // When the transport_form token changes...
    submittedTokens.on('change:transport_form', function(){
        // if transport_form exists
        if(submittedTokens.has('transport_form')) { make_transport_token(submittedTokens.get('transport_form')); }
    });
    
    /*------ initialization handlers ------*/
    if(submittedTokens.has('transport_form')) { make_transport_token(submittedTokens.get('transport_form')); }	
    
});