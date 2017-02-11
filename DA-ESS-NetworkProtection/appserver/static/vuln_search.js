
// Translations for en_US
i18n_register({"plural": function(n) { return n == 1 ? 0 : 1; }, "catalog": {}});

require.config({
    paths: {
        autopause_util: '../app/SA-Utils/js/util/autopause'
    }
});

require(['jquery', 'underscore', 'splunkjs/mvc', 'autopause_util', 'splunkjs/mvc/simplexml/ready!'],
        function($, _, mvc){

  function make_reference_token(value) {            
        // initialize additional tokens to empty strings
        var reference = '';
            
        // update tokens if value is positive
        if (value !== null && value !== '') {
            reference = '(Vulnerabilities.bugtraq="' + value + '" OR Vulnerabilities.cert="' + value + '" OR Vulnerabilities.cve="' + value + '" OR Vulnerabilities.msft="' + value + '" OR Vulnerabilities.mskb="' + value + '" OR Vulnerabilities.xref="' + value + '")';
        }

        // set new tokens
        submittedTokens.set('reference',reference);
    }

    // Get Submitted Tokens
    var submittedTokens = mvc.Components.get('submitted');
    
    /*------ change handlers ------*/

    // When the reference_form token changes...
    submittedTokens.on('change:reference_form', function(){
        // if reference_form exists
        if(submittedTokens.has('reference_form')) { make_reference_token(submittedTokens.get('reference_form')); }
    });

    /*------ initialization handlers ------*/
    if(submittedTokens.has('reference_form')) { make_reference_token(submittedTokens.get('reference_form')); }    

    
    /*------ datamodel search optimization ------*/
    // If search1 (| tstats) is finished and has returned 0 results, finalize search2 (| datamodel)
    // This will help cases where no results are found be faster
    var table1_search = mvc.Components.get('table1').settings.get('managerid');
    var event1_search = mvc.Components.get('event1').settings.get('managerid');
    
    var tstatsSearch = mvc.Components.get(table1_search);
    var datamodelSearch = mvc.Components.get(event1_search);
    
    setTimeout(function() {
        tstatsSearch.on('search:done', function() {
            var tstatsProps = tstatsSearch.get('data');
            var datamodelProps = datamodelSearch.get('data');
    
            if (tstatsProps.isDone && tstatsProps.resultCount===0 && datamodelProps.eventCount===0) {
                console.log('tstats search complete and returned 0 results, finalizing data model search');
                datamodelSearch.finalize();
            }
        }, this);
    
        // Note that the above event may never be hit, because the search
        // may already be done.
        tstatsSearch.replayLastSearchEvent(this);
    }, 3000);
    
});