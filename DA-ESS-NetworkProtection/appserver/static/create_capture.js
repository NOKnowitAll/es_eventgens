
// Translations for en_US
i18n_register({"plural": function(n) { return n == 1 ? 0 : 1; }, "catalog": {}});

require.config({
    paths: {
        create_capture_view: '../app/DA-ESS-NetworkProtection/js/views/CreateCaptureView'
    }
});

require(['jquery','underscore','splunkjs/mvc', 'create_capture_view', 'splunkjs/mvc/simplexml/ready!'],
    function($, _, mvc, CreateCaptureView){
    
	    // Setup the create capture view
	    var createCaptureView = new CreateCaptureView( {
	    	namespace: "DA-ESS-NetworkProtection",
	    	el: $('#stream_capture_view')
	    } );
	    
	    // Render it
	    createCaptureView.render();

});