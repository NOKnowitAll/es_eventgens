define([
    'jquery',
    'underscore',
    'backbone',
    'views/shared/results_table/renderers/BaseCellRenderer'
], function(
    $,
    _,
    Backbone,
    BaseCellRenderer
) {
    return BaseCellRenderer.extend({
    	
    	canRender: function(cell) {
    		// Only render if it is for the given fields
    		return  $.inArray(cell.field, ["ssl_is_valid", "ssl_validity_window", "ssl_end_time"]) >= 0;
    	},
		
    	round: function(n, sig){
    	    var mult = Math.pow(10, sig - Math.floor(Math.log(n) / Math.LN10) - 1);
    	    return Math.round(n * mult) / mult;
    	},
    	
    	makeEpochReadable: function(epoch){
    		
    		var date = new Date(parseInt(epoch * 1000, 10));
    		
    		if(isNaN(date.getMonth())){
    			return epoch;
    		}
    		
    		return  (date.getMonth() + 1) + "/" +
    		    	date.getDate() + "/" +
    		    	date.getFullYear() + " " +
    		    	date.getHours() + ":" +
    		    	date.getMinutes() + ":" +
    		    	date.getSeconds();
    	},
    	
    	makePeriodReadable: function(seconds){
    		var periods = [
    		               {
    		            	   seconds: 60 * 60 * 24 * 365.25,
    		            	   description: 'years',
    		            	   sigfigs: 2
    		               },
    		               {
    		            	   seconds: 60 * 60 * 24,
    		            	   description: 'days',
    		            	   sigfigs: 2
    		               },
    		               {
    		            	   seconds: 60 * 60,
    		            	   description: 'hours',
    		            	   sigfigs: 2
    		               },
    		               {
    		            	   seconds: 60,
    		            	   description: 'minutes',
    		            	   sigfigs: 1
    		               },
    		               {
    		            	   seconds: 1,
    		            	   description: 'seconds',
    		            	   sigfigs: 1
    		               }
    		               
    		               ];
    		
    		for( var c = 0; c < periods.length; c++){
    			if( seconds >= periods[c].seconds ){
    				return this.round(seconds / periods[c].seconds, periods[c].sigfigs) + " " + periods[c].description;
    			}
    		}
    		
    	},
    	
    	parseInteger: function(i){
    		var patt = new RegExp("^[0-9]+([.][0-9]+)?$");
    		
    		if( patt.test(i) ){
    			 return parseInt(i, 10);
    		}
    		else{
    			return NaN;
    		}
    	},
    	
    	render: function($td, cell) {
    		
    		var cell_value = null;
    		
    		if($.inArray(cell.field, ["ssl_validity_window"]) >= 0){
    			cell_value = this.parseInteger(cell.value, 10);
    		}
    		
    		var current_time_epoch = Math.floor( (new Date).getTime() / 1000 );
    		
    		/*
    		 * Rendering of the "ssl_is_valid" field
    		 */
    		// Render a warning for invalid certificates
    		if(cell.field === "ssl_is_valid" && (cell.value === "1" || cell.value === "true" || cell.value === true)){
				 $td.html('<span style="color: #619628"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-check-circle"></i>Valid</span>');
    		}
    		
    		// Render an information message for valid certificates
    		else if(cell.field === "ssl_is_valid" && (cell.value === "0" || cell.value === "false" || cell.value === false)){
    			$td.html('<span style="color: #C42323"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-alert-circle"></i>Invalid</span>');
    		}
    		
    		// Render unknown status certificates
    		else if(cell.field === "ssl_is_valid"){
    			$td.html('<span style="color: #8A8A8A"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-question-circle"></i>Unknown</span>');
    		}
    		
    		/*
    		 * Rendering of the "ssl_validity_window" field
    		 */
    		// Render a warning for certificates with a short duration (<= 1 month)
    		else if(cell.field === "ssl_validity_window" && cell_value <= (86400 * 30)){
    			$td.html('<span style="color: #cb0625"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-alert-circle"></i>' + this.makePeriodReadable(cell.value) + ' (< 30 days)</span>');
    		}
    		
    		// Render a warning for certificates with a short duration (<= 3 months)
    		else if(cell.field === "ssl_validity_window" && cell_value <= (86400 * 90)){
    			$td.html('<span style="color: #F88509"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-alert-circle"></i>' + this.makePeriodReadable(cell.value) + ' (< 90 days)</span>');
    		}
    		
    		// Render the duration
    		else if(cell.field === "ssl_validity_window" && !isNaN(cell_value) && cell_value !== null){
    			$td.html('<span><i style="font-size: 14pt; margin-right: 4px" class="icon icon-info-circle"></i>' + this.makePeriodReadable(cell.value) + '</span>');
    		}
    		
    		// Render the duration when it is unknown
    		else if(cell.field === "ssl_validity_window"){
    			$td.html('<span style="color: #8A8A8A"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-question-circle"></i>Unknown</span>');
    		}
    		
    		/*
    		 * Rendering of the "ssl_end_time" field
    		 */
    		// Render the certificate expiration date when it is unknown
    		else if(cell.field === "ssl_end_time" && (cell.value === null || cell.value === "") ) {
    			$td.html('<span style="color: #8A8A8A"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-question-circle"></i>Unknown</span>');
    		}
    		
    		// Render a warning for certificates that have expired
    		else if(cell.field === "ssl_end_time" && cell.value.indexOf("expired") > -1) {
    			$td.html('<span style="color: #cb0625"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-alert-circle"></i>' + cell.value + '</span>');
    		}
    			
    		// Render a warning for certificates that are about to expire (within 30 days)
    		else if(cell.field === "ssl_end_time" && cell.value.indexOf("expires soon") > -1) {
    			$td.html('<span style="color: #F88509"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-alert-circle"></i>' + cell.value + '</span>');
    		}
    		
    		// Render the certificate expiration date when it is still valid
    		else if(cell.field === "ssl_end_time"){
    			$td.html('<span style="color: #619628"><i style="font-size: 14pt; margin-right: 4px" class="icon icon-check-circle"></i>' + cell.value + '</span>');
    		}

    		
    		// Otherwise, pass through the value
    		else{
				 $td.html(cell.value);
			}

    	}
    });
});
