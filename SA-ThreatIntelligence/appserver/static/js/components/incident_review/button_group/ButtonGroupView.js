"use strict";define(["underscore","jquery","backbone","module","splunkjs/mvc/basemultichoiceview","sa-threatintelligence/js/components/incident_review/button_group/SyntheticButtonControl","css!sa-threatintelligence/js/components/incident_review/button_group/css/SyntheticButtonControl"],function(a,b,c,d,e,f){var g=e.extend({moduleId:d.id,className:"splunk-buttongroup splunk-choice-input",options:{valueField:"",labelField:"","default":void 0,choices:[],value:void 0,disabled:!1},initialize:function(){this.options=a.extend({},e.prototype.options,this.options),e.prototype.initialize.apply(this,arguments),this._selections=new c.Model,this.listenTo(this._selections,"change",this._updateValue,this),this.updateDomVal()},_updateValue:function(b,c,d){var e=this.val().slice(0);a(b.changed).each(function(b,c){b?e.indexOf(c)<0&&e.push(c):e=a(e).without(c)}),this.val(e)},_disable:function(b){a.each(this._buttons,function(a){b?a.disable():a.enable()})},_domVal:function(){var c=[];return a.each(b(".button",this.el),function(a){var d=b("i",a).attr("style")||"",e=d.indexOf("display:none")!==-1||d.indexOf("display: none")!==-1,f=b("a",a).data("name");e||c.push(f)}),c},updateDomVal:function(){var b=this._selections.toJSON(),c={};a(b).each(function(a,b){c[b]=0}),a.each(this.val(),function(a){c[a]=1},this),this._selections.set(c)},createView:function(){return this.$el.empty(),b("<div class='splunk-buttongroup-choices btn-group-vertical' data-toggle='buttons'/>").appendTo(this.el)},updateView:function(c,d){c.empty(),this._buttons&&a.each(this._buttons,function(a){a.remove()}),this._buttons=[],(!d||d.length<=1)&&(d=[{value:"critical",label:"critical:0"},{value:"high",label:"high:0"},{value:"medium",label:"medium:0"},{value:"low",label:"low:0"},{value:"informational",label:"informational:0"}]);var e=this.$(".splunk-buttongroup-choices");return tokenSelections=this.settings.get("value"),a.each(d,function(a){var c=!1;labelRegex=/(\w+):(\w+)/i;var d=labelRegex.exec(b.trim(a.label)),g="",h="";d?(g=d[1],h=d[2]):g=b.trim(a.label),tokenSelections&&tokenSelections.indexOf(a.value)>=0&&(c=!0);var i=new f({model:this._selections,modelAttribute:a.value,label:g||a.value,count:h,isSelected:c});i.render().appendTo(e),this._buttons.unshift(i)},this),this}});return g});