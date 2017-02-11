"use strict";define(["underscore","backbone","jquery","sa-threatintelligence/js/components/response/ModularAlert","views/shared/controls/ControlGroup","views/shared/controls/SyntheticSelectControl","views/shared/controls/SyntheticCheckboxControl","splunk.util","uri/route","sa-utils/js/util/Console"],function(a,b,c,d,e,f,g,h,i){return d.extend({defaults:{suffix:"report",toLabel:a("To").t(),includeSubjectDefaultPlaceholder:!1,includeControls:!0},events:{"click a.show-cc-bcc":function(a){var b=!0;this.showAdditionalEmailAddresses(b),a.preventDefault()}},initialize:function(){d.prototype.initialize.apply(this,arguments),this.options=a.extend({},this.defaults,this.options),this.model=new b.Model({}),this.children={}},render:function(){var b=[new g({modelAttribute:"action.email.include.view_link",model:this.model,label:a("Link to Alert").t()}),new g({modelAttribute:"action.email.include.results_link",model:this.model,label:a("Link to Results").t()}),new g({modelAttribute:"action.email.include.search",model:this.model,label:a("Search String").t()}),new g({additionalClassNames:"include-inline",modelAttribute:"action.email.inline",model:this.model,label:a("Inline").t()}),new f({additionalClassNames:"include-inline-format",modelAttribute:"action.email.format",menuWidth:"narrow",model:this.model,items:[{label:a("Table").t(),value:"table"},{label:a("Raw").t(),value:"raw"},{label:a("CSV").t(),value:"csv"}],labelPosition:"outside",popdownOptions:{attachDialogTo:".modal:visible",scrollContainer:".modal:visible .modal-body:visible"}}),new g({modelAttribute:"action.email.include.trigger",model:this.model,label:a("Trigger Condition").t()}),new g({modelAttribute:"action.email.sendcsv",model:this.model,label:a("Attach CSV").t()}),new g({modelAttribute:"action.email.include.trigger_time",model:this.model,label:a("Trigger Time").t()})];this.options.pdfAvailable&&b.push(new g({modelAttribute:"action.email.sendpdf",model:this.model,label:a("Attach PDF").t()})),this.children.toEmailAddresses=new e({className:"control-group",controlType:"Textarea",controlClass:"controls-block",controlOptions:{modelAttribute:"action.email.to",model:this.model},label:this.options.toLabel,help:h.sprintf(a("Comma separated list of email addresses. %s").t(),' <a href="#" class="show-cc-bcc">'+a("Show CC and BCC").t()+"</a>")}),this.children.ccEmailAddresses=new e({className:"control-group",controlType:"Textarea",controlClass:"controls-block",controlOptions:{modelAttribute:"action.email.cc",model:this.model,placeholder:a("optional").t()},label:a("CC").t()}),this.children.bccEmailAddresses=new e({className:"control-group",controlType:"Textarea",controlClass:"controls-block",controlOptions:{modelAttribute:"action.email.bcc",model:this.model,placeholder:a("optional").t()},label:a("BCC").t()}),this.children.emailPriority=new e({className:"control-group",controlType:"SyntheticSelect",controlClass:"controls-block",controlOptions:{modelAttribute:"action.email.priority",model:this.model,items:[{label:a("Lowest").t(),value:"5"},{label:a("Low").t(),value:"4"},{label:a("Normal").t(),value:"3"},{label:a("High").t(),value:"2"},{label:a("Highest").t(),value:"1"}],toggleClassName:"btn",popdownOptions:{attachDialogTo:".modal:visible",scrollContainer:".modal:visible .modal-body:visible"}},label:a("Priority").t()});var d=i.docHelp(Splunk.util.getConfigValue("MRSPARKLE_ROOT_PATH","/").slice(1),Splunk.util.getConfigValue("LOCALE","en-US"),"learnmore.alert.email.tokens"),j="action.email.subject";h.normalizeBoolean(this.model.get("action.email.useNSSubject"))&&(j+="."+this.options.suffix),this.children.emailSubject=new e({className:"control-group",controlType:"Text",controlClass:"controls-block",controlOptions:{modelAttribute:j,model:this.model,placeholder:this.options.includeSubjectDefaultPlaceholder?a("Default").t():""},label:a("Subject").t(),help:h.sprintf(a("The email subject, recipients and message can include tokens that insert text based on the results of the search. %s").t(),' <a href="'+d+'" target="_blank" title="'+a("Splunk help").t()+'">'+a("Learn More").t()+' <i class="icon-external"></i></a>')}),this.children.emailMessage=new e({className:"control-group",controlType:"Textarea",controlClass:"controls-block",controlOptions:{modelAttribute:"action.email.message."+this.options.suffix,model:this.model,placeholder:a("Default").t(),textareaClassName:"messagearea"},label:a("Message").t()}),this.options.includeControls&&b.length&&(this.children.emailInclude=new e({controlClass:"email-include",controls:b,label:a("Include").t()})),this.children.emailContentType=new e({className:"control-group",controlType:"SyntheticRadio",controlClass:"controls-halfblock",controlOptions:{modelAttribute:"action.email.content_type",model:this.model,items:[{label:a("HTML & Plain Text").t(),value:"html"},{label:a("Plain Text").t(),value:"plain"}]},label:a("Type").t()}),this.$el.append('<form class="form-horizontal form-complex"></form>');var k=c("form",this.$el);this.children.toEmailAddresses.render().appendTo(k),this.children.ccEmailAddresses.render().appendTo(k).$el.hide(),this.children.bccEmailAddresses.render().appendTo(k).$el.hide(),this.children.emailPriority.render().appendTo(k),this.children.emailSubject.render().appendTo(k),this.children.emailMessage.render().appendTo(k),this.children.emailInclude&&this.children.emailInclude.render().appendTo(k),this.children.emailContentType.render().appendTo(k),this.showAdditionalEmailAddresses()},showAdditionalEmailAddresses:function(a){a||this.model.get("action.email.cc")||this.model.get("action.email.bcc")?(this.children.ccEmailAddresses.$el.show(),this.children.bccEmailAddresses.$el.show(),this.children.toEmailAddresses.$("a.show-cc-bcc").css("display","none")):this.children.toEmailAddresses.$("a.show-cc-bcc").css("display","block")},getConfig:function(){var b={};return this.configured&&(b["action."+this.name]=this.enabled?1:0,this.enabled&&(b=a.extend(b,this.model.attributes))),b},setConfig:function(a,b){var c=a.split(".");if("action"!==c[0]||c[1]!==this.name)throw"invalid argument";if(this.configured=!0,2===c.length&&c[1]===this.name){var d=this.enabled;this.enabled=1==b,d!==this.enabled&&this._onEnableChange(this.name,this.enabled)}else this.model.set(a,b)}})});