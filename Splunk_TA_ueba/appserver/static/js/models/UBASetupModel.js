'use strict';

define(['underscore', 'jquery', 'backbone'], function (_, $, Backbone) {
    return Backbone.Model.extend({
        urlRoot: Splunk.util.make_url('/splunkd/__raw/services/data/outputs/tcp/syslog/ubaroute'),

        parse: function parse(response, options) {
            this.set('server', response.entry[0].content.server);
            this.set('type', response.entry[0].content.type);
        },

        saveUBASetting: function saveUBASetting(ubaModel) {
            $.when(saveSettings(ubaModel.toJSON())).then(function (resp) {
                ubaModel.set('server', resp[0].content.server);
                ubaModel.set('type', resp[0].content.type);
                ubaModel.trigger('model:saved');
            }, function (failResp) {
                if (failResp.status === 400) {
                    ubaModel.trigger('model:validation_error', _('The server name should be in the format [hostname]:[port]').t());
                } else if (failResp.status === 403) {
                    ubaModel.trigger('model:no_perm', _('You do not have permission to perform this action.').t());
                } else {
                    ubaModel.trigger('model:general_error', _('A server error occurred while saving the settings. Please contact the system administrator for more information.').t());
                }
            });
        }
    });

    function saveSettings(attrs) {
        var promise = $.Deferred();

        //get the sourcetype settings from backend
        $.ajax({
            url: Splunk.util.make_url('/splunkd/__raw/services/data/outputs/tcp/syslog/ubaroute?output_mode=json'),
            type: 'POST',
            data: attrs,
            success: function success(result) {
                if (result !== undefined && result.isOk === false) {
                    promise.reject('Context could not be obtained: ' + result.message);
                } else {
                    promise.resolve(result.entry);
                }
            },
            error: function error(jqXHR, textStatus, errorThrown) {
                promise.reject(jqXHR);
            }
        });

        return promise;
    }
});
