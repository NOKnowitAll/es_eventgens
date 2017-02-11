'use strict';

require.config({
    paths: {
        'UBASetupView': '../app/Splunk_TA_ueba/js/views/UBASetupView',
        'UBASetupModel': '../app/Splunk_TA_ueba/js/models/UBASetupModel',
        'MessageModalView': '../app/Splunk_TA_ueba/js/views/MessageModalView'
    }
});
require(['underscore', 'jquery', 'backbone', 'UBASetupView', 'UBASetupModel', 'MessageModalView'], function (_, $, Backbone, UBASetupView, UBASetupModel, MessageModal) {

    var ubaSetupModel = new UBASetupModel();
    var ubaSetupView = null;

    $.when(hasCapability('edit_forwarders')).then(function (capabilityExists) {
        if (capabilityExists) {
            checkSHCEnabled();
        } else {
            $('#uba_setup_container').html(_("You do not have the capabilities to access this page").t());
        }
    }, function (failedResp) {
        new MessageModal({
            messageType: 'Error',
            messageTitle: _("Error").t(),
            message: failedResp
        }).render().show();
    });

    function checkSHCEnabled() {
        $.when(isSHCEnabled()).then(function (shcEnabled) {
            console.log(shcEnabled);
            if (shcEnabled) {
                $('#uba_setup_container').append(_("Use the deployer to deploy the outputs.conf file from TA-UEBA to other members of the search head cluster for the setup to take effect").t());
            } else {
                ubaSetupModel.fetch({
                    data: {
                        'output_mode': 'json'
                    }
                });

                ubaSetupView = new UBASetupView({
                    'el': $('#uba_setup_container'),
                    model: ubaSetupModel,
                    restartMsg: false
                });

                ubaSetupView.render();

                ubaSetupModel.on('model:saved', function () {

                    if (ubaSetupView != null) {
                        ubaSetupView.destroy_view();
                        $('#uba_setup_container').empty();
                    }

                    ubaSetupView = new UBASetupView({
                        'el': $('#uba_setup_container'),
                        model: ubaSetupModel,
                        restartMsg: true
                    });

                    ubaSetupView.render();
                });
            }
        }, function (failResp) {
            new MessageModal({
                messageType: 'Error',
                messageTitle: _("Error").t(),
                message: failResp
            }).render().show();
        });
    }

    function isSHCEnabled() {
        var promise = $.Deferred();

        //get the sourcetype settings from backend
        //noinspection Eslint
        $.ajax({
            url: Splunk.util.make_url('/splunkd/__raw/services/shcluster/config'),
            type: 'GET',
            data: {
                'output_mode': 'json'
            },
            success: function success(result) {
                if (result !== undefined && result.isOk === false) {
                    promise.reject('Context could not be obtained: ' + result.message);
                } else {
                    var res = true;
                    if (result.entry[0].content.mode === 'disabled') {
                        res = false;
                    }
                    promise.resolve(res);
                }
            },
            error: function error(jqXHR, textStatus, errorThrown) {
                promise.reject(jqXHR.responseJSON.messages[0]);
            }
        });

        return promise;
    }

    function hasCapability(capability) {
        var promise = $.Deferred();

        // Get all capabilities for the logged in user
        $.ajax({
            url: Splunk.util.make_url('/splunkd/__raw/services/authentication/current-context?output_mode=json'),
            type: 'GET',
            async: true,
            success: function success(result) {
                if (result !== undefined && result.isOk === false) {
                    promise.reject('Context could not be obtained: ' + result.message);
                } else if (result.entry.length != 1) {
                    promise.reject('Context could not be obtained - wrong number of results: ' + result.entry.length);
                } else {
                    var res = false;
                    if ($.inArray(capability, result.entry[0].content.capabilities) >= 0) {
                        res = true;
                    }
                    promise.resolve(res);
                }
            },
            error: function error(jqXHR, textStatus, errorThrown) {
                promise.reject(jqXHR);
            }
        });

        return promise;
    }
});
