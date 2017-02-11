'use strict';

define(['underscore', 'backbone', 'jquery', 'views/shared/controls/ControlGroup', 'MessageModalView', 'splunkjs/mvc/simplexml/ready!'], function (_, Backbone, $, ControlGroup, MessageModal) {
    var UBASetupView = Backbone.View.extend({
        className: 'UBASetup',

        events: {
            'click .setup-save': 'saveUBASetupConfig'
        },

        defaults: {},

        initialize: function initialize(options) {
            var _this = this;

            this.controls = {};
            this.options = options;

            this.model.on('model:validation_error', function (errorTxt) {
                _this.messageModal.hide();
                _this.controls.server.error(true, errorTxt);
                _this.controls.server.setHelpText(errorTxt);
            });

            this.model.on('model:no_perm', function (errorTxt) {
                _this.messageModal.hide();
                _this._displayMessage('error', _("User permission").t(), errorTxt);
            });

            this.model.on('model:general_error', function (errorTxt) {
                _this.messageModal.hide();
                _this._displayMessage('error', _("Error").t(), errorTxt);
            });
        },

        destroy_view: function destroy_view() {
            //remove save in progress backdrop
            if (this.messageModal) {
                this.messageModal.hide();
            }
            // COMPLETELY UNBIND THE VIEW
            this.undelegateEvents();
            this.$el.removeData().unbind();
        },

        render: function render() {

            this.$el.append(_.template('<div class=\'uba_setup_input\'>\n                            </div>'));
            var serverInputBox = new ControlGroup({
                label: _("Management Server").t(),
                required: false,
                help: _("Type the management server name in the format host:port.").t(),
                controlType: 'Text',
                controlOptions: {
                    model: this.model,
                    modelAttribute: 'server',
                    value: this.model.get('server')
                }
            });
            serverInputBox.render().appendTo(this.$el.find('.uba_setup_input'));
            this.controls.server = serverInputBox;

            var typeInputControl = new ControlGroup({
                controlType: 'SyntheticSelect',
                controlOptions: {
                    className: 'btn-group',
                    modelAttribute: 'type',
                    model: this.model,
                    items: [{
                        label: _("UDP").t(),
                        value: 'udp'
                    }, {
                        label: _("TCP").t(),
                        value: 'tcp'
                    }],
                    toggleClassName: 'btn',
                    menuWidth: 'narrow'
                },
                help: _("Select the protocol to use to send notable events.").t(),
                required: false,
                label: _("Type").t()
            });
            typeInputControl.selectedItem = this.model.get('type');
            typeInputControl.render().appendTo(this.$el.find('.uba_setup_input'));
            this.controls.typeInput = typeInputControl;

            var restartlink = Splunk.util.make_url('/manager/launcher/control');
            var tmpl = _.template('<div class="form-footer">\n                <div class="save-block">\n                  <button class="btn btn-primary submit setup-save"><%- _("Save").t() %></button>\n                </div>\n                <div class="restart-msg alert alert-warning">\n                  <p><i class="icon-alert"></i>&nbsp;<%= sprintf(_("Splunk needs to be restarted in order for the settings to take effect. Click <a href=\'%s\'>here</a> to restart.").t(), link) %></p>\n                </div>\n            </div>');

            this.$el.append(tmpl({
                link: restartlink
            }));

            if (this.options.restartMsg) {
                this.$el.find('.restart-msg').show();
            }
        },

        saveUBASetupConfig: function saveUBASetupConfig() {
            this._displayMessage('info', _("In Progress").t(), _("Your settings are being saved...").t());
            this.model.saveUBASetting(this.model);
        },

        _displayMessage: function _displayMessage(type, title, text) {
            this.messageModal = new MessageModal({
                messageType: type,
                messageTitle: title,
                message: text
            }).render();
            this.messageModal.show();
        }
    });
    return UBASetupView;
});
