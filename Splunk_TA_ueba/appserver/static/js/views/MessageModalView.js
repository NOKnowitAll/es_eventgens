"use strict";

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

define(["jquery", "underscore", "views/shared/Modal"], function ($, _, Modal) {
    var MessageModal = function (_Modal) {
        _inherits(MessageModal, _Modal);

        function MessageModal() {
            _classCallCheck(this, MessageModal);

            return _possibleConstructorReturn(this, (MessageModal.__proto__ || Object.getPrototypeOf(MessageModal)).apply(this, arguments));
        }

        _createClass(MessageModal, [{
            key: "initialize",
            value: function initialize(options) {
                Modal.prototype.initialize.apply(this, arguments);
                this.options = _.extend({}, this.defaults, options);
            }
        }, {
            key: "render",
            value: function render() {
                Modal.prototype.render(this, arguments);
                this.$el.html(Modal.TEMPLATE);
                this.$(Modal.HEADER_TITLE_SELECTOR).html(this.options.messageTitle);
                this.$el.find(Modal.BODY_SELECTOR).html(_.template("\n              <div id=\"modal_alert_message\" class=\"alert alert-info\" style=\"margin-bottom: 0px;\">\n                <div class=\"icon-alert\"></div>\n                <span id=\"modal_message_text\"></span>\n              </div>"));
                if (this.options.messageType.toLowerCase() === "info") {
                    this.$el.find("#modal_alert_message").removeClass("alert-error");
                    this.$el.find("#modal_alert_message").addClass("alert-info");
                } else if (this.options.messageType.toLowerCase() === "error") {
                    this.$el.find("#modal_alert_message").removeClass("alert-error");
                    this.$el.find("#modal_alert_message").addClass("alert-info");
                }

                this.$el.find("#modal_message_title").html(this.options.messageTitle);
                this.$el.find("#modal_message_text").html(this.options.message);
                return this;
            }
        }]);

        return MessageModal;
    }(Modal);

    return MessageModal;
});
