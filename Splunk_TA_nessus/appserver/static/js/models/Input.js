/*global define*/
define([
    'underscore',
    'app/models/Base.Model',
    'app/config/ContextMap'
], function (
    _,
    BaseModel,
    ContextMap
) {
    return BaseModel.extend({
        url: [
            ContextMap.restRoot,
            ContextMap.input
        ].join('/'),

        initialize: function (attributes, options) {
            options = options || {};
            this.collection = options.collection;
            BaseModel.prototype.initialize.call(this, attributes, options);
            this.addValidation('server', this.nonEmptyString);
            this.addValidation('data', this.nonEmptyString);
            this.addValidation('start_time', this.validStartTime);
            this.addValidation('index', this.nonEmptyString);
            this.addValidation('interval', this.validInterval);
        },

        validStartTime: function (attr) {
            if (this.entry.content.get(attr)) {
                var starttime = this.entry.content.get(attr).trim();
                if (!starttime ||
                    !starttime.match(/^(19|20)\d\d-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])T([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:Z|[+-](?:2[0-3]|[01][0-9])(?::?[0-5][0-9])?)$/)) {
                    return _('Field "Start Time" is not in format: YYYY-MM-DDThh:mm:ssTZD').t();
                } else {
                    var now, now_utc, start_time, start_time_utc;
                    now = new Date();
                    now_utc = new Date(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(),  now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds());
                    start_time = new Date(starttime);
                    start_time_utc = new Date(start_time.getUTCFullYear(), start_time.getUTCMonth(), start_time.getUTCDate(),  start_time.getUTCHours(), start_time.getUTCMinutes(), start_time.getUTCSeconds());
                    if (start_time_utc > now_utc){
                        return _('Field "Start Time" is a future time').t();
                    }
                }
            }
        },

        validInterval: function (attr) {
            var interval = this.entry.content.get(attr);
            if (interval) {
                interval = Number(interval);
                if (isNaN(interval) || interval != parseInt(interval, 10)) {
                    return _('Field "Interval" is not valid').t();
                } else if (interval <= 0) {
                    return _('Field "Interval" should be positive number').t();
                }
            } else {
                return _('Field "Interval" is required').t();
            }
        }
    });
});
