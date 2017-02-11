/*global define*/
define([
    'app/collections/ProxyBase.Collection',
    'app/models/Server',
    'app/config/ContextMap'
], function (
    BaseCollection,
    Server,
    ContextMap
) {
    return BaseCollection.extend({
        url: [
            ContextMap.restRoot,
            ContextMap.server
        ].join('/'),
        model: Server,
        initialize: function (attributes, options) {
            BaseCollection.prototype.initialize.call(this, attributes, options);
        }
    });
});
