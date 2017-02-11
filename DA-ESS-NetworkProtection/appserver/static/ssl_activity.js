
// Translations for en_US
i18n_register({"plural": function(n) { return n == 1 ? 0 : 1; }, "catalog": {}});

require.config({
    paths: {
        ssl_certificate_cell_renderer: '../app/DA-ESS-NetworkProtection/js/views/SSLCertificateCellRenderer'
    }
});

require(['jquery','underscore','splunkjs/mvc', 'ssl_certificate_cell_renderer', 'splunkjs/mvc/simplexml/ready!'],
        function($, _, mvc, SSLCertificateCellRenderer){

    var recentSSLSessionsTable = mvc.Components.get('recent_ssl_sessions_table');

    recentSSLSessionsTable.getVisualization(function(tableView){
        tableView.addCellRenderer(new SSLCertificateCellRenderer());
        tableView.render();
    });

});