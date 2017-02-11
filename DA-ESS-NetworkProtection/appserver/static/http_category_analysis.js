
// Translations for en_US
i18n_register({"plural": function(n) { return n == 1 ? 0 : 1; }, "catalog": {}});

require.config({
    paths: {
        per_panel_filtering_cell_renderer: '../app/SA-Utils/js/views/PerPanelFilteringCellRenderer',
        per_panel_filter_view: '../app/SA-Utils/js/views/PerPanelFilterView',
        autopause_util: '../app/SA-Utils/js/util/autopause'
    }
});

require(['jquery', 'underscore', 'splunkjs/mvc', 'per_panel_filtering_cell_renderer', 'per_panel_filter_view', 'autopause_util', 'splunkjs/mvc/simplexml/ready!'],
    function($, _, mvc, PerPanelFilteringCellRenderer, PerPanelFilterView){
    
    /*------ per panel filtering ------*/
    
    // Add the checkbox to the table
    var table1Element = mvc.Components.get('table1');
    
    var chart1_search = mvc.Components.get('chart1').settings.get('managerid');
    var table1_search = mvc.Components.get('table1').settings.get('managerid');

    table1Element.getVisualization(function(tableView){
        tableView.addCellRenderer(new PerPanelFilteringCellRenderer());
        tableView.render();
    });
    
    // Setup the per panel filter
    var perPanelFilterView = new PerPanelFilterView( {
        namespace: "DA-ESS-NetworkProtection",
        el: $('#ppf'),
        lookup_name: "ppf_http_category",
        panel_id: "#table1",
        search_managers: [ mvc.Components.get(chart1_search), mvc.Components.get(table1_search)],
        fields: ['category'],
        lookup_edit_view: Splunk.util.make_url("/app/SplunkEnterpriseSecuritySuite/ess_lookups_edit?path=DA-ESS-NetworkProtection/ppf_http_category.csv")
    } );
    
    perPanelFilterView.render();

});