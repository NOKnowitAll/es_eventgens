"use strict";

// Translations for en_US
i18n_register({ "plural": function plural(n) {
        return n == 1 ? 0 : 1;
    }, "catalog": {} });

require.config({
    paths: {
        per_panel_filtering_cell_renderer: '../app/SA-Utils/js/views/PerPanelFilteringCellRenderer',
        per_panel_filter_view: '../app/SA-Utils/js/views/PerPanelFilterView',
        toggle_input_view: '../app/SA-Utils/js/views/ToggleInputView',
        autopause_util: '../app/SA-Utils/js/util/autopause'
    }
});

require(['jquery', 'underscore', 'splunkjs/mvc', 'per_panel_filtering_cell_renderer', 'per_panel_filter_view', 'toggle_input_view', 'autopause_util', 'splunkjs/mvc/simplexml/ready!'], function ($, _, mvc, PerPanelFilteringCellRenderer, PerPanelFilterView, ToggleInputView) {

    function make_threat_group_token(value) {
        // initialize additional tokens to empty strings
        var threat_group = '';

        // update tokens if value is positive
        if (value !== null && value !== '') {
            threat_group = '[| `filter_by_threat_group("Threat_Activity.threat_key","' + value + '")`]';
        }

        // set new tokens
        submittedTokens.set('threat_group', threat_group);
    }

    function make_threat_category_token(value) {
        // initialize additional tokens to empty strings
        var threat_category = '';

        // update tokens if value is positive
        if (value !== null && value !== '') {
            threat_category = '[| `filter_by_threat_category("Threat_Activity.threat_key","' + value + '")`]';
        }

        // set new tokens
        submittedTokens.set('threat_category', threat_category);
    }

    // Get Submitted Tokens
    var submittedTokens = mvc.Components.get('submitted');

    // Set threat_activity token
    if (!submittedTokens.has('threat_activity')) {
        submittedTokens.set('threat_activity', '');
    }

    /*------ change handlers ------*/

    // When the threat_group_form token changes...
    submittedTokens.on('change:threat_group_form', function () {
        // if threat_group_form exists
        if (submittedTokens.has('threat_group_form')) {
            make_threat_group_token(submittedTokens.get('threat_group_form'));
        }
    });

    // When the threat_category_form token changes...
    submittedTokens.on('change:threat_category_form', function () {
        // if threat_category_form exists
        if (submittedTokens.has('threat_category_form')) {
            make_threat_category_token(submittedTokens.get('threat_category_form'));
        }
    });

    /*------ initialization handlers ------*/
    if (submittedTokens.has('threat_group_form')) {
        make_threat_group_token(submittedTokens.get('threat_group_form'));
    }
    if (submittedTokens.has('threat_category_form')) {
        make_threat_category_token(submittedTokens.get('threat_category_form'));
    }

    /*------ per panel filtering ------*/

    // Add the checkbox to the table
    var table1Element = mvc.Components.get('table1');
    var element2_search = mvc.Components.get('element2').settings.get('managerid');
    var element3_search = mvc.Components.get('element3').settings.get('managerid');
    var element4_search = mvc.Components.get('element4').settings.get('managerid');
    var table1_search = mvc.Components.get('table1').settings.get('managerid');

    table1Element.getVisualization(function (tableView) {
        tableView.addCellRenderer(new PerPanelFilteringCellRenderer());
        tableView.render();
    });

    // Setup the per panel filter
    var perPanelFilterView = new PerPanelFilterView({
        namespace: 'DA-ESS-ThreatIntelligence',
        el: $('#ppf'),
        lookup_name: 'ppf_threat_activity',
        panel_id: '#table1',
        search_managers: [mvc.Components.get(element2_search), mvc.Components.get(element3_search), mvc.Components.get(element4_search), mvc.Components.get(table1_search)],
        fields: ['threat_match_field', 'threat_match_value'],
        lookup_edit_view: Splunk.util.make_url('/app/SplunkEnterpriseSecuritySuite/ess_lookups_edit?path=DA-ESS-ThreatIntelligence/ppf_threat_activity.csv')
    });

    perPanelFilterView.render();

    /*------ toggle input ------*/

    // Make the toggle for selecting the filters
    var srchToggleInputView = new ToggleInputView({
        el: $('#srch'),
        choices: [{ 'label': _("Destination").t(),
            'value': 'Threat_Activity.dest'
        }, { 'label': _("Sourcetype").t(),
            'value': 'Threat_Activity.orig_sourcetype'
        }, { 'label': _("Source").t(),
            'value': 'Threat_Activity.src'
        }, { 'label': _("Threat Collection").t(),
            'value': 'Threat_Activity.threat_collection'
        }, { 'label': _("Threat Collection Key").t(),
            'value': 'Threat_Activity.threat_collection_key'
        }, { 'label': _("Threat Key").t(),
            'value': 'Threat_Activity.threat_key'
        }, { 'label': _("Threat Match Field").t(),
            'value': 'Threat_Activity.threat_match_field'
        }, { 'label': _("Threat Match Value").t(),
            'value': 'Threat_Activity.threat_match_value'
        }],
        includeInput: true,
        tokenNamespace: 'default',
        defaultTokenValue: '',
        textValue: '',
        defaultValue: _("Threat Match Value").t(),
        token: "threat_activity",
        makeTokenForEachSelection: false
    });

    srchToggleInputView.render();

    //
    // Provide the label for srchToggleInputView
    //
    $("#srch_label").html(_("Search").t());
});
