"use strict";

//Translations for en_US
i18n_register({ "plural": function plural(n) {
        return n == 1 ? 0 : 1;
    }, "catalog": {} });

require.config({
    paths: {
        toggle_input_view: '../app/SA-Utils/js/views/ToggleInputView',
        mv_field_cell_renderer: '../app/SA-Utils/js/views/MVFieldExpansionCellRenderer',
        extra_field_row_renderer: '../app/SA-Utils/js/views/ExtraFieldExpansionRowRenderer',
        threat_artifact_spec: '../app/DA-ESS-ThreatIntelligence/threat_artifact_spec'
    }
});

require(["jquery", "underscore", "splunkjs/mvc", "sa-utils/js/util/Console", "toggle_input_view", "mv_field_cell_renderer", "extra_field_row_renderer", "threat_artifact_spec", "bootstrap.tab", "bootstrap.dropdown", "splunkjs/mvc/simplexml/ready!"], function ($, _, mvc, console, ToggleInputView, MVFieldExpansionCellRenderer, ExtraFieldExpansionRowRenderer, ThreatArtifactSpec) {

    // Make the toggle for selecting the filters
    var threatArtifactToggleInputView = new ToggleInputView({
        el: $('#threat_artifact'),
        selectionElements: ThreatArtifactSpec.getArtifactElements(),
        defaultValue: ThreatArtifactSpec.ARTIFACTS.THREAT_OVERVIEW.name
    });

    threatArtifactToggleInputView.render();

    //
    // Code below handles the HTTP selection handling
    //

    // Make the toggle for selecting the filters
    var httpToggleInputView = new ToggleInputView({
        el: $('#http'),
        choices: [{
            label: _("Referer").t(),
            value: "http_referer"
        }, {
            label: _("Cookie").t(),
            value: "http_cookie"
        }, {
            label: _("Header").t(),
            value: "http_header"
        }, {
            label: _("Data").t(),
            value: "http_data"
        }, {
            label: _("URL").t(),
            value: "http_url"
        }, {
            label: _("User Agent").t(),
            value: "http_user_agent"
        }],
        includeInput: true,
        tokenNamespace: "default",
        defaultTokenValue: '',
        textValue: "",
        defaultValue: _("Referer").t()
    });

    httpToggleInputView.render();

    //
    // Code below defines the tab handling logic
    //

    //
    // The normal, auto-magical Bootstrap tab processing doesn't work for us since it requires a particular layout
    // of HTML that we cannot use without converting the view entirely to simpleXML. So, we are going to handle it
    // ourselves.
    //
    var hideTabTargets = function hideTabTargets() {

        var tabs = $('a[data-elements]');

        // Go through each toggle tab
        for (var c = 0; c < tabs.length; c++) {

            // Hide the targets associated with the tab
            var targets = $(tabs[c]).data("elements").split(",");

            for (var d = 0; d < targets.length; d++) {
                $('#' + targets[d], this.$el).hide();
            }
        }
    };

    var selectTab = function selectTab(e) {

        // Get the IDs that we should enable for this tab
        var toToggle = $(e.target).data("elements").split(",");

        // Hide the tab content by default
        hideTabTargets();

        // Now show this tabs toggle elements
        for (var c = 0; c < toToggle.length; c++) {
            $('#' + toToggle[c], this.$el).show();
        }
    };

    var __selector = $('a[data-toggle="tab"]');

    // Wire up the function to show the appropriate tab
    __selector.on('shown', selectTab);

    // Show the first tab
    $('.toggle-tab').first().trigger('shown');

    // Make the tabs into tabs
    $('#tabs', this.$el).tab();

    //
    // Code below handles the tokens that trigger when searches are kicked off for a tab.
    //

    // Get the tab token for a given tab name
    var getTabTokenForTabName = function getTabTokenForTabName(tab_name) {
        return "tab_" + tab_name;
    };

    // Get all of the possible tab control tokens
    var getTabTokens = function getTabTokens() {
        var tabTokens = [],
            tabLinks = $('#tabs > li > a');

        for (var c = 0; c < tabLinks.length; c++) {
            tabTokens.push(getTabTokenForTabName($(tabLinks[c]).attr('href').substring(1)));
        }

        return tabTokens;
    };

    // Clear all but the active tab control tokens
    var clearTabControlTokens = function clearTabControlTokens() {
        console.info("Clearing tab control tokens");

        var tabTokens = getTabTokens(),
            activeTabToken = getActiveTabToken(),
            tokens = mvc.Components.getInstance("submitted");

        // Clear the tokens for all tabs except for the active one
        for (var c = 0; c < tabTokens.length; c++) {
            if (activeTabToken !== tabTokens[c]) {
                tokens.set(tabTokens[c], undefined);
            }
        }
    };

    // Get the name of the active tab
    var getActiveTab = function getActiveTab() {
        return $('#tabs > li.active > a').attr('href').substring(1);
    };

    // Get the tab control token for the active tab
    var getActiveTabToken = function getActiveTabToken() {
        return getTabTokenForTabName(getActiveTab());
    };

    // Set the token for the active tab
    var setActiveTabToken = function setActiveTabToken() {
        var activeTabToken = getActiveTabToken(),
            tokens = mvc.Components.getInstance("submitted");

        tokens.set(activeTabToken, '');
    };

    var setTokenForTab = function setTokenForTab(e) {

        var tabToken = getTabTokenForTabName($(e.target).attr('href').substring(1)),
            // Get the token for the tab
        tokens = mvc.Components.getInstance("submitted"); // Set the token

        tokens.set(tabToken, '');

        console.info("Set the token for the active tab (" + tabToken + ")");
    };

    __selector.on('shown', setTokenForTab);

    // Wire up the tab control tokenization
    var submit = mvc.Components.get("submit");

    submit.on("submit", function () {
        clearTabControlTokens();
    });

    // Set the token for the selected tab
    setActiveTabToken();

    /**
     * Processes the user input fields for each of the Threat Artifacts specified in the ThreatArtifactSpec.
     */
    var processInputs = function processInputs() {
        var artifacts = ThreatArtifactSpec.ARTIFACTS,
            selectedArtifact = threatArtifactToggleInputView.val(),
            submittedTokens = mvc.Components.get('submitted');

        for (var artifact in artifacts) {
            if (Object.prototype.hasOwnProperty.call(artifacts, artifact)) {
                if (artifacts[artifact].name == selectedArtifact) {
                    submittedTokens.set(artifacts[artifact].outputToken, artifacts[artifact].getFilter(submittedTokens));
                } else {
                    submittedTokens.set(artifacts[artifact].outputToken, "");
                }
            }
        }
    };

    // Process Inputs on page load so that the filter tokens used in search are initialized and the panels aren't
    // waiting for user input.
    processInputs();

    //
    // Add a change handler to the 'submitted' token namespace as well as the threatArtifactToggleInputView to
    // update filter tokens when changes are made to the tokens or a different threat artifact is selected.
    //
    var submittedTokens = mvc.Components.get('submitted');
    submittedTokens.on("change", processInputs);
    threatArtifactToggleInputView.on("change", processInputs);

    // Setup the cell renderer
    var mvTableRender = function mvTableRender(tableView) {
        tableView.addCellRenderer(new MVFieldExpansionCellRenderer());
        tableView.render();
    };

    var setupTableRenderer = function setupTableRenderer(table) {
        var component = mvc.Components.get(table.id);

        if (component && mvc.Components.get(table.id).el && mvc.Components.get(table.id).el.className.indexOf("dashboard-element table splunk-view") >= 0) {
            component.getVisualization(mvTableRender);
        }
    };

    _.each(mvc.Components.attributes, setupTableRenderer);

    // Setup the row renderer
    var makeRowRenderer = function makeRowRenderer(columns) {
        return function (tableView) {
            var renderer = new ExtraFieldExpansionRowRenderer({ fieldsToShowCount: columns });

            tableView.addRowExpansionRenderer(renderer);
            tableView.render();

            renderer.hideExtraColumns(tableView.table.cid);
        };
    };

    // Registry intelligence (endpoint)
    mvc.Components.get("element6").getVisualization(makeRowRenderer(2));

    // File intelligence (endpoint)
    mvc.Components.get("element5").getVisualization(makeRowRenderer(8));

    // Process intelligence (endpoint)
    mvc.Components.get("element7").getVisualization(makeRowRenderer(5));

    // Service intelligence (endpoint)
    mvc.Components.get("element8").getVisualization(makeRowRenderer(2));

    // IP intelligence (network)
    mvc.Components.get("element3").getVisualization(makeRowRenderer(5));

    // HTTP intelligence (network)
    mvc.Components.get("element2").getVisualization(makeRowRenderer(8));

    // Certificate intelligence (certificate)
    mvc.Components.get("element10").getVisualization(makeRowRenderer(4));

    // Email intelligence (email)
    mvc.Components.get("element11").getVisualization(makeRowRenderer(6));

    //
    // Updating labels inside the HTML tags
    //
    $("#label_threat_artifact_holder").html(_("Threat Artifact").t());
    $("#label_http_holder").html(_("HTTP").t());
    $("#id_tab_threat_overview").html(_("Threat Overview").t());
    $("#id_tab_network").html(_("Network").t());
    $("#id_tab_endpoint").html(_("Endpoint").t());
    $("#id_tab_certificate").html(_("Certificate").t());
    $("#id_tab_email").html(_("Email").t());
});
