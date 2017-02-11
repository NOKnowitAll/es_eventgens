"use strict";

// Translations for en_US
i18n_register({ "plural": function plural(n) {
        return n == 1 ? 0 : 1;
    }, "catalog": {} });

require(['jquery', 'underscore', 'splunkjs/mvc', 'splunkjs/mvc/tokenutils', 'splunkjs/mvc/simplexml/ready!'], function ($, _, mvc, tokenutils) {

    // Get Submitted Tokens
    var submittedTokens = mvc.Components.get('submitted');

    // Override sourcetype token
    var sourcetypeToken = mvc.Components.get('sourcetype_id');

    function make_sourcetype_token(model, selectedSourcetypes) {
        // per SPL-106143 we sometimes get an empty string instead of an array
        if (selectedSourcetypes === '') selectedSourcetypes = [selectedSourcetypes];

        if (!selectedSourcetypes) return;
        var valuePrefix = sourcetypeToken.settings.get('valuePrefix') || '';
        var valueSuffix = sourcetypeToken.settings.get('valueSuffix') || '';
        var prefix = sourcetypeToken.settings.get('prefix') || '';
        var suffix = sourcetypeToken.settings.get('suffix') || '';
        var delimiter = sourcetypeToken.settings.get('delimiter') || '';

        selectedSourcetypes = _(selectedSourcetypes).filter(function (item) {
            return item && item !== '';
        });
        var newValue = _(selectedSourcetypes).map(function (item) {
            return valuePrefix + item + valueSuffix;
        });
        var sourcetype = prefix + newValue.join(delimiter) + suffix;
        console.log('SET', sourcetype);
        submittedTokens.set('sourcetype', sourcetype);
    }

    submittedTokens.on('change:form.sourcetype_form', make_sourcetype_token);
    make_sourcetype_token(submittedTokens, submittedTokens.get('form.sourcetype_form'));

    // Override level token
    var levelToken = mvc.Components.get('level_id');

    function make_level_token(model, selectedLevels) {
        // per SPL-106143 we sometimes get an empty string instead of an array
        if (selectedLevels === '') selectedLevels = [selectedLevels];

        if (!selectedLevels) return;
        var valuePrefix = levelToken.settings.get('valuePrefix') || '';
        var valueSuffix = levelToken.settings.get('valueSuffix') || '';
        var prefix = levelToken.settings.get('prefix') || '';
        var suffix = levelToken.settings.get('suffix') || '';
        var delimiter = levelToken.settings.get('delimiter') || '';

        selectedLevels = _(selectedLevels).filter(function (item) {
            return item && item !== '';
        });
        var newValue = _(selectedLevels).map(function (item) {
            return valuePrefix + item + valueSuffix;
        });
        var level = prefix + newValue.join(delimiter) + suffix;
        console.log('SET', level);
        submittedTokens.set('level', level);
    }

    submittedTokens.on('change:form.level_form', make_level_token);
    make_level_token(submittedTokens, submittedTokens.get('form.level_form'));
});
