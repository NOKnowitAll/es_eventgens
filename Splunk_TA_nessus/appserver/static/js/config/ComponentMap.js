/*global define,window*/
define([
    'underscore',
    'app/views/Models/TextDisplayControl',
    'views/shared/controls/TextControl',
    'app/views/Models/SingleInputControl',
    'app/views/Models/SingleInputControlEx',
    'views/shared/controls/SyntheticCheckboxControl',
    'views/shared/controls/SyntheticRadioControl',
    'app/views/Models/MultiSelectInputControl',
    'app/models/Input',
    'app/models/Nessus',
    'app/models/Server',
    'app/collections/Inputs',
    'app/collections/Nessuses'
], function (
    _,
    TextDisplayControl,
    TextControl,
    SingleInputControl,
    SingleInputControlEx,
    SyntheticCheckboxControl,
    SyntheticRadioControl,
    MultiSelectInputControl,
    Input,
    Nessus,
    Server,
    Inputs,
    Nessuses
) {
    return {
        "input": {
            "title": "Input",
            "caption": {
                title: "Inputs",
                description: 'Create data inputs to collect data from Tenable.',
                enableButton: true,
                singleInput: false,
                buttonId: "addInputBtn",
                buttonValue: "Create New Input",
                enableHr: true
            },
            "header": [
                {
                    "field": "name",
                    "label": "Name",
                    "sort": true,
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "service",
                    "label": "Service",
                    "sort": true,
                    mapping: function (model) {
                        if (model.id.indexOf('ta_tenable_nessus_inputs') > -1) {
                            return "Nessus";
                        }
                        return "Security Center";
                    }
                },
                {
                    "field": "interval",
                    "label": "Interval",
                    "sort": true,
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "index",
                    "label": "Index",
                    "sort": true,
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "disabled",
                    "label": "Status",
                    "sort": true,
                    mapping: function (field) {
                        return field ? "Disabled" : "Enabled";
                    }
                }
            ],
            "moreInfo": [
                {
                    "field": "name",
                    "label": "Name",
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                // These fields are for Security Center
                {
                    "field": "server",
                    "label": "Server",
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "data",
                    "label": "Metrics",
                    mapping: function (field) {
                        if (field === 'sc_vulnerability') {
                            return 'Vulnerability';
                        } else {
                            return '';
                        }
                    }
                },
                {
                    "field": "start_time",
                    "label": "Start Time",
                    mapping: function (field) {
                        return field? field.replace(/</g, "&lt;").replace(/>/g, "&gt;") : "</br>";
                    }
                },
                // These fields are for Nessus
                {
                    "field": "metric",
                    "label": "Metrics",
                    mapping: function (field) {
                        if (field === 'nessus_plugin') {
                            return 'Nessus Plugins';
                        } else if (field === 'nessus_scan') {
                            return 'Nessus Host Scans';
                        }
                    }
                },
                {
                    "field": "url",
                    "label": "Nessus Server URL",
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "start_date",
                    "label": "Start Date",
                    mapping: function (field) {
                        return field? field.replace(/</g, "&lt;").replace(/>/g, "&gt;") : "</br>";
                    }
                },
                {
                    "field": "batch_size",
                    "label": "Batch Size",
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                // Common fields
                {
                    "field": "interval",
                    "label": "Interval",
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "index",
                    "label": "Index",
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "disabled",
                    "label": "Status",
                    mapping: function (field) {
                        return field ? "Disabled" : "Enabled";
                    }
                }
            ],
            "services": {
                "input": {
                    "title": "Security Center",
                    "model": Input,
                    "url": "",
                    "collection": Inputs,
                    "entity": [
                        {
                            "field": "name",
                            "label": "Name",
                            "type": TextControl,
                            "required": true,
                            "help": "Enter a unique name for each security center input."
                        },
                        {
                            "field": "server",
                            "label": "Server",
                            "type": SingleInputControl,
                            "required": true,
                            "options": {}
                        },
                        {
                            "field": "data",
                            "label": "Metrics",
                            "type": SingleInputControl,
                            "required": true,
                            "defaultValue": "sc_vulnerability",
                            "options": {
                                "disableSearch": true,
                                "autoCompleteFields": [{"label": "Vulnerability", "value": "sc_vulnerability"}]
                            }
                        },
                        {
                            "field": "start_time",
                            "label": "Start Time",
                            "type": TextControl,
                            "required": false,
                            "options": {
                                "placeholder": "YYYY-MM-DDThh:mm:ssTZD"
                            },
                            "help": "The add-on starts collecting data with a date later than this UTC time. The default time is 30 days ago."
                        },
                        {
                            "field": "interval",
                            "label": "Interval",
                            "type": TextControl,
                            "required": true,
                            "defaultValue": "60",
                            "help": "Time interval of input in seconds."
                        },
                        {
                            "field": "index",
                            "label": "Index",
                            "type": SingleInputControlEx,
                            "required": true,
                            "defaultValue": "default"
                        }
                    ],
                    "actions": [
                        "edit",
                        "delete",
                        "enable",
                        "clone"
                    ]
                },
                "nessus": {
                    "title": "Nessus",
                    "model": Nessus,
                    "url": "",
                    "collection": Nessuses,
                    "entity": [
                        {
                            "field": "name",
                            "label": "Name",
                            "type": TextControl,
                            "required": true,
                            "help": "Enter a unique name for each nessus input."
                        },
                        {
                            "field": "metric",
                            "label": "Nessus Metrics",
                            "type": SingleInputControl,
                            "required": true,
                            "defaultValue": "nessus_plugin",
                            "options": {
                                "disableSearch": true,
                                "autoCompleteFields": [
                                    {"label": "Nessus Plugins", "value": "nessus_plugin"},
                                    {"label": "Nessus Host Scans", "value": "nessus_scan"}
                                ]
                            },
                            "help": "Select Nessus Host Scans to collect vulnerabilities discovered on hosts. Select Nessus Plugins to collect plugin information from Tenable Knowledgebase."
                        },
                        {
                            "field": "url",
                            "label": "Nessus Server URL",
                            "type": TextControl,
                            "required": true,
                            "defaultValue": "https://",
                            "help": "For example, https://10.10.10.10:8834"
                        },
                        {
                            "field": "access_key",
                            "label": "Access Key",
                            "type": TextControl,
                            "required": true,
                            "encrypted": true,
                            "help": "Nessus Access Key generated in the Nessus server."
                        },
                        {
                            "field": "secret_key",
                            "label": "Secret Key",
                            "type": TextControl,
                            "required": true,
                            "encrypted": true,
                            "help": "Nessus Secret Key generated in the Nessus server."
                        },
                        {
                            "field": "start_date",
                            "label": "Start Date",
                            "type": TextControl,
                            "required": true,
                            "defaultValue": "1999/01/01",
                            "help": "The add-on starts collecting data with a date later than this UTC time. Default is '1999/01/01'. For Nessus Host Scans, this value refers to the host scaned date. For Nessus Plugins, this value refers to the last modification date."
                        },
                        {
                            "field": "batch_size",
                            "label": "Batch Size",
                            "type": TextControl,
                            "required": true,
                            "defaultValue": "100000",
                            "help": "The batch size of events collected during each interval. Default is 100000. 0 means unlimited. Must be 0, or greater than or equal to 1000."
                        },
                        {
                            "field": "interval",
                            "label": "Interval",
                            "type": TextControl,
                            "required": true,
                            "defaultValue": "43200",
                            "help": "For Nessus Host Scans, 43200 seconds(0.5 day) is recommended. For Nessus Plugins, 604800 seconds(7 days) is recommended."
                        },
                        {
                            "field": "index",
                            "label": "Index",
                            "type": SingleInputControlEx,
                            "required": true,
                            "defaultValue": "default"
                        }
                    ],
                    "actions": [
                        "edit",
                        "delete",
                        "enable",
                        "clone"
                    ]
                }
            },
            filterKey: ['name', 'service', 'server', 'data', 'metric', 'url', 'start_time', 'start_date', 'batch_size', 'index', 'interval', 'status']
        },

        "server": {
            "model": Server,
            "title": "Security Center Server",
            "header": [
                {
                    "field": "name",
                    "label": "Name",
                    "sort": true,
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "url",
                    "label": "URL",
                    "sort": true,
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                },
                {
                    "field": "username",
                    "label": "Username",
                    "sort": true,
                    mapping: function (field) {
                        return field.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    }
                }
            ],
            "entity": [
                {"field": "name", "label": "Name", "type": TextControl, "required": true, "help": "Enter a unique name for each security center server."},
                {"field": "url", "label": "URL", "type": TextControl, "required": true, "help": "For example, https://10.10.10.10:443"},
                {"field": "username", "label": "Username", "type": TextControl, "required": true},
                {"field": "password", "label": "Password", "type": TextControl, "required": true, "encrypted": true}
            ],
            "refLogic": function (model, refModel) {
                return model.entry.attributes.name === refModel.entry.content.attributes.server;
            },
            "actions": [
                "edit",
                "delete",
                "clone"
            ],
            "tag": "server"
        },

        "proxy": {
            "title": "Proxy",
            "entity": [
                {"field": "proxy_enabled", "label": "Enable", "type": SyntheticCheckboxControl},
                {
                    "field": "proxy_type",
                    "label": "Proxy Type",
                    "type": SingleInputControl,
                    "options": {
                        "disableSearch": true,
                        "autoCompleteFields": [
                            {"label": "http", "value": "http"},
                            {"label": "http_no_tunnel", "value": "http_no_tunnel"},
                            {"label": "socks4", "value": "socks4"},
                            {"label": "socks5", "value": "socks5"}
                        ]
                    },
                    "defaultValue": "http"
                },
                {"field": "proxy_rdns", "label": "DNS Resolution", "type": SyntheticCheckboxControl},
                {"field": "proxy_url", "label": "Host", "type": TextControl},
                {"field": "proxy_port", "label": "Port", "type": TextControl},
                {"field": "proxy_username", "label": "Username", "type": TextControl},
                {
                    "field": "proxy_password",
                    "label": "Password",
                    "type": TextControl,
                    "encrypted": true,
                    "associated": "username"
                }
            ]
        },
        "logging": {
            "entity": [
                {
                    "field": "loglevel",
                    "label": "Log Level",
                    "type": SingleInputControl,
                    "options": {
                        "disableSearch": true,
                        "autoCompleteFields": [
                            {"label": "INFO", "value": "INFO"},
                            {"label": "WARN", "value": "WARN"},
                            {"label": "ERROR", "value": "ERROR"}
                        ]
                    },
                    "defaultValue": "WARN"
                }
            ]
        }
    };
});
