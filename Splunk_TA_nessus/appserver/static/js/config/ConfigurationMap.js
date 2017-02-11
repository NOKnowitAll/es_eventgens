/*global define*/
define([], function (
) {
    return {
        "configuration": {
            "header": {
                title: "Configuration",
                description: "Configure your Security Center server, proxy and logging level.",
                enableButton: false,
                enableHr: false
            },
            "allTabs": [
                {
                    title: "Security Center Server",
                    order: 0,
                    active: true
                },
                {
                    title: "Proxy",
                    order: 1
                },
                {
                    title: "Logging",
                    order: 2
                }
            ]
        }
    };
});
