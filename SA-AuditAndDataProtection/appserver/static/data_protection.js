/*
 * Copyright (C) 2016 Splunk Inc. All Rights Reserved.
 */

require(
    [
        "jquery",
        "underscore",
        "splunk.util",
        "splunkjs/mvc",
        "splunkjs/mvc/simplexml/ready!"
    ],
    function (
        $,
        _,
        splunkUtil,
        mvc
    ) {
        const DISPLAY_TEMPLATE = _.template(`
            <div class="panel-body html">
                <h2><%- jsonData.header.title %></h2>
                <%- jsonData.header.desc %>
                <% jsonData.children.forEach(function (child) { %>
                <h3><%- child.title %></h3>
                <%= child.desc %>
                <% }) %>
            </div>
        `);

        const URI = {
            DOCS: {
                DATA_INTEGRITY: "http://docs.splunk.com/Documentation/Splunk/latest/Security/Dataintegritycontrol",
                ANONYMIZE_DATA: "http://docs.splunk.com/Documentation/Splunk/latest/Data/Anonymizedatausingconfigurationfiles"
            },
            WIKI: {
                LUHN: "http://www.wikipedia.org/wiki/Luhn_algorithm",
                CREDIT_CARD: "http://www.wikipedia.org/wiki/Payment_card_number"
            }
        };

        //
        // One of the proposals for a standardized JSON format. For static content pages, such as this one, the
        // displayed content can be roughly compartmentalized into similar sections - header, children, footer -
        // each with standard elements (e.g., title, desc, etc.), thus making it possible for a standardized
        // handler in the long run.
        //
        const JSONDATA_DATA_INTEGRITY_CONTROL = {
            header: {
                title: _("Data Integrity Control").t(),
                desc: _(
                    "Splunk Enterprise's Data Integrity Control feature provides a consistent way to verify the " +
                    "integrity and safety of data in indexes and buckets. This is especially valuable for auditing " +
                    "and legal purposes."
                ).t()
            },
            children: [
                {
                    title: _("Configuring Data Integrity Control").t(),
                    desc: _(
                        "Data Integrity Control is configured in <em>indexes.conf</em> by setting " +
                        "<code>enableDataIntegrityControl=true</code>. Data integrity control can be configured per " +
                        "index (hash all events for an index) or globally (for all indexes)."
                    ).t()
                },
                {
                    title: _("Verifying data integrity").t(),
                    desc: splunkUtil.sprintf(
                        _(
                            "The integrity of an index or bucket can be verified using the CLI by running the following " +
                            "commands. <code>./splunk check-integrity -index &lt;indexname&gt; [-verbose]</code> " +
                            "<code>./splunk check-integrity -bucketPath &lt;path_to_bucket&gt; [-verbose]</code><br />" +
                            "<br />See <a target='_blank' href='%(uri)s'>Splunk's docs</a> for details regarding using " +
                            "and configuring Data Integrity Control."
                        ).t(),
                        {
                            uri: URI.DOCS.DATA_INTEGRITY
                        }
                    )
                }
            ]
        };

        //
        // One of the proposals for a standardized JSON format. For static content pages, such as this one, the
        // displayed content can be roughly compartmentalized into similar sections - header, children, footer -
        // each with standard elements (e.g., title, desc, etc.), thus making it possible for a standardized
        // handler in the long run.
        //
        const JSONDATA_MASK_SENSITIVE_DATA = {
            header: {
                title: _("Anonymizing Sensitive Data").t(),
                desc: _(
                    "Log data may contain sensitive data such as passwords, PII (personally identifiable information), " +
                    "credit cards, etc. Event data can be anonymized such that the sensitive data is removed as it is " +
                    "indexed."
                ).t()
            },
            children: [
                {
                    title: _("Configuring Splunk to Anonymize Data").t(),
                    desc: splunkUtil.sprintf(
                        _(
                            "Data anonymization is configured in <em>props.conf</em> ($SPLUNK_HOME/etc/system/local/props.conf). " +
                            "Data is anonymized by specifying sed scripts that match and replace portions of the raw " +
                            "event. <a target='_blank' href='%(uri)s'>splunk>docs</a>."
                        ).t(),
                        {
                            uri: URI.DOCS.ANONYMIZE_DATA
                        }
                    )
                },
                {
                    title: _("Detecting Sensitive Data").t(),
                    desc: splunkUtil.sprintf(
                        _(
                            "Data Protection uses the <a target='_blank' href='%(uri_luhn)s'>Luhn algorithm</a> to " +
                            "detect a variety of identification numbers. If the identification number happens to be a " +
                            "bank card number the institution which issued the card will be detected via the first 6 " +
                            "digits of the <a target='_blank' href='%(uri_credit_card)s'>credit card number</a>."
                        ).t(),
                        {
                            uri_luhn: URI.WIKI.LUHN,
                            uri_credit_card: URI.WIKI.CREDIT_CARD
                        }
                    )
                }
            ]
        };

        $("#dataIntegrityID").html(
            DISPLAY_TEMPLATE({
                jsonData: JSONDATA_DATA_INTEGRITY_CONTROL
            })
        );

        $("#maskDataID").html(
            DISPLAY_TEMPLATE({
                jsonData: JSONDATA_MASK_SENSITIVE_DATA
            })
        );

        mvc.Components.get("submitted").set("label_token", _("Events with sensitive data: %d").t());
    }
);
