package org.wso2.identity.webhook.caep.event.handler.internal.constant;

/**
 * Constants class for CAEP-specific channel and event-type URIs.
 */
public class CAEPConstants {

    public static class Channel {

        public static final String SESSION_ESTABLISHED_CHANNEL =
                "https://schemas.openid.net/secevent/caep/session-established";
        public static final String SESSION_PRESENTED_CHANNEL =
                "https://schemas.openid.net/secevent/caep/session-presented";
        public static final String SESSION_REVOKED_CHANNEL =
                "https://schemas.openid.net/secevent/caep/session-revoked";
        public static final String CREDENTIAL_CHANGE_CHANNEL = "https://schemas.openid.net/secevent/caep/credential";
    }

    public static class Event {

        public static final String SESSION_REVOKED_EVENT =
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
        public static final String SESSION_CREATED_EVENT =
                "https://schemas.openid.net/secevent/caep/event-type/session-established";
        public static final String SESSION_PRESENTED_EVENT =
                "https://schemas.openid.net/secevent/caep/event-type/session-presented";
        public static final String CREDENTIAL_CHANGE_EVENT =
                "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    }
}
