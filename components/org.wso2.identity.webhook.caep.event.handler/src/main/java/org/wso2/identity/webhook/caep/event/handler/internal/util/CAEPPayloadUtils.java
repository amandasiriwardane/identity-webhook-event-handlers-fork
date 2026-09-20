/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.webhook.caep.event.handler.internal.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.core.context.model.Flow; 
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.identity.webhook.caep.event.handler.internal.constants.CAEPConstants;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List; 
import java.util.Objects;
import java.util.Map;

public class CAEPPayloadUtils {

    private static final String EVENT_TIMESTAMP = "eventTimestamp";

    private static final String USER_PERSONA = "user";
    private static final String ADMIN_PERSONA = "admin";
    private static final String SYSTEM_PERSONA = "system";
    private static final String POLICY_PERSONA = "policy";

    private static final String PASSWORD_CREDENTIAL_TYPE = "password";
    private static final String PASSKEY_CREDENTIAL_TYPE ="fido2-platform";

    private static final Log LOG = LogFactory.getLog(CAEPPayloadUtils.class);
    
    private static final Map<String, String> AUTHENTICATOR_NAME_TO_AMR = createAuthenticatorAmrMap();

    private static Map<String, String> createAuthenticatorAmrMap() {

        Map<String, String> map = new HashMap<>();
        // Authenticators with no RFC 8176 AMR fit (e.g. Magic
        // Link) are left unmapped.
        map.put("BasicAuthenticator", "pwd");
        map.put("totp", "otp");
        map.put("email-otp-authenticator", "otp");
        map.put("sms-otp-authenticator", "sms");
        map.put("FIDOAuthenticator", "hwk");
        return Collections.unmodifiableMap(map);
    }

    /**
     * Resolve the amr claim from the authentication step history, mapping each step's authenticator
     * name to its RFC 8176 AMR value. Steps with no known mapping are skipped.
     *
     * @param eventData Event data.
     * @return List of AMR values, or null if none could be resolved.
     */
    public static List<String> resolveAmr(EventData eventData) {

        if (eventData.getAuthenticationContext() == null) {
            return null;
        }
        List<AuthHistory> stepHistory = eventData.getAuthenticationContext().getAuthenticationStepHistory();
        if (stepHistory == null) {
            return null;
        }
        List<String> amr = new ArrayList<>();
        for (AuthHistory step : stepHistory) {
            String amrValue = AUTHENTICATOR_NAME_TO_AMR.get(step.getAuthenticatorName());
            if (amrValue == null) {
                LOG.debug("No AMR mapping found for authenticator: " + step.getAuthenticatorName());
            } else if (!amr.contains(amrValue)) {
                amr.add(amrValue);
            }
        }
        return amr.isEmpty() ? null : amr;
    }

    /**
     * Resolve the event timestamp from event params, falling back to the current time.
     *
     * @param params Event params.
     * @return Event timestamp in epoch millis.
     */
    public static long resolveEventTimeStamp(Map<String, Object> params) {

        return params != null && params.containsKey(EVENT_TIMESTAMP) ?
                Long.parseLong(params.get(EVENT_TIMESTAMP).toString()) :
                System.currentTimeMillis();
    }

    public static String resolveInitiatingEntity(Flow flow) {

        if (flow == null || flow.getInitiatingPersona() == null) {
            return null;
        }
        switch (flow.getInitiatingPersona()) {
            case USER:
                return USER_PERSONA;
            case ADMIN:
                return ADMIN_PERSONA;
            // Due to CAEP definitions, "SYSTEM" initiatingPersona corresponds to "policy" initiatingEntity value.
            case APPLICATION:
                return SYSTEM_PERSONA;
            case SYSTEM:
                return POLICY_PERSONA;
            default:
                return null;
        }
    }

    /**
     * Resolve the fp_ua claim from the request's User-Agent header.
     *
     * @param eventData Event data.
     * @return User-Agent header value, or null if unavailable.
     */
    public static String resolveFpUa(EventData eventData) {

        return eventData.getRequest() != null ? eventData.getRequest().getHeader("User-Agent") : null;
    }

    /**
     * Resolve the ext_id claim from the first authentication step carrying a federated IdP session index.
     *
     * @param eventData Event data.
     * @return IdP session index, or null if unavailable.
     */
    public static String resolveExtId(EventData eventData) {

        if (eventData.getAuthenticationContext() == null) {
            return null;
        }
        List<AuthHistory> stepHistory = eventData.getAuthenticationContext().getAuthenticationStepHistory();
        if (stepHistory == null) {
            return null;
        }
        for (AuthHistory step : stepHistory) {
            if (StringUtils.isNotBlank(step.getIdpSessionIndex())) {
                return step.getIdpSessionIndex();
            }
        }
        return null;
    }

    /**
     * Resolve the acr claim from the authentication context.
     *
     * @param eventData Event data.
     * @return Selected ACR value, or null if unavailable.
     */
    public static String resolveAcr(EventData eventData) {

        return eventData.getAuthenticationContext() != null ?
                eventData.getAuthenticationContext().getSelectedAcr() : null;
    }

    /**
     * Resolve the CAEP credential_type value from the current Flow's credential type.
     *
     * @param flow Current flow, may be null.
     * @return CAEP credential_type value.
     */
    public static String resolveCredentialType(Flow flow) {

        if (flow != null && flow.getCredentialType() == Flow.CredentialType.PASSKEY) {
            // TODO: CAEP distinguishes fido2-platform vs fido2-roaming; Flow.CredentialType.PASSKEY
            // doesn't carry that distinction today - confirm the right mapping.
            return PASSKEY_CREDENTIAL_TYPE;
        }
        return PASSWORD_CREDENTIAL_TYPE;
    }
    /**
     * Resolve the event metadata based on the event name.
     *
     * @param eventName Event name.
     * @return Event metadata containing event and channel information.
     */
    public static EventMetadata resolveEventHandlerKey(String eventName) {

        String event = null;
        String channel = null;
        if (Objects.requireNonNull(eventName).equals(
                IdentityEventConstants.Event.SESSION_TERMINATE_V2)) {
            channel = CAEPConstants.Channel.SESSION_CHANNEL;
            event = CAEPConstants.Event.SESSION_REVOKED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_CREATE.equals(eventName)) {
            channel = CAEPConstants.Channel.SESSION_CHANNEL;
            event = CAEPConstants.Event.SESSION_CREATED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_EXTENSION.equals(eventName) ||
                IdentityEventConstants.Event.SESSION_UPDATE.equals(eventName)) {
            channel = CAEPConstants.Channel.SESSION_CHANNEL;
            event = CAEPConstants.Event.SESSION_PRESENTED_EVENT;
        } else if (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_ME_API.equals(eventName)) {
            channel = CAEPConstants.Channel.CREDENTIAL_CHANGE_CHANNEL;
            event = CAEPConstants.Event.CREDENTIAL_CHANGE_EVENT;
        }

        return EventMetadata.builder()
                .event(String.valueOf(event))
                .channel(String.valueOf(channel))
                .eventProfile(Constants.EventSchema.CAEP.name())
                .build();
    }
}
