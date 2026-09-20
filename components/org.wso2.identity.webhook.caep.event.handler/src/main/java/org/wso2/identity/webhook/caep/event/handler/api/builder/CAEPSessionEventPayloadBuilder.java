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

package org.wso2.identity.webhook.caep.event.handler.api.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionEstablishedEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionPresentedEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionRevokedEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.util.CAEPPayloadUtils;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is responsible for building CAEP session event payloads.
 */
public class CAEPSessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(CAEPSessionEventPayloadBuilder.class);

    static final String CREATED_TIMESTAMP = "CreatedTimestamp";
    static final String UPDATED_TIMESTAMP = "UpdatedTimestamp";

    @Override
    public EventPayload buildSessionRevokedEvent(EventData eventData) throws IdentityEventException {

        final Map<String, Object> params = eventData.getEventParams();
        long eventTimeStamp = CAEPPayloadUtils.resolveEventTimeStamp(params);
        String initiatingEntity = null;
        Map<String, String> reasonAdmin = new HashMap<>();
        Map<String, String> reasonUser = new HashMap<>();

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        initiatingEntity = CAEPPayloadUtils.resolveInitiatingEntity(flow);
        if (flow != null) {
            // TODO: Define Flows and change names accordingly
            switch (flow.getName()) {
                case LOGOUT:
                    reasonAdmin.put("en", "User Logout");
                    reasonUser.put("en", "User Logged Out");
                    break;
                case CREDENTIAL_RESET:
                case CREDENTIAL_UPDATE:
                    reasonAdmin.put("en", "Credential Updated");
                    reasonUser.put("en", "Credential Updated");
                    break;
                case PROFILE_UPDATE:
                    // Account lock/disable flows are commonly preceded by a PROFILE_UPDATE flow in practice.
                    reasonAdmin.put("en", "User Profile Locked or Disabled");
                    reasonUser.put("en", "User Profile Locked or Disabled");
                    break;
                case USER_ACCOUNT_DELETE:
                    reasonAdmin.put("en", "User Deleted");
                    reasonUser.put("en", "User Deleted");
                    break;
                case USER_ACCOUNT_DISABLE:
                    reasonAdmin.put("en", "Account Disabled");
                    reasonUser.put("en", "User Account was Disabled");
                    break;
                case USER_ACCOUNT_LOCK:
                    reasonAdmin.put("en", "Account Locked");
                    reasonUser.put("en", "User Account was Locked");
                    break;
                case SESSION_REVOKE:
                    if (flow.getInitiatingPersona() == Flow.InitiatingPersona.ADMIN) {
                        reasonAdmin.put("en", "Session Revoked by Admin");
                        reasonUser.put("en", "Session Revoked by Admin");
                    } else if (flow.getInitiatingPersona() == Flow.InitiatingPersona.USER) {
                        reasonAdmin.put("en", "Session Revoked by User");
                        reasonUser.put("en", "Session Revoked by User");
                    } else {
                        reasonAdmin.put("en", "Session Revoked");
                        reasonUser.put("en", "Session Revoked");
                    }
                    break;
                default:
                    // Fallback so reason_admin/reason_user are never empty - the CAEP Interoperability
                    // Profile requires reason_admin to be populated with a non-empty object whenever
                    // session-revoked is emitted.
                    reasonAdmin.put("en", "Session revoked due to " + flow.getName());
                    reasonUser.put("en", "Session revoked");
                    break;
            }
        } else {
            // No Flow context available. initiating_entity is genuinely unknown here and stays absent (it's
            // optional per spec); reason_admin/reason_user still need the same non-empty fallback.
            reasonAdmin.put("en", "Session revoked");
            reasonUser.put("en", "Session revoked");
        }

        return new CAEPSessionRevokedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser.isEmpty() ? null : reasonUser)
                .reasonAdmin(reasonAdmin.isEmpty() ? null : reasonAdmin)
                .build();
    }

    /**
     * Build the Session Create event.
     *
     * @param eventData Event data.
     * @return Event payload.
     */
    @Override
    public EventPayload buildSessionEstablishedEvent(EventData eventData) throws IdentityEventException {

        final Map<String, Object> params = eventData.getEventParams();
        SessionContext sessionContext = eventData.getSessionContext();
        Long eventTimeStamp = null;
        if (sessionContext != null && sessionContext.getProperty(CREATED_TIMESTAMP) != null) {
            eventTimeStamp = Long.parseLong(sessionContext.getProperty(CREATED_TIMESTAMP).toString());
        }
        if (eventTimeStamp == null) {
            eventTimeStamp = CAEPPayloadUtils.resolveEventTimeStamp(params);
        }
        String initiatingEntity = null;
        Map<String, String> reasonAdmin = new HashMap<>();
        Map<String, String> reasonUser = new HashMap<>();
        
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        initiatingEntity = CAEPPayloadUtils.resolveInitiatingEntity(flow);
        if (flow != null) {
            switch (flow.getName()) {
                case LOGIN:
                    reasonAdmin.put("en", "Initial Login");
                    reasonUser.put("en", "User Logged In");
                    break;
                default:
                    reasonAdmin.put("en", "Session Established");
                    reasonUser.put("en", "User Logged In");
                    break;
            }
        } else {
            reasonAdmin.put("en", "Session Established");
            reasonUser.put("en", "User Logged In");
        }

        List<String> amr = CAEPPayloadUtils.resolveAmr(eventData);
        String fpUa = CAEPPayloadUtils.resolveFpUa(eventData);
        String extId = CAEPPayloadUtils.resolveExtId(eventData);
        String acr = CAEPPayloadUtils.resolveAcr(eventData);

        return new CAEPSessionEstablishedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser)
                .reasonAdmin(reasonAdmin)
                .amr(amr)
                .fpUa(fpUa)
                .extId(extId)
                .acr(acr)
                .build();
    }

    /**
     * Build the Session Update event.
     *
     * @param eventData Event data.
     * @return Event payload.
     */
    @Override
    public EventPayload buildSessionPresentedEvent(EventData eventData) throws IdentityEventException {

        final Map<String, Object> params = eventData.getEventParams();
        SessionContext sessionContext = eventData.getSessionContext();
        Long eventTimeStamp = null;
        if (sessionContext != null && sessionContext.getProperty(UPDATED_TIMESTAMP) != null) {
            eventTimeStamp = Long.parseLong(sessionContext.getProperty(UPDATED_TIMESTAMP).toString());
        }

        if (eventTimeStamp == null) {
            eventTimeStamp = CAEPPayloadUtils.resolveEventTimeStamp(params);
        }

        String initiatingEntity = null;
        Map<String, String> reasonAdmin = new HashMap<>();
        Map<String, String> reasonUser = new HashMap<>();

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        initiatingEntity = CAEPPayloadUtils.resolveInitiatingEntity(flow);
        reasonAdmin.put("en", "Session Presented");
        reasonUser.put("en", "Session Presented");

        String fpUa = CAEPPayloadUtils.resolveFpUa(eventData);
        String extId = CAEPPayloadUtils.resolveExtId(eventData);

        return new CAEPSessionPresentedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser)
                .reasonAdmin(reasonAdmin)
                .fpUa(fpUa)
                .extId(extId)
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.CAEP;
    }
}
