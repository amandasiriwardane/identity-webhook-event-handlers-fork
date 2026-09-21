/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.caep.event.handler.internal.service.impl;

import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.identity.webhook.caep.event.handler.internal.constant.CAEPConstants;
import org.wso2.identity.webhook.common.event.handler.api.service.EventProfileManager;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;

import java.util.Objects;

public class CAEPEventProfileManager implements EventProfileManager {

    @Override
    public EventMetadata resolveEventMetadata(String event) {

        String eventUri = null;
        String channelUri = null;
        if (Objects.requireNonNull(event).equals(
                IdentityEventConstants.Event.SESSION_TERMINATE_V2)) {
            channelUri = CAEPConstants.Channel.SESSION_CHANNEL;
            eventUri = CAEPConstants.Event.SESSION_REVOKED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_CREATE.equals(event)) {
            channelUri = CAEPConstants.Channel.SESSION_CHANNEL;
            eventUri = CAEPConstants.Event.SESSION_CREATED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_EXTENSION.equals(event) ||
                IdentityEventConstants.Event.SESSION_UPDATE.equals(event)) {
            channelUri = CAEPConstants.Channel.SESSION_CHANNEL;
            eventUri = CAEPConstants.Event.SESSION_PRESENTED_EVENT;
        } else if (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(event) ||
                IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(event) ||
                IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_ME_API.equals(event)) {
            channelUri = CAEPConstants.Channel.CREDENTIAL_CHANGE_CHANNEL;
            eventUri = CAEPConstants.Event.CREDENTIAL_CHANGE_EVENT;
        }

        return EventMetadata.builder()
                .event(String.valueOf(eventUri))
                .channel(String.valueOf(channelUri))
                .eventProfile(Constants.EventSchema.CAEP.name())
                .build();
    
    }
}
