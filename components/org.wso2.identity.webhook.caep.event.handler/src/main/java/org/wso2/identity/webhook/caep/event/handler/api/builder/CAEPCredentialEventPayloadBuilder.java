package org.wso2.identity.webhook.caep.event.handler.api.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPCredentialChangeEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.Map;

/**
 * This class is responsible for building CAEP credential change event payloads.
 */
public class CAEPCredentialEventPayloadBuilder implements CredentialEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(CAEPCredentialEventPayloadBuilder.class);

    @Override
    public EventPayload buildCredentialUpdateEvent(EventData eventData) throws IdentityEventException {

        // TODO: credential_type/change_type are placeholders - real values need the
        // Flow.CredentialType mapping and create/update/delete/revoke design decisions
        Map<String, String> reasonAdmin = new HashMap<>();
        reasonAdmin.put("en", "Credential Updated");
        Map<String, String> reasonUser = new HashMap<>();
        reasonUser.put("en", "Your credential was updated");

        return new CAEPCredentialChangeEventPayload.Builder()
                .eventTimeStamp(System.currentTimeMillis())
                .initiatingEntity("user")
                .reasonAdmin(reasonAdmin)
                .reasonUser(reasonUser)
                .credentialType("password")
                .changeType("update")
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.CAEP;
    }
}

