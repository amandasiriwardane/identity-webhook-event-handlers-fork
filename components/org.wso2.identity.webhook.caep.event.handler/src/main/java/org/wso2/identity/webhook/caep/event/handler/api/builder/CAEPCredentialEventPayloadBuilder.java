package org.wso2.identity.webhook.caep.event.handler.api.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPCredentialChangeEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.util.CAEPPayloadUtils;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.Map;

/**
 * This class is responsible for building CAEP credential change event payloads.
 */
public class CAEPCredentialEventPayloadBuilder implements CredentialEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(CAEPCredentialEventPayloadBuilder.class);
    
    private static final String UPDATE_CHANGE_TYPE = "update";

    @Override
    public EventPayload buildCredentialUpdateEvent(EventData eventData) throws IdentityEventException {
        
        final Map<String, Object> params = eventData.getEventParams();
        long eventTimeStamp = CAEPPayloadUtils.resolveEventTimeStamp(params);
        
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatingEntity = CAEPPayloadUtils.resolveInitiatingEntity(flow);
        String credentialType = CAEPPayloadUtils.resolveCredentialType(flow);

        Map<String, String> reasonAdmin = new HashMap<>();
        Map<String, String> reasonUser = new HashMap<>();
        reasonAdmin.put("en", "Credential Updated");
        reasonUser.put("en", "Your credential was updated");

        return new CAEPCredentialChangeEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonAdmin(reasonAdmin)
                .reasonUser(reasonUser)
                .credentialType(credentialType)
                .changeType(UPDATE_CHANGE_TYPE)
                .friendlyName(null)
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.CAEP;
    }
}

