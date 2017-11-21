/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters;

import org.jboss.logging.Logger;
import org.keycloak.AuthorizationContext;
import org.keycloak.adapters.authorization.UnauthenticatedPolicyEnforcer;


/**
 * Pre-installed actions that can be done anonymously
 *
 * Actions include:
 *
 * CORS Origin Check and Response headers
 * Enforce resources to check scopes
 *
 * @author ebondu
 * @version $Revision: 1 $
 */
public class UnauthenticatedActionsHandler extends AuthenticatedActionsHandler {
    private static final Logger log = Logger.getLogger(UnauthenticatedActionsHandler.class);
    private UnauthenticatedPolicyEnforcer policyEnforcer;

    public UnauthenticatedActionsHandler(KeycloakDeployment deployment, OIDCHttpFacade facade, UnauthenticatedPolicyEnforcer policyEnforcer) {
        super(deployment, facade);
        this.policyEnforcer = policyEnforcer;
    }

    @Override
    public boolean handledRequest() {
        log.debugv("AnonymousActionsValve.invoke {0}", this.facade.getRequest().getURI());
        if (corsRequest()) {
            return true;
        }
        if (!isAuthorized()) {
            return true;
        }
        return false;
    }


    private boolean isAuthorized() {
        if (policyEnforcer == null) {
            log.debugv("Policy enforcement is disabled.");
            return true;
        }

        OIDCHttpFacade facade = (OIDCHttpFacade) this.facade;
        AuthorizationContext authorizationContext = policyEnforcer.authorize(facade);
        return authorizationContext.isGranted();
    }
}
