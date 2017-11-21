package org.keycloak.adapters.springsecurity.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.UnauthenticatedActionsHandler;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.authorization.UnauthenticatedPolicyEnforcer;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.filter.GenericFilterBean;

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

/**
 * Exposes a Keycloak adapter {@link UnauthenticatedActionsHandler} as a Spring Security filter.
 *
 * @author ebondu
 * @version $Revision: 1 $
 */
public class KeycloakUnauthenticatedActionsFilter extends GenericFilterBean implements ApplicationContextAware {

    private static final Logger log = LoggerFactory.getLogger(KeycloakUnauthenticatedActionsFilter.class);

    private ApplicationContext applicationContext;

    private AdapterDeploymentContext deploymentContext;

    private UnauthenticatedPolicyEnforcer policyEnforcer;

    public KeycloakUnauthenticatedActionsFilter() {
        super();
    }

    @Override
    protected void initFilterBean() throws ServletException {
        deploymentContext = applicationContext.getBean(AdapterDeploymentContext.class);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpFacade facade = new SimpleHttpFacade((HttpServletRequest)request, (HttpServletResponse)response);
        if (policyEnforcer == null) {
            policyEnforcer = new UnauthenticatedPolicyEnforcer(deploymentContext.resolveDeployment(facade).getPolicyEnforcer());
        }
        UnauthenticatedActionsHandler handler = new UnauthenticatedActionsHandler(deploymentContext.resolveDeployment(facade), (OIDCHttpFacade)facade, policyEnforcer);
        boolean handled = handler.handledRequest();
        if (handled) {
            log.debug("Unauthenticated scopes filter handled request: {}", ((HttpServletRequest) request).getRequestURI());
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}