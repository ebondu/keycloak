package org.keycloak.adapters.authorization;

import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.AuthorizationContext;
import org.keycloak.RSATokenVerifier;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.representation.EntitlementRequest;
import org.keycloak.authorization.client.representation.EntitlementResponse;
import org.keycloak.authorization.client.representation.PermissionRequest;
import org.keycloak.authorization.client.representation.ResourceRepresentation;
import org.keycloak.authorization.client.resource.ProtectedResource;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.representations.idm.authorization.Permission;

/**
 * To enforce resources for unauthenticated users
 */
public class UnauthenticatedPolicyEnforcer extends AbstractPolicyEnforcer {

    private static Logger LOGGER = Logger.getLogger(UnauthenticatedPolicyEnforcer.class);

    private PolicyEnforcer policyEnforcer;
    private PolicyEnforcerConfig enforcerConfig;
    private Map<String, PolicyEnforcerConfig.PathConfig> paths;
    private AuthzClient authzClient;
    private PathMatcher pathMatcher;

    public UnauthenticatedPolicyEnforcer(PolicyEnforcer policyEnforcer) {
        super(policyEnforcer);
        this.policyEnforcer = policyEnforcer;
        this.enforcerConfig = policyEnforcer.getEnforcerConfig();
        this.authzClient = policyEnforcer.getClient();
        this.pathMatcher = new PathMatcher(this.authzClient);
        this.paths = policyEnforcer.getPaths();
    }

    public AuthorizationContext authorize(OIDCHttpFacade httpFacade) {
        PolicyEnforcerConfig.EnforcementMode enforcementMode = this.enforcerConfig.getEnforcementMode();

        if (PolicyEnforcerConfig.EnforcementMode.DISABLED.equals(enforcementMode)) {
            return createEmptyAuthorizationContext(true);
        }

        HttpFacade.Request request = httpFacade.getRequest();
        HttpFacade.Response response = httpFacade.getResponse();
        String path = getPath(request);

        PolicyEnforcerConfig.PathConfig pathConfig = pathMatcher.matches(path, this.paths);
        LOGGER.debugf("Checking permissions for path [%s] with config [%s].", request.getURI(), pathConfig);

        if (pathConfig == null) {
            if (PolicyEnforcerConfig.EnforcementMode.PERMISSIVE.equals(enforcementMode)) {
                return createEmptyAuthorizationContext(true);
            }

            LOGGER.debugf("Could not find a configuration for path [%s]", path);
            response.setStatus(403);//, "Could not find a configuration for path [" + path + "].");

            return createEmptyAuthorizationContext(false);
        }

        if (PolicyEnforcerConfig.EnforcementMode.DISABLED.equals(pathConfig.getEnforcementMode())) {
            return createEmptyAuthorizationContext(true);
        }

        PolicyEnforcerConfig.PathConfig actualPathConfig = resolvePathConfig(pathConfig, request);
        Set<String> requiredScopes = getRequiredScopes(actualPathConfig, request);

        if (isAuthorized(actualPathConfig, requiredScopes, httpFacade)) {
            return createEmptyAuthorizationContext(true);
        }

        response.setStatus(403);//, "No permission to access path");
        return createEmptyAuthorizationContext(false);
    }

    @Override
    protected boolean challenge(PolicyEnforcerConfig.PathConfig pathConfig, PolicyEnforcerConfig.MethodConfig methodConfig, OIDCHttpFacade facade) {
        return false;
    }

    protected boolean isAuthorized(PolicyEnforcerConfig.PathConfig actualPathConfig, Set<String> requiredScopes, OIDCHttpFacade httpFacade) {

        HttpFacade.Request request = httpFacade.getRequest();

        boolean hasPermission = false;

        List<Permission> permissions = getPermissions(actualPathConfig, requiredScopes);

        for (Permission permission : permissions) {
            if (permission.getResourceSetId() != null) {
                if (isResourcePermission(actualPathConfig, permission)) {
                    hasPermission = true;

                    if (actualPathConfig.isInstance() && !matchResourcePermission(actualPathConfig, permission)) {
                        continue;
                    }

                    if (hasResourceScopePermission(requiredScopes, permission, actualPathConfig)) {
                        LOGGER.debugf("Authorization GRANTED for path [%s]. Permissions [%s].", actualPathConfig, permissions);
                        if (request.getMethod().equalsIgnoreCase("DELETE") && actualPathConfig.isInstance()) {
                            this.paths.remove(actualPathConfig);
                        }
                        return true;
                    }
                }
            } else {
                if (hasResourceScopePermission(requiredScopes, permission, actualPathConfig)) {
                    return true;
                }
            }
        }

        if (!hasPermission && PolicyEnforcerConfig.EnforcementMode.PERMISSIVE.equals(actualPathConfig.getEnforcementMode())) {
            return true;
        }

        LOGGER.debugf("Authorization FAILED for path [%s]. No enough permissions [%s].", actualPathConfig, permissions);
        return false;
    }

    private AuthorizationContext createEmptyAuthorizationContext(final boolean granted) {
        return new AuthorizationContext() {
            @Override
            public boolean hasPermission(String resourceName, String scopeName) {
                return granted;
            }

            @Override
            public boolean hasResourcePermission(String resourceName) {
                return granted;
            }

            @Override
            public boolean hasScopePermission(String scopeName) {
                return granted;
            }

            @Override
            public List<Permission> getPermissions() {
                return Collections.EMPTY_LIST;
            }

            @Override
            public boolean isGranted() {
                return granted;
            }
        };
    }
    private String getPath(HttpFacade.Request request) {
        String pathInfo = URI.create(request.getURI()).getPath().substring(1);
        return pathInfo.substring(pathInfo.indexOf('/'), pathInfo.length());
    }

    private PolicyEnforcerConfig.PathConfig resolvePathConfig(PolicyEnforcerConfig.PathConfig originalConfig, HttpFacade.Request request) {
        long start = System.currentTimeMillis();
        String path = getPath(request);

        if (originalConfig.hasPattern()) {
            ProtectedResource resource = this.authzClient.protection().resource();
            Set<String> search = resource.findByFilter("uri=" + path);

            if (!search.isEmpty()) {
                // resource does exist on the server, cache it
                ResourceRepresentation targetResource = resource.findById(search.iterator().next()).getResourceDescription();
                PolicyEnforcerConfig.PathConfig config = PolicyEnforcer.createPathConfig(targetResource);

                config.setScopes(originalConfig.getScopes());
                config.setMethods(originalConfig.getMethods());
                config.setParentConfig(originalConfig);
                config.setEnforcementMode(originalConfig.getEnforcementMode());

                this.policyEnforcer.addPath(config);

                LOGGER.info("resolvePathConfig in "+(System.currentTimeMillis() - start));
                return config;
            }
        }
        LOGGER.info("resolvePathConfig in "+(System.currentTimeMillis() - start));
        return originalConfig;
    }

    private Set<String> getRequiredScopes(PolicyEnforcerConfig.PathConfig pathConfig, HttpFacade.Request request) {
        Set<String> requiredScopes = new HashSet<>();

        requiredScopes.addAll(pathConfig.getScopes());

        String method = request.getMethod();

        for (PolicyEnforcerConfig.MethodConfig methodConfig : pathConfig.getMethods()) {
            if (methodConfig.getMethod().equals(method)) {
                requiredScopes.addAll(methodConfig.getScopes());
            }
        }

        return requiredScopes;
    }

    private boolean isResourcePermission(PolicyEnforcerConfig.PathConfig actualPathConfig, Permission permission) {
        // first we try a match using resource id
        boolean resourceMatch = matchResourcePermission(actualPathConfig, permission);

        // as a fallback, check if the current path is an instance and if so, check if parent's id matches the permission
        if (!resourceMatch && actualPathConfig.isInstance()) {
            resourceMatch = matchResourcePermission(actualPathConfig.getParentConfig(), permission);
        }

        return resourceMatch;
    }


    protected AuthzClient getAuthzClient() {
        return this.authzClient;
    }

    protected PolicyEnforcerConfig getEnforcerConfig() {
        return enforcerConfig;
    }

    protected PolicyEnforcer getPolicyEnforcer() {
        return policyEnforcer;
    }

    private boolean hasResourceScopePermission(Set<String> requiredScopes, Permission permission, PolicyEnforcerConfig.PathConfig actualPathConfig) {
        Set<String> allowedScopes = permission.getScopes();
        return (allowedScopes.containsAll(requiredScopes) || allowedScopes.isEmpty());
    }
    private boolean matchResourcePermission(PolicyEnforcerConfig.PathConfig actualPathConfig, Permission permission) {
        return permission.getResourceSetId().equals(actualPathConfig.getId());
    }

    private List<Permission> getPermissions(PolicyEnforcerConfig.PathConfig path, Set<String> requiredScopes) {
        String eat = authzClient.obtainAccessToken().getToken();

        // create an entitlement request
        EntitlementRequest request = new EntitlementRequest();
        PermissionRequest permission = new PermissionRequest();

        permission.setResourceSetId(path.getId());
        permission.setResourceSetName(path.getName());
        permission.setScopes(requiredScopes);

        request.addPermission(permission);

        // send the entitlement request to the server in order to get all permissions granted to the

        try {
            LOGGER.debugf("Sending entitlements request: resource_set_id [%s], resource_set_name [%s], scopes [%s].", permission.getResourceSetId(), permission.getResourceSetName(), permission.getScopes());
            EntitlementResponse response = authzClient.entitlement(eat).get(authzClient.getConfiguration().getResource(), request);
            LOGGER.debugf("Obtained permissions for resource [%s].", path);

            String rpt = response.getRpt();
            //CacheManager.getInstance().getCache("authorizations").put(new Element(path.getId(), rpt));
            return RSATokenVerifier.create(rpt).getToken().getAuthorization().getPermissions();

        } catch (Exception e) {
            LOGGER.debugf("Unable to obtain permissions for resource [%s].", path);
        }
        return Collections.EMPTY_LIST;
    }
}
