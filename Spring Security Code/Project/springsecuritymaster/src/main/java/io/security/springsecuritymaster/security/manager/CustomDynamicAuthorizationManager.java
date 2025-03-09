package io.security.springsecuritymaster.security.manager;

import io.security.springsecuritymaster.admin.repository.ResourcesRepository;
import io.security.springsecuritymaster.security.mapper.MapBasedUrlRoleMapper;
import io.security.springsecuritymaster.security.mapper.PersistentUrlRoleMapper;
import io.security.springsecuritymaster.security.service.DynamicAuthorizationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    // RequestMatcherEntry<T> 타입이므로 T에 AuthorizationManager
    private List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

    // mappings에 부합된 EndPoint와 ROLE은 중요한 보안이므로 지켜져야 하지만, 나머지 클라이언트 요청은 문제가 없으므로 ACCESS
    private static final AuthorizationDecision ACCESS = new AuthorizationDecision(true);

    private final HandlerMappingIntrospector handlerMappingIntrospector; // MVC RequestMatcher 필요에 의해 주입

    private final ResourcesRepository resourcesRepository;

    // RoleHierarchy 주입
    private final RoleHierarchy roleHierarchy;

    DynamicAuthorizationService dynamicAuthorizationService;

    @PostConstruct // 빈이 생성된 이후 호출
    public void mapping() {

//      DynamicAuthorizationService dynamicAuthorizationService = new DynamicAuthorizationService(new MapBasedUrlRoleMapper());
        dynamicAuthorizationService = new DynamicAuthorizationService(new PersistentUrlRoleMapper(resourcesRepository));
        setMapping();

    }

    // 여러 명이 접근할 수 있으므로 동시성 문제에 대한 동기화 처리 필요
    public synchronized void reload() {
        mappings.clear(); // mapping 초기화
        setMapping();
    }

    // EndPoint, 권한 처리 메서드 추출
    private void setMapping() {
        mappings = dynamicAuthorizationService.getUrlRoleMappings()
                .entrySet().stream()
                .map(entry -> new RequestMatcherEntry<>(
                        new MvcRequestMatcher(handlerMappingIntrospector, entry.getKey()),
                        customAuthorizationManager(entry.getValue()))) // 권한 처리할 메서드 생성
                .collect(Collectors.toList());
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext request) {

        //RequestMatcherDelegatingAuthorizationManager check() 이용
        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {

            RequestMatcher matcher = mapping.getRequestMatcher();
            RequestMatcher.MatchResult matchResult = matcher.matcher(request.getRequest());

            if (matchResult.isMatch()) {
                AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
                return manager.check(authentication,
                        new RequestAuthorizationContext(request.getRequest(), matchResult.getVariables()));
            }
        }

        return ACCESS; // mapping 정보에 부합하지 않으면 위에서 설정한 DENY 값
    }


    private AuthorizationManager<RequestAuthorizationContext> customAuthorizationManager(String role) {
        // role : ROLE_USER, hasRole(...), permitAll 등
        if(role != null) {
            if(role.startsWith("ROLE")) {
                // ROLE_ 권한은 AuthorityAuthorizationManager
                AuthorityAuthorizationManager<RequestAuthorizationContext> authorizationManager = AuthorityAuthorizationManager.hasAuthority(role);
                // 계층적 권한 부여
                authorizationManager.setRoleHierarchy(roleHierarchy);

                return authorizationManager;
            } else {
                // 그 외의 경우는 표현식 사용
                DefaultHttpSecurityExpressionHandler handler = new DefaultHttpSecurityExpressionHandler();
                // 계층적 권한 부여 (핸들러를 통해 부여 후, 매니저로 설정)
                handler.setRoleHierarchy(roleHierarchy);

                WebExpressionAuthorizationManager authorizationManager = new WebExpressionAuthorizationManager(role);
                authorizationManager.setExpressionHandler(handler);

                return authorizationManager;
            }
        }

        return null;
    }

    @Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        AuthorizationManager.super.verify(authentication, object);
    }

}
