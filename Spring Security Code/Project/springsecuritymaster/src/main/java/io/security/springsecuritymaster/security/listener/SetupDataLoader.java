package io.security.springsecuritymaster.security.listener;

import io.security.springsecuritymaster.admin.repository.RoleRepository;
import io.security.springsecuritymaster.domain.entity.Account;
import io.security.springsecuritymaster.domain.entity.Role;
import io.security.springsecuritymaster.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {
    private boolean alreadySetup = false;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    // private final FilterChainProxy filterChainProxy; // FilterChainProxy 주입

    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {
        if (alreadySetup) {
            return;
        }
        // disableAuthorizationFilter(); // AuthorizationFilter 제거 메서드
        setupData();
        alreadySetup = true;
    }

    /*
    private void disableAuthorizationFilter() {
        // FilterChainProxy에서 가장 마지막 필터 (AuthorizationFilter) 제거
        filterChainProxy.getFilterChains()
                .forEach(df -> df.getFilters().remove(df.getFilters().size()-1));
    }
    */

    private void setupData() {
        HashSet<Role> roles = new HashSet<>();
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
        roles.add(adminRole);
        createUserIfNotFound("admin", "admin@admin.com", "pass", roles);
    }

    public Role createRoleIfNotFound(String roleName, String roleDesc) {
        Role role = roleRepository.findByRoleName(roleName);

        if (role == null) {
            role = Role.builder()
                    .roleName(roleName)
                    .roleDesc(roleDesc)
                    .build();
        }
        return roleRepository.save(role);
    }

    public void createUserIfNotFound(final String userName, final String email, final String password, Set<Role> roleSet) {
        Account account = userRepository.findByUsername(userName);

        if (account == null) {
            account = Account.builder()
                    .username(userName)
                    .password(passwordEncoder.encode(password))
                    .userRoles(roleSet)
                    .build();
        }
        userRepository.save(account);
    }
}