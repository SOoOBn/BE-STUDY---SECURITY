package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {

    private com.cos.security1.model.User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    // 해당 User의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정 만료?
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정 잠김?
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 비밀번호 만료?    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 활성화?
    @Override
    public boolean isEnabled() {
        return true;
    }
}
