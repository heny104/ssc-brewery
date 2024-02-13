package guru.sfg.brewery.config;

import guru.sfg.brewery.security.JpaUserDetailsService;
import guru.sfg.brewery.security.RestHeaderAuthFilter;
import guru.sfg.brewery.security.RestUrlAuthFilter;
import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.naming.ldap.LdapContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 헤더 권한 부여 필터
    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager) {
        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    public RestUrlAuthFilter restUrlAuthFilter(AuthenticationManager authenticationManager){
        RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Spring Security에 필터 추가
        // 필터 체인에 사용자 이름 및 비밀번호 인증 필터 전에 실행할 필터를 추가
        http.addFilterBefore(restHeaderAuthFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class)
                .csrf().disable();

        http.addFilterBefore(restUrlAuthFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class);

        http
                .authorizeRequests(authorize -> {
                    authorize
                            // h2 db console에 접근, production에서는 사용 금지
                            .antMatchers("/h2-console/**").permitAll()
                            // antMatchers - 특정 리소스에 대해서 권한을 설정
                            // permitAll - antMatchers 설정한 리소스의 접근을 인증절차 없이 허용
                            .antMatchers("/","/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            // antMatchers 대신 Spring MVC Matcher를 사용하는 모습
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                })
                .authorizeRequests((requests) -> {
                    // requests.anyRequest()).authenticated() - 모든 리소스를 의미하며 접근허용 리소스 및 인증후 특정 레벨의 권한을 가진 사용자만 접근가능한 리소스를 설정하고 그외 나머지 리소스들은 무조건 인증을 완료해야 접근이 가능
                    ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)requests.anyRequest()).authenticated();
                });
        http.formLogin();
        http.httpBasic();

        // h2 console config - iframe 사용시 sameOrigin() 문제 발생
        http.headers().frameOptions().sameOrigin();
    }

    // password encoder의 형식 기본 구현
    @Bean
    PasswordEncoder passwordEncoder() {
        //return NoOpPasswordEncoder.getInstance(); // noop
        //return new LdapShaPasswordEncoder();      // Ldap
        //return new StandardPasswordEncoder();     // SHA256
        //return new BCryptPasswordEncoder();         // Bcrypt

        // spring framework5의 새로운 기능
        // DelegatingPasswordEncoder()
        //return PasswordEncoderFactories.createDelegatingPasswordEncoder();

        // customizing된 createDelegatingPasswordEncoder
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // 초기방법
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("spring")
//                .password("guru")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user);
//    }


//    @Autowired
//    JpaUserDetailsService jpaUserDetailsService;

    // 좀 더 세련된 방법 Fluent Api
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // JPA를 사용해서 인증
//        auth.userDetailsService(this.jpaUserDetailsService).passwordEncoder(passwordEncoder())

        // inMemory 인증 사용을 하기위해 구성
//        auth.inMemoryAuthentication()
//                .withUser("spring")
//                //.password("{noop}guru") // {noop} 암호를 인코딩하지 않는 옵션
//                //.password("guru")   // password encoder 기본 구현으로 {noop} 필요없어짐
//                // DelegatingPasswordEncoder()는 앞에 encoding 방식을 적어준다.
//                .password("{bcrypt}$2a$10$0YQFNcENRVqOEauNBUXFL.REwKgdhK2ee5w1xlhiWT5o17EKsPvVC")
//                .roles("ADMIN")
//                .and()
//                .withUser("user")
//                //.password("{noop}password")
//                //.password("password") // password encoder 기본 구현으로 {noop} 필요없어짐
//                //.password("{SSHA}fGFiyOowMefCzKa71X6HpF5sFvOvUD0lZAe1qg==") // Ldap
//                // .password("1b6b7aa5e8399d93b2fe349fb481baa6f817ea3e3764a6aeffaf0fdac69fae5d7a71867e1cc01ab7") // SHA256
//                //.password("$2a$10$jRNmW0q6W9mLxqzRj2tylOsFtQJP7kSdRbQ.HIysVLuLdEP.r2Vru") // Bcrypt
//                .password("{sha256}c5713fd72e44158fa23858880b4944f1cebaac3f04b6ff33d84600888c101bc7c965405a5c02976b")
//                .roles("USER");
//
//        auth.inMemoryAuthentication()
//                .withUser("scott")
//                //.password("tiger")
//                // DelegatingPasswordEncoder()는 앞에 encoding 방식을 적어준다.
//                //.password("{ldap}{SSHA}ahBwS1Om/ldZGlFn7MhRN2/JkX1V9Pw6VJq+CA==")
//                .password("{bcrypt}$2a$10$vw6snZBA6u1K5rS.iwWp/O1e6dQ61W13DoOo.DUS9IR4MJ91IxqmC")
//                .roles("CUSTOMER");
//    }
}
