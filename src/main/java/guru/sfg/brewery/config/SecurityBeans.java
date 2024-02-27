package guru.sfg.brewery.config;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.ICredentialRepository;
import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

@Configuration
public class SecurityBeans {

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

    @Bean
    public GoogleAuthenticator googleAuthenticator(ICredentialRepository credentialRepository) {
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder configBuilder
                = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();

        configBuilder
                .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(60))
                .setWindowSize(10)
                .setNumberOfScratchCodes(0);

        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator(configBuilder.build());
        googleAuthenticator.setCredentialRepository(credentialRepository);
        return googleAuthenticator;

    }

    // event를 처리
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }

}
