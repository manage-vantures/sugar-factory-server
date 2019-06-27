package com.sugarfactory.config;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;


@Configuration
@EnableWebSecurity
public class SecuritySpnegoConfig  extends WebSecurityConfigurerAdapter{
	@Override
	protected void configure(HttpSecurity http) throws Exception {
        http
        	.anonymous()
        		.disable()
        	.exceptionHandling()
        		.accessDeniedPage("/auth/403.html")
        	.and()
        		.formLogin()
        			.loginPage("/auth/login.html")
        				.loginProcessingUrl("/login")
        					.permitAll()
        	.and()
        		.logout()
        			.logoutUrl("/logout")
        				.logoutSuccessUrl("/auth/logout.html")
        					.permitAll()
        	.and()
        		.authorizeRequests()
        			.antMatchers(HttpMethod.POST,"/login")
        				.permitAll()
        		.antMatchers(HttpMethod.GET,"health")
        				.permitAll()
        		.antMatchers("/admin/**")
        				.hasRole("ADMIN")
        		.anyRequest()
        				.hasRole("USER")
        		.antMatchers("/").permitAll()
        	.and()
        		.csrf()
        			.disable();
             
    }
	
	public SpnegoEntryPoint spnegoEntryPoint() {
		return new SpnegoEntryPoint("/auth/login.html");
	}
	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers(
				"auth/**",
				"health"
				
				);
	}
	
	
	public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
		SpnegoAuthenticationProcessingFilter filter=spnegoAuthenticationProcessingFilter(authenticationManager);
		SimpleUrlAuthenticationFailureHandler failureHandler=new SimpleUrlAuthenticationFailureHandler("/auth/login.html");
		failureHandler.setUseForward(true);
		filter.setFailureHandler(failureHandler);
		return filter;
		
	}
	public LdapAuthoritiesPopulator  authoritiesPopulator() {
		return(operations,s)->{
			Collection<? extends GrantedAuthority> original=authoritiesPopulator().getGrantedAuthorities(operations, s);
			Collection<GrantedAuthority>authorities=new ArrayList<>();
			for(GrantedAuthority authority:original) {
				authorities.add(authority);
				if(authority.getAuthority().equalsIgnoreCase("adminGroup")) {
					authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
				}
				if(authority.getAuthority().equalsIgnoreCase("userGroup")) {
					authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
				}
			}
			return authorities;
		};
	}

}
