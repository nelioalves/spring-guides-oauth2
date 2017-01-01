package com.nelioalves.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.annotation.PropertySource;

@Configuration
@Profile("dev")
@PropertySource("file:///${user.home}/.spring-oauth2/application-dev.properties")
public class DevelopmentConfig {

}
