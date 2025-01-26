package com.example.petcare.config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

/**
 * Configuration for email service using Gmail SMTP
 * Handles email credentials and SMTP settings
 */
@Configuration
public class EmailConfiguration {

    /**
     * Gmail username injected from application properties
     */
    @Value("${spring.mail.username}")
    private String emailUsername;

    /**
     * Gmail password/app-specific password injected from application properties
     */
    @Value("${spring.mail.password}")
    private String emailPassword;

    /**
     * Configures JavaMailSender with Gmail SMTP settings
     * @return Configured JavaMailSender instance
     */
    @Bean
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        // Configure Gmail SMTP server settings
        mailSender.setHost("smtp.gmail.com");
        mailSender.setPort(587);  // TLS port
        mailSender.setUsername(emailUsername);
        mailSender.setPassword(emailPassword);

        // Configure additional mail properties
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");         // Enable authentication
        props.put("mail.smtp.starttls.enable", "true");  // Enable TLS
        props.put("mail.debug", "true");             // Enable debug mode

        return mailSender;
    }
}