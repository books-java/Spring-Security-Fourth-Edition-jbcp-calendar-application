package com.packtpub.springsecurity.service;

import com.packtpub.springsecurity.domain.CalendarUser;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

/**
 * An implementation of {@link UserContext} that looks up the
 * {@link CalendarUser} using the Spring Security's
 * {@link Authentication} by principal name.
 *
 * @author bnasslahsen
 */
@Component
public class SpringSecurityUserContext implements UserContext {

	/**
	 * The Calendar service.
	 */
	private final CalendarService calendarService;

	/**
	 * The User details service.
	 */
	private final UserDetailsService userDetailsService;

	/**
	 * Instantiates a new Spring security user context.
	 *
	 * @param calendarService    the calendar service
	 * @param userDetailsService the user details service
	 */
	public SpringSecurityUserContext(final CalendarService calendarService,
			final UserDetailsService userDetailsService) {
		if (calendarService == null) {
			throw new IllegalArgumentException("calendarService cannot be null");
		}
		if (userDetailsService == null) {
			throw new IllegalArgumentException("userDetailsService cannot be null");
		}
		this.calendarService = calendarService;
		this.userDetailsService = userDetailsService;
	}

	/**
	 * Get the {@link CalendarUser} by obtaining the currently logged in Spring
	 * Security user's
	 * {@link Authentication#getName()} and using that to find the
	 * {@link CalendarUser} by email address (since for our
	 * application Spring Security usernames are email addresses).
	 */
	@Override
	public CalendarUser getCurrentUser() {
		/*
		 * Our code obtains the username from the current Spring Security Authentication
		 * object and
		 * utilizes that to look up the current CalendarUser object by email address.
		 * Since our Spring
		 * Security username is an email address, we can use the email address to link
		 * CalendarUser
		 * with the Spring Security user. Note that if we were to link accounts, we
		 * would normally want to
		 * do this with a key that we generated rather than something that may change
		 * (that is, an email
		 * address). We follow the good practice of returning only our domain object to
		 * the application.
		 * This ensures that our application is only aware of our CalendarUser object
		 * and thus is not coupled to Spring Security.
		 */
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		if (authentication == null) {
			return null;
		}
		return (CalendarUser) authentication.getPrincipal();

	}

	@Override
	public void setCurrentUser(CalendarUser user) {
		if (user == null) {
			throw new IllegalArgumentException("user cannot be null");
		}

		UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());

		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
				user.getPassword(), userDetails.getAuthorities());

		SecurityContextHolder.getContext().setAuthentication(authentication);
	}
}