/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.credential.resource;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import jakarta.mail.Message;
import jakarta.mail.internet.InternetAddress;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.apache.commons.lang3.CharUtils;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.reflect.MethodUtils;
import org.apache.commons.text.RandomStringGenerator;
import org.ligoj.app.iam.IPasswordGenerator;
import org.ligoj.app.iam.IUserRepository;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.app.iam.SimpleUserOrg;
import org.ligoj.app.iam.UserOrg;
import org.ligoj.app.plugin.credential.dao.PasswordResetRepository;
import org.ligoj.app.plugin.credential.model.PasswordReset;
import org.ligoj.app.resource.ServicePluginLocator;
import org.ligoj.bootstrap.core.DateUtils;
import org.ligoj.bootstrap.core.plugin.FeaturePlugin;
import org.ligoj.bootstrap.core.resource.BusinessException;
import org.ligoj.bootstrap.core.security.SecurityHelper;
import org.ligoj.bootstrap.core.validation.ValidationJsonException;
import org.ligoj.bootstrap.model.system.SystemConfiguration;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

/**
 * Password resource.
 */
@Path("/service/password")
@Service
@Transactional
@Produces(MediaType.APPLICATION_JSON)
@Slf4j
public class PasswordResource implements IPasswordGenerator, FeaturePlugin {

	private static final String MAIL_NODE = "password.mail.node";
	private static final String URL_PUBLIC = "password.mail.url";
	private static final String SUBJECT = "password.mail.reset.subject";
	private static final String MESSAGE_RESET = "password.mail.reset.content";
	private static final String MESSAGE_NEW_SUBJECT = "password.mail.new.subject";
	private static final String MESSAGE_NEW = "password.mail.new.content";
	private static final String MESSAGE_FROM_TITLE = "password.mail.from.title";
	private static final String MESSAGE_FROM = "password.mail.from";

	/**
	 * Configuration key to of generated password length
	 */
	public static final String PASSWORD_GEN_LENGTH = "password.strength.gen.length";

	/**
	 * The default generated password length.
	 */
	public static final int PASSWORD_GEN_LENGTH_DEFAULT = 10;

	/**
	 * Configuration key to of password validation (regular expression)
	 */
	public static final String PASSWORD_VALIDATOR = "password.strength.validation";

	/**
	 * The default password validation regular expression.
	 */
	public static final String PASSWORD_VALIDATOR_DEFAULT = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{10,}$";

	/**
	 * Az09 string generator.
	 */
	private static final RandomStringGenerator GENERATOR = new RandomStringGenerator.Builder()
			.filteredBy(c -> CharUtils.isAsciiAlphanumeric(Character.toChars(c)[0])).build();

	/**
	 * IAM provider.
	 */
	@Autowired
	protected IamProvider[] iamProvider;

	@Autowired
	protected SecurityHelper securityHelper;

	@Autowired
	protected PasswordResetRepository repository;

	@Autowired
	protected ConfigurationResource configuration;

	@Autowired
	protected ServicePluginLocator servicePluginLocator;

	/**
	 * Used for "this" and forcing proxying.
	 */
	@Autowired
	private PasswordResource self;

	/**
	 * Generate a random password having at least one digit and one letter.
	 *
	 * @return A generated password.
	 */
	public String generate() {
		String value;
		do {
			value = GENERATOR.generate(configuration.get(PASSWORD_GEN_LENGTH, PASSWORD_GEN_LENGTH_DEFAULT));
		} while (!isAcceptedClasses(value));
		return value;
	}

	/**
	 * Generate a password for given user. This password is stored as digested in corresponding user entry.
	 *
	 * @param uid
	 *            UID of user.
	 * @param quiet
	 *            Flag to turn off the possible notification such as mail. Never <code>null</code>.
	 */
	@Override
	public String generate(final String uid, final boolean quiet) {
		return create(uid, generate(), quiet);
	}

	/**
	 * Indicate the given password suits to the minimal security regarding only the character classes.
	 *
	 * @param value
	 *            The password to check.
	 * @return <code>true</code> when enough complex.
	 */
	protected boolean isAcceptedClasses(final String value) {
		return value.matches(configuration.get(PASSWORD_VALIDATOR, PASSWORD_VALIDATOR_DEFAULT));
	}

	/**
	 * Update user password for current user.
	 *
	 * @param request
	 *            the user request.
	 */
	@PUT
	@Consumes(MediaType.APPLICATION_JSON)
	public void update(final ResetPassword request) {
		final String login = securityHelper.getLogin();
		final UserOrg user = getUser().findById(login);
		// Check user and password
		if (getUser().authenticate(login, request.getPassword()) == null) {
			throw new ValidationJsonException("password", "login");
		}

		// Update password
		getUser().setPassword(user, request.getPassword(), request.getNewPassword());
	}

	/**
	 * Reset password from a mail challenge :token + mail + username.
	 *
	 * @param request
	 *            the user request.
	 * @param uid
	 *            the user UID.
	 */
	@POST
	@Path("reset/{uid}")
	@Consumes(MediaType.APPLICATION_JSON)
	public void reset(final ResetPasswordByMailChallenge request, @PathParam("uid") final String uid) {
		// check token in database : Invalid token, or out-dated, or invalid user ?
		final Calendar calendar = DateUtils.newCalendar();
		calendar.add(Calendar.HOUR, -1);
		final PasswordReset passwordReset = repository.findByLoginAndTokenAndDateAfter(uid, request.getToken(),
				calendar.getTime());
		if (passwordReset == null) {
			throw new BusinessException(BusinessException.KEY_UNKNOWN_ID);
		}

		// Check the user and update his/her password
		final UserOrg user = getUser().findById(uid);
		if (user != null && user.getLocked() == null) {
			getUser().setPassword(user, null, request.getPassword());

			// Remove password reset request since this token is no more valid
			repository.delete(passwordReset);
		}
	}

	/**
	 * Manage user password recovery with valid username and mail.
	 *
	 * @param uid
	 *            user identifier.
	 * @param mail
	 *            user mail to match.
	 */
	@POST
	@Path("recovery/{uid}/{mail}")
	public void requestRecovery(@PathParam("uid") final String uid, @PathParam("mail") final String mail) {
		// Check user exists and is not locked
		final UserOrg user = getUser().findById(uid);
		if (user != null && user.getLocked() == null) {
			// Case insensitive match
			final Set<String> mails = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
			mails.addAll(user.getMails());
			final Calendar calendar = DateUtils.newCalendar();
			calendar.add(Calendar.MINUTE, -5);
			if (mails.contains(mail) && repository.findByLoginAndDateAfter(uid, calendar.getTime()) == null) {
				// We accept password reset only if no request has been done for 5 minutes
				createPasswordReset(uid, mail, user, UUID.randomUUID().toString());
			}
		}
	}

	/**
	 * Create a password reset. Previous token are kept.
	 */
	private void createPasswordReset(final String uid, final String mail, final UserOrg user, final String token) {
		final PasswordReset passwordReset = new PasswordReset();
		passwordReset.setLogin(uid);
		passwordReset.setToken(token);
		passwordReset.setDate(new Date());
		repository.saveAndFlush(passwordReset);
		sendMailReset(user, mail, token);
	}

	/**
	 * Send mail for reset request
	 *
	 * @param user
	 *            User account.
	 * @param mailTo
	 *            Recipient's mail.
	 * @param token
	 *            Random token.
	 */
	protected void sendMailReset(final UserOrg user, final String mailTo, final String token) {
		sendMail(message -> {
			final Map<String, String> values = toMap(user);
			values.put("LINK", values.get("LINK") + "#reset=" + token + "/" + user.getId());
			message.setHeader("Content-Type", "text/plain; charset=UTF-8");
			message.setFrom(new InternetAddress(configuration.get(MESSAGE_FROM), configuration.get(MESSAGE_FROM_TITLE),
					StandardCharsets.UTF_8.name()));
			message.setRecipient(Message.RecipientType.TO,
					new InternetAddress(mailTo, values.get("FULLNAME"), StandardCharsets.UTF_8.name()));
			message.setSubject(configuration.get(SUBJECT), StandardCharsets.UTF_8.name());
			message.setContent(format(MESSAGE_RESET, values), "text/html; charset=UTF-8");
		});
	}

	/**
	 * Send the mail of password to the user.
	 *
	 * @param user
	 *            The target recipient.
	 * @param password
	 *            The exposed password.
	 */
	protected void sendMailPassword(final SimpleUserOrg user, final String password) {
		log.info("Sending mail to '{}' at {}", user.getId(), user.getMails());
		prepareAndSendMail(user, password);
	}

	private void prepareAndSendMail(final SimpleUserOrg user, final String password) {
		sendMail(message -> {
			final Map<String, String> values = toMap(user);
			values.put("PASSWORD", password);
			final InternetAddress[] addresses = getUserInternetAdresses(user, values.get("FULLNAME"));
			final String charset = StandardCharsets.UTF_8.name();
			message.setHeader("Content-Type", "text/plain; charset=UTF-8");
			message.setFrom(new InternetAddress(configuration.get(MESSAGE_FROM), configuration.get(MESSAGE_FROM_TITLE),
					charset));
			message.setRecipients(Message.RecipientType.TO, addresses);
			message.setSubject(format(MESSAGE_NEW_SUBJECT, values), charset);
			message.setContent(format(MESSAGE_NEW, values), "text/html; charset=UTF-8");
		});
	}

	private Map<String, String> toMap(final SimpleUserOrg user) {
		final Map<String, String> values = new HashMap<>();
		values.put("ID", user.getId());
		values.put("FIRSTNAME", user.getFirstName());
		values.put("LASTNAME", user.getLastName());
		values.put("COMPANY", user.getCompany());
		values.put("FULLNAME", user.getFirstName() + " " + user.getLastName());
		values.put("LINK", StringUtils.removeEnd(configuration.get(URL_PUBLIC), "/"));
		return values;
	}

	private String format(final String key, final Map<String, String> values) {
		final AtomicReference<String> cursor = new AtomicReference<>(configuration.get(key));
		values.forEach((key1, value) -> cursor.getAndUpdate(s -> s.replace("$" + key1, StringUtils.trimToEmpty(value))));
		return cursor.get();
	}

	private InternetAddress[] getUserInternetAdresses(final SimpleUserOrg user, final String fullName)
			throws UnsupportedEncodingException {
		final InternetAddress[] internetAddresses = new InternetAddress[user.getMails().size()];
		for (int i = 0; i < user.getMails().size(); i++) {
			internetAddresses[i] = new InternetAddress(user.getMails().get(i), fullName, StandardCharsets.UTF_8.name());
		}
		return internetAddresses;
	}

	/**
	 * Send an email using the default mail node. If no mail is configured, nothing happens.
	 *
	 * @param preparator
	 *            Message delegate.
	 */
	protected void sendMail(final MimeMessagePreparator preparator) {
		final String node = configuration.get(MAIL_NODE);
		try {
			final Class<?> mailService = ClassUtils.getClass("org.ligoj.app.plugin.mail.resource.MailServicePlugin",
					true);
			// "plugin-mail" plug-in is available, locate the node
			final Object plugin = servicePluginLocator.getResource(node, mailService);
			if (plugin == null) {
				// Node is not available: fail safe mode, deleted plug-in, ...
				log.info("Unable to send the password mail using node {}: not available", node);
			} else {
				// Node is available, send the mail through it
				MethodUtils.invokeMethod(plugin, "send", node, preparator);
			}
		} catch (final Exception e) {
			log.error("Unable to send the password mail using node {}: {}", node,
					ExceptionUtils.getRootCause(e).getMessage());
		}
	}

	/**
	 * Daily, clean old recovery requests.
	 */
	@Scheduled(cron = "0 0 1 1/1 * ?")
	public void cleanRecoveries() {
		// @Modifying + @Scheduled + @Transactional [+protected] --> No TX
		self.cleanRecoveriesInternal();
	}

	/**
	 * Clean old recovery requests
	 */
	public void cleanRecoveriesInternal() {
		final Calendar calendar = DateUtils.newCalendar();
		calendar.add(Calendar.DATE, -1);
		repository.deleteByDateBefore(calendar.getTime());
	}

	/**
	 * Set the password of given user (UID) and return the generated one. This password is stored as digested in
	 * corresponding user entry.
	 *
	 * @param uid
	 *            UID of user.
	 * @param password
	 *            The password to set.
	 * @param quiet
	 *            Flag to turn off the possible notification such as mail.
	 * @return the clear generated password.
	 */
	private String create(final String uid, final String password, final boolean quiet) {
		final UserOrg user = checkUser(uid);

		// Replace the old or create a new one
		getUser().setPassword(user, password);
		if (!quiet) {
			sendMailPassword(user, password);
		}
		return password;
	}

	/**
	 * Check the user exists and return it.
	 *
	 * @param uid
	 *            UID of user to lookup.
	 * @return {@link UserOrg} User entry. Never <code>null</code>.
	 */
	private UserOrg checkUser(final String uid) {
		final UserOrg user = getUser().findById(uid);
		if (user == null || user.getLocked() != null) {
			// Locked users are read-only
			throw new BusinessException(BusinessException.KEY_UNKNOWN_ID, uid);
		}
		return user;
	}

	/**
	 * User repository provider.
	 *
	 * @return User repository provider.
	 */
	protected IUserRepository getUser() {
		return iamProvider[0].getConfiguration().getUserRepository();
	}

	@Override
	public String getKey() {
		return "feature:password";
	}

	@Override
	public List<Class<?>> getInstalledEntities() {
		return Collections.singletonList(SystemConfiguration.class);
	}

}
