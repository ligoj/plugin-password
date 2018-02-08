package org.ligoj.app.plugin.credential.resource;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import javax.mail.Message;
import javax.mail.internet.InternetAddress;
import javax.transaction.Transactional;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.commons.lang3.CharUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.text.RandomStringGenerator;
import org.joda.time.DateTime;
import org.ligoj.app.api.FeaturePlugin;
import org.ligoj.app.iam.IPasswordGenerator;
import org.ligoj.app.iam.IUserRepository;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.app.iam.SimpleUserOrg;
import org.ligoj.app.iam.UserOrg;
import org.ligoj.app.plugin.credential.dao.PasswordResetRepository;
import org.ligoj.app.plugin.credential.model.PasswordReset;
import org.ligoj.app.plugin.mail.resource.MailServicePlugin;
import org.ligoj.app.resource.ServicePluginLocator;
import org.ligoj.bootstrap.core.SpringUtils;
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
 * LDAP password resource.
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
	 * Az09 string generator.
	 */
	private static RandomStringGenerator GENERATOR = new RandomStringGenerator.Builder()
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
	protected ConfigurationResource configurationResource;

	@Autowired
	protected ServicePluginLocator servicePluginLocator;

	/**
	 * Generate a random password.
	 * 
	 * @return a generated password.
	 */
	public String generate() {
		return GENERATOR.generate(10);
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
		final UserOrg userLdap = getUser().findById(login);
		// Check user and password
		if (!getUser().authenticate(login, request.getPassword())) {
			throw new ValidationJsonException("password", "login");
		}

		
		// Update password
		getUser().setPassword(userLdap, request.getPassword(), request.getNewPassword());
	}

	/**
	 * Reset password from a mail challenge :token + mail + user name.
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
		// check token in database : Invalid token, or out-dated, or invalid
		// user ?
		final PasswordReset passwordReset = repository.findByLoginAndTokenAndDateAfter(uid, request.getToken(),
				DateTime.now().minusHours(NumberUtils.INTEGER_ONE).toDate());
		if (passwordReset == null) {
			throw new BusinessException(BusinessException.KEY_UNKNOW_ID);
		}

		// Check the user and update his/her password
		final UserOrg userLdap = getUser().findById(uid);
		getUser().setPassword(userLdap, null, request.getPassword());


		// Remove password reset request since this token is no more valid
		repository.delete(passwordReset);
	}

	/**
	 * Manage user password recovery with valid user name and mail.
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
		final UserOrg userLdap = getUser().findById(uid);
		if (userLdap != null && userLdap.getLocked() == null) {
			// Case insensitive match
			final Set<String> mails = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
			mails.addAll(userLdap.getMails());
			if (!mails.add(mail)
					&& repository.findByLoginAndDateAfter(uid, DateTime.now().minusMinutes(5).toDate()) == null) {
				// We accept password reset only if no request has been done for
				// 5 minutes
				createPasswordReset(uid, mail, userLdap, UUID.randomUUID().toString());
			}
		}
	}

	/**
	 * Create a password reset. Previous token are kept.
	 */
	private void createPasswordReset(final String uid, final String mail, final UserOrg userLdap, final String token) {
		final PasswordReset passwordReset = new PasswordReset();
		passwordReset.setLogin(uid);
		passwordReset.setToken(token);
		passwordReset.setDate(new Date());
		repository.saveAndFlush(passwordReset);
		sendMailReset(userLdap, mail, token);
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
		sendMail(mimeMessage -> {
			final String fullName = user.getFirstName() + " " + user.getLastName();
			final InternetAddress internetAddress = new InternetAddress(mailTo, fullName,
					StandardCharsets.UTF_8.name());
			String link = configurationResource.get(URL_PUBLIC) + "#reset=" + token + "/" + user.getId();
			link = "<a href=\"" + link + "\">" + link + "</a>";
			mimeMessage.setHeader("Content-Type", "text/plain; charset=UTF-8");
			mimeMessage.setFrom(new InternetAddress(configurationResource.get(MESSAGE_FROM),
					configurationResource.get(MESSAGE_FROM_TITLE), StandardCharsets.UTF_8.name()));
			mimeMessage.setRecipient(Message.RecipientType.TO, internetAddress);
			mimeMessage.setSubject(configurationResource.get(SUBJECT), StandardCharsets.UTF_8.name());
			mimeMessage.setContent(
					String.format(configurationResource.get(MESSAGE_RESET), fullName, link, fullName, link),
					"text/html; charset=UTF-8");
		});
	}

	/**
	 * Send an email using the default mail node. If no mail is configured,
	 * nothing happens.
	 */
	private void sendMail(final MimeMessagePreparator preparator) {
		try {
			final String node = configurationResource.get(MAIL_NODE);
			Optional.ofNullable(servicePluginLocator.getResource(node, MailServicePlugin.class))
					.map(p -> p.send(node, preparator));
		} catch (Exception e) {
			log.error(e.getMessage());
		}
	}

	/**
	 * Daily, clean old recovery requests.
	 */
	@Scheduled(cron = "0 0 1 1/1 * ?")
	public void cleanRecoveries() {
		// @Modifying + @Scheduled + @Transactional [+protected] --> No TX, wait
		// for next release & TU
		SpringUtils.getBean(PasswordResource.class).cleanRecoveriesInternal();
	}

	/**
	 * Clean old recovery requests
	 */
	public void cleanRecoveriesInternal() {
		repository.deleteByDateBefore(DateTime.now().minusDays(1).toDate());
	}

	/**
	 * Generate a password for given user. This password is is stored as
	 * digested in corresponding LDAP entry.
	 * 
	 * @param uid
	 *            LDAP UID of user.
	 */
	@Override
	public String generate(final String uid) {
		return create(uid, generate());
	}

	/**
	 * Set the password of given user (UID) and return the generated one. This
	 * password is stored as digested in corresponding LDAP entry.
	 * 
	 * @param uid
	 *            LDAP UID of user.
	 * @param password
	 *            The password to set.
	 * @return the clear generated password.
	 */
	protected String create(final String uid, final String password) {
		return create(uid, password, true);
	}

	/**
	 * Set the password of given user (UID) and return the generated one. This
	 * password is stored as digested in corresponding LDAP entry.
	 * 
	 * @param uid
	 *            LDAP UID of user.
	 * @param password
	 *            The password to set.
	 * @param sendMail
	 *            send a mail if true.
	 * @return the clear generated password.
	 */
	protected String create(final String uid, final String password, final boolean sendMail) {
		final UserOrg userLdap = checkUser(uid);

		// Replace the old or create a new one
		getUser().setPassword(userLdap, password);
		if (sendMail) {
			sendMailPassword(userLdap, password);
		}
		return password;
	}

	/**
	 * Check the user exists.
	 * 
	 * @param uid
	 *            UID of user to lookup.
	 * @return {@link UserOrg} LDAP entry.
	 */
	private UserOrg checkUser(final String uid) {
		final UserOrg userLdap = getUser().findById(uid);
		if (userLdap == null || userLdap.getLocked() != null) {
			throw new BusinessException(BusinessException.KEY_UNKNOW_ID, uid);
		}
		return userLdap;
	}

	/**
	 * Send the mail of password to the user.
	 * @param user The target recipient.
	 * @param password The exposed password.
	 */
	protected void sendMailPassword(final SimpleUserOrg user, final String password) {
		log.info("Sending mail to '{}' at {}", user.getId(), user.getMails());
		prepareAndSendMail(user, password);
	}

	private void prepareAndSendMail(final SimpleUserOrg user, final String password) {
		sendMail(mimeMessage -> {
			final String fullName = user.getFirstName() + " " + user.getLastName();
			final InternetAddress[] internetAddresses = getUserInternetAdresses(user, fullName);
			final String link = "<a href=\"" + configurationResource.get(URL_PUBLIC) + "\">"
					+ configurationResource.get(URL_PUBLIC) + "</a>";
			mimeMessage.setHeader("Content-Type", "text/plain; charset=UTF-8");
			mimeMessage.setFrom(new InternetAddress(configurationResource.get(MESSAGE_FROM),
					configurationResource.get(MESSAGE_FROM_TITLE), StandardCharsets.UTF_8.name()));
			mimeMessage.setSubject(String.format(configurationResource.get(MESSAGE_NEW_SUBJECT), fullName),
					StandardCharsets.UTF_8.name());
			mimeMessage.setRecipients(Message.RecipientType.TO, internetAddresses);
			mimeMessage.setContent(String.format(configurationResource.get(MESSAGE_NEW), fullName, user.getId(),
					password, link, fullName, user.getId(), password, link), "text/html; charset=UTF-8");
		});
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
