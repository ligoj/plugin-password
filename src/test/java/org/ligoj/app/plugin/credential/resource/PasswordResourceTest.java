package org.ligoj.app.plugin.credential.resource;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.regex.Pattern;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.transaction.Transactional;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.ligoj.app.AbstractAppTest;
import org.ligoj.app.MatcherUtil;
import org.ligoj.app.iam.IUserRepository;
import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.app.iam.UserOrg;
import org.ligoj.app.plugin.credential.dao.PasswordResetRepository;
import org.ligoj.app.plugin.credential.model.PasswordReset;
import org.ligoj.app.plugin.mail.resource.MailServicePlugin;
import org.ligoj.app.resource.ServicePluginLocator;
import org.ligoj.bootstrap.core.resource.BusinessException;
import org.ligoj.bootstrap.core.security.SecurityHelper;
import org.ligoj.bootstrap.core.validation.ValidationJsonException;
import org.ligoj.bootstrap.model.system.SystemConfiguration;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Test of {@link PasswordResource}
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(locations = "classpath:/META-INF/spring/application-context-test.xml")
@Rollback
@Transactional
public class PasswordResourceTest extends AbstractAppTest {

	private Exception exOnPrepare = null;
	private MimeMessage mockMessage;

	@Autowired
	private PasswordResource resource;

	@Autowired
	private PasswordResetRepository repository;

	@BeforeEach
	public void prepareConfiguration() throws IOException {
		persistEntities("csv", SystemConfiguration.class);
		exOnPrepare = null;
	}

	@Test
	public void generate() {
		for (int i = 100; i-- > 0;) {
			final String password = resource.generate();
			Assertions.assertNotNull(password);
			Assertions.assertEquals(10, password.length());
			Assertions.assertTrue(StringUtils.containsAny(password, "0123456789"));
			Assertions.assertTrue(StringUtils.containsAny(password, "abcdefghijklmnopqrstuvwxyz"));
			Assertions.assertTrue(StringUtils.containsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
			Assertions.assertTrue(resource.isAcceptedClasses(password));
		}
	}

	@Test
	public void isAcceptedClasses() {
		Assertions.assertFalse(resource.isAcceptedClasses("abcdefghIJ"));
		Assertions.assertFalse(resource.isAcceptedClasses("0123456789"));
		Assertions.assertFalse(resource.isAcceptedClasses("0124567Ab"));
		Assertions.assertTrue(resource.isAcceptedClasses("01234567Ab"));
		Assertions.assertTrue(resource.isAcceptedClasses("01234567aB"));
		Assertions.assertTrue(resource.isAcceptedClasses("0@#1)#b/A="));
	}

	@Test
	public void generateForUnknownUser() {
		Assertions.assertEquals("unknown-id", Assertions.assertThrows(BusinessException.class, () -> {
			newResource().generate(DEFAULT_USER, false);
		}).getMessage());
	}

	@Test
	public void generateForUser() {
		final PasswordResource resource = newResource();
		mockUser(resource, "fdaugan");
		Assertions.assertTrue(resource.isAcceptedClasses(resource.generate("fdaugan", false)));
	}

	@Test
	public void generateForUserQuite() {
		final PasswordResource resource = newResource();
		mockUser(resource, "fdaugan");
		UserOrg userOrg = resource.getUser().findById("fdaugan");
		Mockito.verify(userOrg, Mockito.never()).getMails();
		Assertions.assertTrue(resource.isAcceptedClasses(resource.generate("fdaugan", true)));
	}

	private PasswordResource newResource() {
		final PasswordResource resource = new PasswordResource();
		resource.iamProvider = new IamProvider[] { Mockito.mock(IamProvider.class) };
		final IamConfiguration iamConfiguration = Mockito.mock(IamConfiguration.class);
		final IUserRepository mock = Mockito.mock(IUserRepository.class);
		Mockito.when(iamConfiguration.getUserRepository()).thenReturn(mock);
		Mockito.when(resource.iamProvider[0].getConfiguration()).thenReturn(iamConfiguration);
		final ConfigurationResource configuration = Mockito.mock(ConfigurationResource.class);
		Mockito.when(configuration.get("password.mail.from")).thenReturn("FROM");
		Mockito.when(configuration.get("password.mail.new.subject")).thenReturn("NEW-%s");
		Mockito.when(configuration.get("password.mail.new.content")).thenReturn("%s-%s-%s-%s-%s-%s-%s-%s");
		Mockito.when(configuration.get("password.mail.reset.content")).thenReturn("%s-%s-%s-%s");
		Mockito.when(configuration.get("password.mail.reset.subject")).thenReturn("RESET-%s");
		Mockito.when(configuration.get("password.mail.node")).thenReturn("service:mail:smtp:local");
		Mockito.when(configuration.get("password.mail.url")).thenReturn("host");
		Mockito.when(configuration.get(PasswordResource.PASSWORD_GEN_LENGTH, 10)).thenReturn(10);
		Mockito.when(
				configuration.get(PasswordResource.PASSWORD_VALIDATOR, PasswordResource.PASSWORD_VALIDATOR_DEFAULT))
				.thenReturn(PasswordResource.PASSWORD_VALIDATOR_DEFAULT);
		resource.configuration = configuration;
		resource.repository = Mockito.mock(PasswordResetRepository.class);
		resource.servicePluginLocator = Mockito.mock(ServicePluginLocator.class);
		resource.securityHelper = Mockito.mock(SecurityHelper.class);
		Mockito.when(resource.securityHelper.getLogin()).thenReturn(getAuthenticationName());

		mockMessage = Mockito.mock(MimeMessage.class);
		MailServicePlugin mailServicePlugin = Mockito.mock(MailServicePlugin.class);
		Mockito.when(resource.servicePluginLocator.getResource("service:mail:smtp:local", MailServicePlugin.class))
				.thenReturn(mailServicePlugin);
		Mockito.when(mailServicePlugin.send(ArgumentMatchers.eq("service:mail:smtp:local"),
				ArgumentMatchers.any(MimeMessagePreparator.class))).thenAnswer(a -> {
					((MimeMessagePreparator) a.getArguments()[1]).prepare(mockMessage);
					return (MimeMessagePreparator) a.getArguments()[1];
				});
		return resource;
	}

	@Test
	public void sendMailPasswordNoPassword() throws MessagingException {
		final PasswordResource resource = newResource();
		final MimeMessage message = Mockito.mock(MimeMessage.class);
		Mockito.when(resource.configuration.get("password.mail.url")).thenReturn("host");
		final MailServicePlugin mailServicePlugin = resource.servicePluginLocator.getResource("service:mail:smtp:local",
				MailServicePlugin.class);
		Mockito.when(mailServicePlugin.send(ArgumentMatchers.eq("service:mail:smtp:local"),
				ArgumentMatchers.any(MimeMessagePreparator.class))).thenAnswer(

						i -> {
							MimeMessagePreparator mimeMessagePreparator = (MimeMessagePreparator) i.getArguments()[1];
							try {
								mimeMessagePreparator.prepare(message);
							} catch (final Exception e) {
								exOnPrepare = e;
							}
							return mimeMessagePreparator;
						});

		final UserOrg user = new UserOrg();
		user.setFirstName("John");
		user.setLastName("Doe");
		user.setId("fdauganB");
		user.setMails(Collections.singletonList("f.g@sample.com"));
		resource.sendMailPassword(user, null);
		Assertions.assertNull(exOnPrepare);
		Mockito.verify(message, Mockito.atLeastOnce()).setContent(
				"John Doe-fdauganB-null-<a href=\"host\">host</a>-John Doe-fdauganB-null-<a href=\"host\">host</a>",
				"text/html; charset=UTF-8");
	}

	@Test
	public void requestRecoveryUserNotFound() {
		final PasswordResource resource = newResource();
		resource.requestRecovery("fdauganB", "f.d@sample.com");
		Assertions.assertEquals(0, repository.findAll().size());
	}

	@Test
	public void requestRecoveryBadMail() {
		resource.requestRecovery("fdaugan", "f.d@sample.com");
		Assertions.assertEquals(0, repository.findAll().size());
	}

	@Test
	public void requestRecoveryLocked() {
		final PasswordResource resource = newResource();
		final UserOrg lockedUser = mockUser(resource, "fdaugan");
		Mockito.when(lockedUser.getLocked()).thenReturn(new Date());
		resource.requestRecovery("fdaugan", "f.d@sample.com");
		Assertions.assertEquals(0, repository.findAll().size());
		Mockito.verify(lockedUser).getLocked();
		Mockito.verifyNoMoreInteractions(lockedUser);
	}

	@Test
	public void sendMailReset() throws MessagingException {
		final PasswordResource resource = newResource();
		final UserOrg user = new UserOrg();
		user.setFirstName("John");
		user.setLastName("Doe");
		user.setId("fdauganB");
		user.setMails(Collections.singletonList("f.g@sample.com"));
		resource.sendMailReset(user, "mail", "token");
		Mockito.verify(mockMessage, Mockito.atLeastOnce()).setContent(
				"John Doe-<a href=\"host#reset=token/fdauganB\">host#reset=token/fdauganB</a>-John Doe-<a href=\"host#reset=token/fdauganB\">host#reset=token/fdauganB</a>",
				"text/html; charset=UTF-8");
	}

	@Test
	void sendMailNoMailPlugin() {
		final PasswordResource resource = new PasswordResource();
		resource.servicePluginLocator = Mockito.mock(ServicePluginLocator.class);
		resource.configuration = Mockito.mock(ConfigurationResource.class);
		Mockito.doReturn("service:mail:deleted-plug-in").when(resource.configuration).get("password.mail.node");
		resource.sendMail(null);
		Mockito.verify(resource.servicePluginLocator).getResource("service:mail:deleted-plug-in",
				MailServicePlugin.class);
	}

	@Test
	public void sendMailPassword() {
		final PasswordResource resource = newResource();

		exOnPrepare = null;
		final UserOrg user = new UserOrg();
		user.setFirstName("John");
		user.setLastName("Doe");
		user.setId("fdauganB");
		user.setMails(Collections.singletonList("f.g@sample.com"));
		resource.sendMailPassword(user, "password");
		MailServicePlugin mailService = resource.servicePluginLocator.getResource("service:mail:smtp:local",
				MailServicePlugin.class);
		Mockito.verify(mailService, Mockito.atLeastOnce()).send(ArgumentMatchers.eq("service:mail:smtp:local"),
				ArgumentMatchers.any(MimeMessagePreparator.class));
	}

	@Test
	public void sendMailPasswordWithException() {
		final PasswordResource resource = newResource();
		Mockito.when(resource.configuration.get("password.mail.url")).thenReturn("host");
		final MailServicePlugin mailServicePlugin = resource.servicePluginLocator.getResource("service:mail:smtp:local",
				MailServicePlugin.class);
		Mockito.when(mailServicePlugin.send(ArgumentMatchers.eq("service:mail:smtp:local"),
				ArgumentMatchers.any(MimeMessagePreparator.class))).thenAnswer(i -> {
					throw new BusinessException(null, MimeMessagePreparator.class);
				});
		final UserOrg user = new UserOrg();
		user.setFirstName("John");
		user.setLastName("Doe");
		user.setId("fdauganB");
		user.setMails(Collections.singletonList("f.g@sample.com"));
		resource.sendMailPassword(user, "passwd");
	}

	@Test
	public void requestRecovery() throws MessagingException {
		final PasswordResource resource = newResource();
		final MimeMessage message = Mockito.mock(MimeMessage.class);
		resource.repository = repository;
		resource.iamProvider = new IamProvider[] { iamProvider };
		Mockito.when(resource.configuration.get("password.mail.url")).thenReturn("host");
		final MailServicePlugin mailServicePlugin = resource.servicePluginLocator.getResource("service:mail:smtp:local",
				MailServicePlugin.class);
		Mockito.when(mailServicePlugin.send(ArgumentMatchers.eq("service:mail:smtp:local"),
				ArgumentMatchers.any(MimeMessagePreparator.class))).thenAnswer(

						i -> {
							MimeMessagePreparator mimeMessagePreparator = (MimeMessagePreparator) i.getArguments()[1];
							try {
								mimeMessagePreparator.prepare(message);
							} catch (final Exception e) {
								exOnPrepare = e;
							}
							return mimeMessagePreparator;
						});
		resource.requestRecovery("fdaugan", "fDaugaN@sample.com");
		em.flush();

		Assertions.assertNull(exOnPrepare);
		final List<PasswordReset> requests = repository.findAll();
		Assertions.assertEquals(1, requests.size());
		final PasswordReset passwordReset = requests.get(0);
		Assertions.assertEquals("fdaugan", passwordReset.getLogin());

		Mockito.verify(message, Mockito.atLeastOnce())
				.setContent("First Last-<a href=\"host#reset=" + passwordReset.getToken() + "/fdaugan\">host#reset="
						+ passwordReset.getToken() + "/fdaugan</a>-First Last-<a href=\"host#reset="
						+ passwordReset.getToken() + "/fdaugan\">host#reset=" + passwordReset.getToken()
						+ "/fdaugan</a>", "text/html; charset=UTF-8");
	}

	@Test
	public void requestRecoveryTooOld() {
		final PasswordResource resource = newResource();
		resource.repository = repository;
		resource.iamProvider = new IamProvider[] { iamProvider };
		resource.repository = repository;

		// prepare existing request
		final PasswordReset pwdReset = new PasswordReset();
		pwdReset.setDate(new Date());
		pwdReset.setLogin("fdaugan");
		pwdReset.setToken("t-t-t-t");
		repository.save(pwdReset);
		resource.requestRecovery("fdaugan", "fdaugan@sample.com");
		em.flush();

		Assertions.assertNull(exOnPrepare);
		final PasswordReset passwordReset = repository.findAll().get(0);

		Assertions.assertEquals(pwdReset.getDate(), passwordReset.getDate());
	}

	@Test
	public void reset() {
		resource.reset(prepareReset("fdaugan"), "fdaugan");

		// check mocks
		Assertions.assertNull(repository.findByLoginAndTokenAndDateAfter("fdaugan", "t-t-t-t", new Date()));
		getUser().authenticate("fdaugan", "Strong3r");
	}

	@Test
	public void resetInvalidUser() {
		final PasswordResource resource = newResource();
		resource.repository = repository;
		resource.reset(prepareReset("fdaugan"), "fdaugan");
	}

	@Test
	public void resetLockedUser() {
		final PasswordResource resource = newResource();
		Mockito.when(resource.repository.findByLoginAndTokenAndDateAfter(ArgumentMatchers.anyString(),
				ArgumentMatchers.anyString(), ArgumentMatchers.any(Date.class))).thenReturn(new PasswordReset());
		final UserOrg lockedUser = mockUser(resource, "fdaugan");
		Mockito.when(lockedUser.getLocked()).thenReturn(new Date());
		resource.reset(prepareReset("fdaugan"), "fdaugan");
		Assertions.assertEquals(1, repository.findAll().size());
		Mockito.verify(lockedUser).getLocked();
		Mockito.verifyNoMoreInteractions(lockedUser);
	}

	private UserOrg mockUser(final PasswordResource resource, final String login) {
		final IUserRepository mock = resource.getUser();
		final UserOrg user = Mockito.mock(UserOrg.class);
		Mockito.when(mock.findById(login)).thenReturn(user);
		Mockito.when(user.getId()).thenReturn(login);
		Mockito.when(user.getMails()).thenReturn(Collections.emptyList());
		return user;
	}

	@Test
	public void restInvalidToken() {
		// call business
		final ResetPasswordByMailChallenge userResetPassword = new ResetPasswordByMailChallenge();
		userResetPassword.setToken("bad-token");
		userResetPassword.setPassword("Strong3r");
		Assertions.assertEquals("unknown-id", Assertions.assertThrows(BusinessException.class, () -> {
			resource.reset(userResetPassword, "mdupont");
		}).getMessage());
		em.flush();
	}

	private ResetPasswordByMailChallenge prepareReset(final String user) {
		// create dataset
		final PasswordReset pwdReset = new PasswordReset();
		pwdReset.setLogin(user);
		pwdReset.setToken("t-t-t-t");
		pwdReset.setDate(new Date());
		repository.save(pwdReset);
		em.flush();

		// call business
		final ResetPasswordByMailChallenge userResetPassword = new ResetPasswordByMailChallenge();
		userResetPassword.setToken("t-t-t-t");
		userResetPassword.setPassword("Strong3r");
		return userResetPassword;
	}

	@Test
	public void confirmRecoveryOldToken() {
		// create dataset
		final PasswordReset pwdReset = createRequest();
		repository.save(pwdReset);
		em.flush();

		// call business
		final ResetPasswordByMailChallenge userResetPassword = new ResetPasswordByMailChallenge();
		userResetPassword.setToken("t-t-t-t");
		userResetPassword.setPassword("Strong3r");
		Assertions.assertEquals("unknown-id", Assertions.assertThrows(BusinessException.class, () -> {
			resource.reset(userResetPassword, "mdupont");
		}).getMessage());
	}

	@Test
	public void updateAuthenticationFailed() {
		final PasswordResource resource = newResource();
		final ResetPassword request = new ResetPassword();
		request.setNewPassword("Strong3r");
		request.setPassword("any");
		MatcherUtil.assertThrows(Assertions.assertThrows(ValidationJsonException.class, () -> {
			resource.update(request);
		}), "password", "login");
	}

	@Test
	public void update() {
		initSpringSecurityContext("fdauganA");
		final ResetPassword request = new ResetPassword();
		request.setPassword("Azerty01");
		request.setNewPassword("Azerty02");
		resource.update(request);
		getUser().authenticate("fdauganA", "Azerty02");

		// Restore old value
		request.setPassword("Azerty02");
		request.setNewPassword("Azerty01");
		resource.update(request);
	}

	@Test
	public void cleanRecoveriesAllRequests() {
		initSpringSecurityContext("fdauganA");
		// create dataset
		final PasswordReset pwdResetOld = createRequest();
		repository.save(pwdResetOld);
		em.flush();

		// call
		resource.cleanRecoveries();

		// check
		Assertions.assertEquals(0, repository.count());
	}

	@Test
	public void cleanRecoveriesOneRequest() {
		// create dataset
		final PasswordReset pwdResetOld = createRequest();
		repository.save(pwdResetOld);
		final PasswordReset pwdReset = createRequest();
		pwdReset.setDate(new Date());
		pwdReset.setLogin(DEFAULT_USER);
		repository.save(pwdReset);
		em.flush();

		// call
		resource.cleanRecoveries();

		// check
		Assertions.assertEquals(1, repository.count());
	}

	@Test
	public void cleanRecoveriesNoRequests() {
		// create dataset
		final PasswordReset pwdReset1 = createRequest();
		pwdReset1.setDate(new Date());
		repository.save(pwdReset1);
		final PasswordReset pwdReset2 = createRequest();
		pwdReset2.setDate(DateTime.now().minusHours(1).toDate());
		pwdReset2.setLogin(DEFAULT_USER);
		repository.save(pwdReset2);
		em.flush();

		// call
		resource.cleanRecoveries();

		// check
		Assertions.assertEquals(2, repository.count());

	}

	/**
	 * create basic data
	 * 
	 * @return password reset
	 */
	private PasswordReset createRequest() {
		final PasswordReset pwdReset = new PasswordReset();
		pwdReset.setLogin("mdupont");
		pwdReset.setToken("t-t-t-t");
		pwdReset.setDate(new GregorianCalendar(2012, 2, 2).getTime());
		return pwdReset;
	}

	@Test
	public void checkPassword() {
		final Pattern pattern = Pattern.compile(ResetPassword.COMPLEXITY_PATTERN);

		// Accepted password
		Assertions.assertTrue(pattern.matcher("aZ1-----").matches());
		Assertions.assertTrue(pattern.matcher("aZ3rty?;").matches());
		Assertions.assertTrue(pattern.matcher("azertyY2").matches());
		Assertions.assertTrue(pattern.matcher("AZERTYa0").matches());
		Assertions.assertTrue(pattern.matcher("b1234567890&#'{}()[].,;:!|<>-=+*_@$?§/£Y").matches());
		Assertions.assertTrue(pattern.matcher("b0&#$%_-/:µ,.~¤!§*£=+|{}[]?<>;'&B").matches());

		// Rejected password
		Assertions.assertFalse(pattern.matcher("AZERYa0").matches());
		Assertions.assertFalse(pattern.matcher("AZERYUIO").matches());
		Assertions.assertFalse(pattern.matcher("azertyop").matches());
		Assertions.assertFalse(pattern.matcher("azerty0p").matches());
		Assertions.assertFalse(pattern.matcher("AZERYUI0").matches());
		Assertions.assertFalse(pattern.matcher("AZéRYUI0").matches());
	}

	@Test
	public void getKey() {
		Assertions.assertEquals("feature:password", resource.getKey());
	}

	@Test
	public void getInstalledEntities() {
		Assertions.assertTrue(resource.getInstalledEntities().contains(SystemConfiguration.class));
	}
}
