package org.ligoj.app.plugin.credential.dao;

import java.util.Date;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.ligoj.app.plugin.credential.model.PasswordReset;
import org.ligoj.bootstrap.core.dao.RestRepository;

/**
 * {@link PasswordReset} repository
 */
public interface PasswordResetRepository extends RestRepository<PasswordReset, Integer> {
	/**
	 * find by login and token
	 * 
	 * @param login
	 *            User's login
	 * @param token
	 *            Token
	 * @param date
	 *            validity date
	 * @return password reset
	 */
	PasswordReset findByLoginAndTokenAndDateAfter(String login, String token, Date date);

	/**
	 * find by login where request is before validity
	 * 
	 * @param login
	 *            login
	 * @param date
	 *            validity date
	 * @return password reset
	 */
	PasswordReset findByLoginAndDateAfter(String login, Date date);

	/**
	 * Delete by date.
	 * 
	 * @param date
	 *            The maximum date
	 */
	@Modifying
	@Query("DELETE PasswordReset WHERE date < ?1")
	void deleteByDateBefore(Date date);
}
