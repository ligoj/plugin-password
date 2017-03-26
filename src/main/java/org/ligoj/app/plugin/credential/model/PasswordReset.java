package org.ligoj.app.plugin.credential.model;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import lombok.Getter;
import lombok.Setter;

import org.hibernate.validator.constraints.NotBlank;

import org.ligoj.bootstrap.core.model.AbstractPersistable;
import org.ligoj.bootstrap.core.validation.LowerCase;

/**
 * password reset request
 */
@Getter
@Setter
@Entity
@Table(name = "LIGOJ_PASSWORD_RESET")
public class PasswordReset extends AbstractPersistable<Integer> {

	/**
	 * serial UID
	 */
	private static final long serialVersionUID = -2317331866002580938L;

	/**
	 * User name/login/UID.
	 */
	@NotNull
	@NotBlank
	@LowerCase
	@Pattern(regexp = "^[a-z0-9]+$")
	private String login;

	/**
	 * Mail.
	 */
	@NotNull
	@NotBlank
	private String token;

	/**
	 * Date.
	 */
	@NotNull
	private Date date;

}
