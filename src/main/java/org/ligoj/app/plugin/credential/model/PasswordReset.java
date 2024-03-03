/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.credential.model;

import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import org.ligoj.bootstrap.core.model.AbstractPersistable;
import org.ligoj.bootstrap.core.validation.LowerCase;

import lombok.Getter;
import lombok.Setter;

/**
 * password reset request
 */
@Getter
@Setter
@Entity
@Table(name = "LIGOJ_PASSWORD_RESET")
public class PasswordReset extends AbstractPersistable<Integer> {

	/**
	 * Username/login/UID.
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
