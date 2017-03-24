package org.ligoj.app.plugin.credential.resource;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import lombok.Getter;
import lombok.Setter;

import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotBlank;

/**
 * Password update from a connected user.
 */
@Getter
@Setter
public class ResetPassword {

	/**
	 * Password complexity pattern.
	 */
	public static final String COMPLEXITY_PATTERN = "((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])[a-zA-Z\\dµ,.~¤@#$%_\\-/:!§*£=+|{}()\\[\\]?<>;'&]{8,50})";

	/**
	 * Current password used to check the connected user.
	 */
	@NotBlank
	@NotNull
	@Length(max = 50)
	private String password;

	/**
	 * New password.
	 */
	@NotBlank
	@NotNull
	@Length(max = 50)
	@Pattern(regexp = COMPLEXITY_PATTERN)
	private String newPassword;

}
