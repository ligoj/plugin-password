/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.credential.resource;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import org.hibernate.validator.constraints.Length;

import lombok.Getter;
import lombok.Setter;

/**
 * Password reset from mail challenge.
 */
@Getter
@Setter
public class ResetPasswordByMailChallenge {

	@NotBlank
	@NotNull
	@Length(max = 40)
	private String token;

	@NotBlank
	@NotNull
	@Length(max = 50)
	@Pattern(regexp = ResetPassword.COMPLEXITY_PATTERN)
	private String password;

}
