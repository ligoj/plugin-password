# :link: Ligoj Password Management plugin [![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.ligoj.plugin/plugin-password/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.ligoj.plugin/plugin-password)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=org.ligoj.plugin%3Aplugin-password&metric=coverage)](https://sonarcloud.io/dashboard?id=org.ligoj.plugin%3Aplugin-password)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?metric=alert_status&project=org.ligoj.plugin:plugin-password)](https://sonarcloud.io/dashboard/index/org.ligoj.plugin:plugin-password)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4531336334664f9286cb43df834172dd)](https://www.codacy.com/gh/ligoj/plugin-password?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ligoj/plugin-password&amp;utm_campaign=Badge_Grade)
[![CodeFactor](https://www.codefactor.io/repository/github/ligoj/plugin-password/badge)](https://www.codefactor.io/repository/github/ligoj/plugin-password)
[![License](http://img.shields.io/:license-mit-blue.svg)](http://fabdouglas.mit-license.org/)

[Ligoj](https://github.com/ligoj/ligoj) Password Management plugin
This plugin does not hold password, only tokens for renew request. The storage is delegated
to [plugin-id](https://github.com/ligoj/plugin-id)
Provides the following features :

- Mail for new accounts
- Mail challenge reset password

Spring-Boot properties (can be injected in `CUSTOM_OPTS`) and can be dynamically modified from the administration
console:

| Name                         | Default value                               | Note                                                                                                                                                            |
|------------------------------|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| password.mail.from           |                                             | Mail `FROM` attribute when generated password is sent                                                                                                           |
| password.mail.new.subject"   |                                             | Mail `SUBJECT` attribute when generated password is sent                                                                                                        |
| password.mail.new.content    |                                             | Mail `BODY` attribute when generated password is sent. Can be a template containing `$FULLNAME`,`$FIRSTNAME`,`$LASTNAME`,`$LINK`,`$ID`,`$COMPANY`               |
| password.mail.reset.subject  |                                             | Same than `password.mail.new.subject` be for reset workflow                                                                                                     |
| password.mail.reset.content  |                                             | Same than `password.mail.new.content` be for reset workflow                                                                                                     |
| password.mail.node           |                                             | Ligoj plugin node's identifier, implementing `service:mail` contract. See [plugin-mail](https://github.com/ligoj/plugin-mail). When undefined, no mail is sent. |
| password.mail.from           |                                             | Mail `FROM` attribute when generated password is sent                                                                                                           |
| password.mail.url            |                                             | Reset URL overriding the application's URL.                                                                                                                     |
| password.strength.gen.length | `10`                                        | Generated default  length for generated password.                                                                                                               |
| password.strength.validation | `^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{10,}$` | Regular expression validating a new manual password.                                                                                                            |                                                                                                                   