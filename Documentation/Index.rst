Neos Ldap Documentation
=======================

Example LoginController
-----------------------

LoginController.php::

	<?php
	namespace My\Package\Controller;

	use Neos\Flow\Annotations as Flow;
	use Neos\Flow\Security\Authentication\Controller\AbstractAuthenticationController;

	/**
	 * @Flow\Scope("singleton")
	 */
	class LoginController extends AbstractAuthenticationController {

		/**
		 * Default action, displays the login screen
		 *
		 * @param string $username Optional: A username to prefill into the username field
		 * @return void
		 */
		public function indexAction($username = NULL) {
			$this->view->assign('username', $username);
		}

		/**
		 * @param \Neos\Flow\Mvc\ActionRequest $originalRequest
		 * @return string|void
		 */
		public function onAuthenticationSuccess(\Neos\Flow\Mvc\ActionRequest $originalRequest = NULL) {
			$this->redirect('status');
		}

		/**
		 * Logs out a - possibly - currently logged in account.
		 *
		 * @return void
		 */
		public function logoutAction() {
			$this->authenticationManager->logout();
			$this->addFlashMessage('Successfully logged out.');
			$this->redirect('index');
		}

		/**
		 * @return void
		 */
		public function statusAction() {
			$this->view->assign('activeTokens', $this->securityContext->getAuthenticationTokens());
		}

	}

Index.html::

	<f:form action="authenticate" >
		<f:flashMessages class="errorMessages" />
			<div>
				<label>User</label>
				<input type="text" name="__authentication[Neos][Flow][Security][Authentication][Token][UsernamePassword][username]" id="username" value="{username}" />
			</div>
			<div>
				<label>Password</label>
				<input type="password" name="__authentication[Neos][Flow][Security][Authentication][Token][UsernamePassword][password]" id="password" />
			</div>
			<f:form.submit value="Login" />
		</div>
	</f:form>

Status.html::

	Status: Logged in<br/>
	User: {activeTokens.LdapProvider.account.accountIdentifier}<br/>
	<f:link.action action="logout">Logout</f:link.action>

Make sure you configure the policies so that the login and logout actions are available for the user. For that use a Policy.yaml
like::

	resources:
	  methods:
		My_Package_LoginController: 'method(My\Package\Controller\LoginController->(index|status|login|authenticate|logout)Action())'

	  acls:
	    Everybody:
	      methods:
	        My_Package_LoginController: GRANT

Configuration examples
----------------------

You can find examples of a ``Settings.yaml`` file for Ldap and Active Directory in the Configuration/ folder
of the Neos.Ldap package.
