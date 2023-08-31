<?php
/**
 * Body of LoginNotify extension
 *
 * @file
 * @ingroup Extensions
 */

namespace LoginNotify;

use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\Hook\AuthManagerLoginAuthenticateAuditHook;
use MediaWiki\Auth\Hook\LocalUserCreatedHook;
use MediaWiki\User\UserFactory;
use User;

class Hooks implements
	AuthManagerLoginAuthenticateAuditHook,
	LocalUserCreatedHook
{
	/** @var UserFactory */
	private $userFactory;

	public function __construct( UserFactory $userFactory ) {
		$this->userFactory = $userFactory;
	}

	/**
	 * Hook for login auditing
	 *
	 * @param AuthenticationResponse $ret Is login successful?
	 * @param User|null $user User object on successful auth
	 * @param string|null $username Username for failed attempts.
	 * @param string[] $extraData
	 */
	public function onAuthManagerLoginAuthenticateAudit(
		$ret, $user, $username, $extraData
	) {
		if ( !$user && $username !== null ) {
			$user = $this->userFactory->newFromName( $username, UserFactory::RIGOR_USABLE );
		}

		if ( !$user ) {
			return;
		}

		if ( $ret->status === AuthenticationResponse::PASS ) {
			self::doSuccessfulLogin( $user );
		} elseif (
			$ret->status === AuthenticationResponse::FAIL
			&& $ret->message->getKey() !== 'login-throttled'
		) {
			self::doFailedLogin( $user );
		}
		// Other statuses include Abstain, Redirect, or UI. We ignore such
		// statuses.
	}

	/**
	 * Handle a successful login (clear the attempt counter, send a notice, and record the
	 * current IP address as known).
	 *
	 * @param User $user The user who logged in.
	 */
	public static function doSuccessfulLogin( User $user ) {
		$loginNotify = new LoginNotify();
		$loginNotify->clearCounters( $user );
		$loginNotify->sendSuccessNotice( $user );
		$loginNotify->setCurrentAddressAsKnown( $user );
	}

	/**
	 * Handle a failed login (record the failure).
	 *
	 * @param User $user The user that failed to log in.
	 */
	public static function doFailedLogin( User $user ) {
		$loginNotify = new LoginNotify();
		$loginNotify->recordFailure( $user );
	}

	/**
	 * Hook handler for new account creation.
	 *
	 * Called immediately after a local user has been created and saved to the database
	 *
	 * @todo This still sets cookies if user creates account well logged in as someone else.
	 * @param User $user User created
	 * @param bool $autocreated Whether this was an auto-created account
	 */
	public function onLocalUserCreated( $user, $autocreated ) {
		if ( !$autocreated ) {
			$loginNotify = new LoginNotify();
			$loginNotify->setCurrentAddressAsKnown( $user );
		}
	}
}
