<?php
class LoginNotifyPresentationModel extends EchoEventPresentationModel {

	/**
	 * Show an user avatar.
	 *
	 * @return String Name of icon
	 */
	public function getIconType() {
		return 'LoginNotify-user-avatar';
	}

	/**
	 * Nothing really to link to
	 *
	 * @return boolean false to disable link
	 */
	public function getPrimaryLink() {
		return false;
	}

	/**
	 * Include the number of attempts in the message if needed
	 *
	 * @return Message
	 */
	public function getHeaderMessage() {
		switch ( $this->event->getType() ) {
			case 'login-fail-known':
				$msg = $this->msg( 'notification-known-header-login-fail' );
				$msg->params( $this->event->getExtraParam( 'count', 0 ) );
				break;
			case 'login-fail-new':
				if ( $this->isBundled() ) {
					$msg = $this->msg( 'notification-new-bundled-header-login-fail' );
					$msg->params( $this->event->getExtraParam( 'count', 0 ) );
				} else {
					$msg = $this->msg( 'notification-new-unbundled-header-login-fail' );
					$msg->params( $this->event->getExtraParam( 'count', 0 ) );
				}
				break;
			default:
				$msg = $this->msg( 'notification-header-login-success' );
		}
		return $msg;
	}

	/**
	 * Get links to be used in the notification
	 *
	 * @return array Link to Special:ChangePassword
	 */
	public function getSecondaryLinks() {
		$changePasswordLink = [
			'url' => SpecialPage::getTitleFor( 'ChangePassword' )->getFullURL(),
			'label' => $this->msg( 'changepassword' )->text(),
			'description' => '',
			'icon' => 'lock',
			'prioritized' => true,
		];

		return [ $changePasswordLink ];
	}
}
