<?php

namespace LoginNotify;

use MediaWiki\JobQueue\Job;
use MediaWiki\Title\Title;

class PurgeSeenJob extends Job {
	private LoginNotify $loginNotify;

	public function __construct( Title $title, array $params, LoginNotify $loginNotify ) {
		parent::__construct( 'LoginNotifyPurgeSeen', $title, $params );
		$this->loginNotify = $loginNotify;
	}

	/** @inheritDoc */
	public function run() {
		$minId = $this->getParams()['minId'];
		$this->loginNotify->purgeSeen( $minId );
		return true;
	}
}
