<?php

namespace LoginNotify;

use MediaWiki\Installer\DatabaseUpdater;
use MediaWiki\Installer\Hook\LoadExtensionSchemaUpdatesHook;

class SchemaHooks implements LoadExtensionSchemaUpdatesHook {
	/**
	 * @param DatabaseUpdater $updater
	 */
	public function onLoadExtensionSchemaUpdates( $updater ) {
		$updater->addExtensionUpdateOnVirtualDomain( [
			'virtual-LoginNotify',
			'addTable',
			'loginnotify_seen_net',
			dirname( __DIR__ ) . "/sql/{$updater->getDB()->getType()}/tables-generated.sql",
			true
		] );
	}
}
