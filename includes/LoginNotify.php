<?php
/**
 * Body of LoginNotify extension
 *
 * @file
 * @ingroup Extensions
 */

namespace LoginNotify;

use BagOStuff;
use CentralAuthUser;
use Config;
use EchoEvent;
use IBufferingStatsdDataFactory;
use JobQueueGroup;
use JobSpecification;
use MediaWiki\MediaWikiServices;
use WebRequest;
use Wikimedia\Assert\Assert;
use Wikimedia\Rdbms\Database;
use Exception;
use IP;
use MediaWiki\Logger\LoggerFactory;
use MWCryptRand;
use ObjectCache;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;
use RequestContext;
use UnexpectedValueException;
use User;

/**
 * Handle sending notifications on login from unknown source.
 *
 * @author Brian Wolff
 */
class LoginNotify implements LoggerAwareInterface {

	const COOKIE_NAME = 'loginnotify_prevlogins';

	// The following 3 constants specify outcomes of user search
	/** User's system is known to us */
	const USER_KNOWN = 'known';
	/** User's system is new for us, based on our data */
	const USER_NOT_KNOWN = 'not known';
	/** We don't have data to confirm or deny this is a known system */
	const USER_NO_INFO = 'no info';

	/** @var BagOStuff */
	private $cache;
	/** @var Config */
	private $config;
	/** @var LoggerInterface Usually instance of LoginNotify log */
	private $log;
	/** @var string|bool Salt for cookie hash */
	private $gSalt;
	/** @var string */
	private $secret;
	/** @var IBufferingStatsdDataFactory */
	private $stats;

	/**
	 * Constructor
	 *
	 * @param Config $cfg Optional. Set if you have handy.
	 * @param BagOStuff $cache Optional. Only set if you want to override default caching behaviour.
	 */
	public function __construct( Config $cfg = null, BagOStuff $cache = null ) {
		if ( !$cache ) {
			$cache = ObjectCache::getLocalClusterInstance();
		}
		if ( !$cfg ) {
			$cfg = RequestContext::getMain()->getConfig();
		}
		$this->cache = $cache;
		$this->config = $cfg;
		// Generate salt just once to avoid duplicate cookies
		$this->gSalt = \Wikimedia\base_convert( MWCryptRand::generateHex( 8 ), 16, 36 );

		if ( $this->config->get( 'LoginNotifySecretKey' ) !== null ) {
			$this->secret = $this->config->get( 'LoginNotifySecretKey' );
		} else {
			$globalSecret = $this->config->get( 'SecretKey' );
			$this->secret = hash( 'sha256', $globalSecret . 'LoginNotify' );
		}

		$log = LoggerFactory::getInstance( 'LoginNotify' );
		$this->log = $log;

		$this->stats = MediaWikiServices::getInstance()->getStatsdDataFactory();
	}

	/**
	 * Set the logger.
	 * @param LoggerInterface $logger The logger object.
	 */
	public function setLogger( LoggerInterface $logger ) {
		$this->log = $logger;
	}

	/**
	 * Get just network part of an IP (assuming /24 or /64)
	 *
	 * @param string $ip Either IPv4 or IPv6 address
	 * @return string Just the network part (e.g. 127.0.0.)
	 * @throws UnexpectedValueException If given something not an IP
	 * @throws Exception If regex totally fails (Should never happen)
	 */
	private function getIPNetwork( $ip ) {
		$ip = IP::sanitizeIP( $ip );
		if ( IP::isIPv6( $ip ) ) {
			// Match against the /64
			$subnetRegex = '/[0-9A-F]+:[0-9A-F]+:[0-9A-F]+:[0-9A-F]+$/i';
		} elseif ( IP::isIPv4( $ip ) ) {
			// match against the /24
			$subnetRegex = '/\d+$/';
		} else {
			throw new UnexpectedValueException( "Unrecognized IP address: $ip" );
		}
		$prefix = preg_replace( $subnetRegex, '', $ip );
		if ( !is_string( $prefix ) ) {
			throw new Exception( __METHOD__ . " Regex failed on '$ip'!?" );
		}
		return $prefix;
	}

	/**
	 * Is the current computer known to be used by the current user (fast checks)
	 * To be used for checks that are fast enough to be run at the moment the user logs in.
	 *
	 * @param User $user User in question
	 * @param WebRequest $request
	 * @return string One of USER_* constants
	 */
	private function isKnownSystemFast( User $user, WebRequest $request ) {
		$result = $this->userIsInCookie( $user, $request );

		if ( $result !== self::USER_KNOWN ) {
			$result = $this->mergeResults( $result, $this->userIsInCache( $user, $request ) );
		}

		$this->log->debug( 'Checking cookies and cache for {user}: {result}', [
			'function' => __METHOD__,
			'user' => $user->getName(),
			'result' => $result,
		] );

		return $result;
	}

	/**
	 * Is the current computer known to be used by the current user (slow checks)
	 * These checks are slow enough to be run via the job queue
	 *
	 * @param User $user User in question
	 * @param string $subnet User's current subnet
	 * @param string $resultSoFar Value returned by isKnownSystemFast() or null if
	 *        not available.
	 * @return bool true if the user has used this computer before
	 */
	private function isKnownSystemSlow( User $user, $subnet, $resultSoFar = null ) {
		$result = $this->checkUserAllWikis( $user, $subnet );
		if ( $result === self::USER_KNOWN ) {
			return true;
		}

		if ( $resultSoFar !== null ) {
			$result = $this->mergeResults( $result, $resultSoFar );
		}

		// If we have no check user data for the user, and there was
		// no cookie supplied, just pass the user in, since we don't have
		// enough info to determine if from known ip.
		// FIXME: Does this make sense
		if ( $result === self::USER_NO_INFO ) {
			// We have to be careful here. Whether $cookieResult is
			// self::USER_NO_INFO, is under control of the attacker.
			// If checking CheckUser is disabled, then we should not
			// hit this branch.

			$this->log->info( "Assuming {user} is from known IP since no info available", [
				'method' => __METHOD__,
				'user' => $user->getName()
			] );
			return true;
		}

		return false;
	}

	/**
	 * Check if we cached this user's ip address from last login.
	 *
	 * @param User $user User in question
	 * @param WebRequest $request
	 * @return string One of USER_* constants
	 */
	private function userIsInCache( User $user, WebRequest $request ) {
		$ipPrefix = $this->getIPNetwork( $request->getIP() );
		$key = $this->getKey( $user, 'prevSubnet' );
		$res = $this->cache->get( $key );
		if ( $res !== false ) {
			return $res === $ipPrefix ? self::USER_KNOWN : self::USER_NOT_KNOWN;
		}
		return self::USER_NO_INFO;
	}

	/**
	 * Is the subnet of the current IP in the check user data for the user.
	 *
	 * If CentralAuth is installed, this will check not only the current wiki,
	 * but also the ten wikis where user has most edits on.
	 *
	 * @param User $user User in question
	 * @param string $subnet User's current subnet
	 * @return string One of USER_* constants
	 */
	private function checkUserAllWikis( User $user, $subnet ) {
		Assert::parameter( $user->isLoggedIn(), '$user', 'User must be logged in' );

		if ( !$this->config->get( 'LoginNotifyCheckKnownIPs' )
			|| !class_exists( 'CheckUser' )
		) {
			// Checkuser checks disabled.
			// Note: It's important this be USER_NOT_KNOWN and not USER_NO_INFO.
			return self::USER_NOT_KNOWN;
		}

		$dbr = wfGetDB( DB_SLAVE );
		$result = $this->checkUserOneWiki( $user->getId(), $subnet, $dbr );
		if ( $result === self::USER_KNOWN ) {
			return $result;
		}

		if ( $result === self::USER_NO_INFO
			&& $this->userHasCheckUserData( $user->getId(), $dbr )
		) {
			$result = self::USER_NOT_KNOWN;
		}

		// Also check checkuser table on the top ten wikis where this user has
		// edited the most. We only do top ten, to limit the worst-case where the
		// user has accounts on 800 wikis.
		if ( class_exists( 'CentralAuthUser' ) ) {
			$globalUser = CentralAuthUser::getInstance( $user );
			if ( $globalUser->exists() ) {
				// This is expensive. However, On WMF wikis, probably
				// already done as part of password complexity check, and
				// will be cached.
				$info = $globalUser->queryAttached();
				// already checked the local wiki.
				unset( $info[wfWikiID()] );
				usort( $info,
					function ( $a, $b ) {
						// descending order
						return $b['editCount'] - $a['editCount'];
					}
				);
				$count = 0;
				foreach ( $info as $localInfo ) {
					if ( !isset( $localInfo['id'] ) || !isset( $localInfo['wiki'] ) ) {
						break;
					}
					if ( $count > 10 || $localInfo['editCount'] < 1 ) {
						break;
					}

					$wiki = $localInfo['wiki'];
					$lb = MediaWikiServices::getInstance()
						->getDBLoadBalancerFactory()
						->getMainLB( $wiki );
					$dbrLocal = $lb->getConnection( DB_SLAVE, [], $wiki );

					if ( !$this->hasCheckUserTables( $dbrLocal ) ) {
						// Skip this wiki, no checkuser table.
						$lb->reuseConnection( $dbrLocal );
						continue;
					}
					// FIXME The case where there are no CU entries for
					// this user.
					$res = $this->checkUserOneWiki(
						$localInfo['id'],
						$subnet,
						$dbrLocal
					);

					if ( $res ) {
						$lb->reuseConnection( $dbrLocal );
						return self::USER_KNOWN;
					}
					if ( $result === self::USER_NO_INFO
						 && $this->userHasCheckUserData( $user->getId(), $dbr )
					) {
						$result = self::USER_NOT_KNOWN;
					}
					$lb->reuseConnection( $dbrLocal );
					$count++;
				}
			}
		}
		return $result;
	}

	/**
	 * Actually do the query of the check user table.
	 *
	 * @suppress PhanTypeMismatchArgument
	 *
	 * @note This catches and ignores database errors.
	 * @param int $userId User id number (Not necessarily for the local wiki)
	 * @param string $ipFragment Prefix to match against cuc_ip (from $this->getIPNetwork())
	 * @param Database $dbr A database connection (possibly foreign)
	 * @return string One of USER_* constants
	 */
	private function checkUserOneWiki( $userId, $ipFragment, Database $dbr ) {
		// For some unknown reason, the index is on
		// (cuc_user, cuc_ip, cuc_timestamp), instead of
		// cuc_ip_hex which would be ideal.
		// user-agent might also be good to look at,
		// but no index on that.
		$IPHasBeenUsedBefore = $dbr->selectField(
			'cu_changes',
			'1',
			[
				'cuc_user' => $userId,
				'cuc_ip ' . $dbr->buildLike(
					$ipFragment,
					$dbr->anyString()
				)
			],
			__METHOD__
		);
		return $IPHasBeenUsedBefore ? self::USER_KNOWN : self::USER_NO_INFO;
	}

	/**
	 * Check if we have any check user info for this user
	 *
	 * If we have no info for user, we maybe don't treat it as
	 * an unknown IP, since user has no known IPs.
	 *
	 * @suppress PhanTypeMismatchArgument
	 *
	 * @todo FIXME Does this behaviour make sense, esp. with cookie check?
	 * @param int $userId User id number (possibly on foreign wiki)
	 * @param Database $dbr DB connection (possibly to foreign wiki)
	 * @return bool
	 */
	private function userHasCheckUserData( $userId, Database $dbr ) {
		// Verify that we actually have IP info for
		// this user.
		// @todo: Should this instead be if we have a
		// a certain number of checkuser entries for this
		// user. Or maybe it should be if we have at least
		// 2 different IPs for this user. Or something else.
		$haveIPInfo = $dbr->selectField(
			'cu_changes',
			'1',
			[
				'cuc_user' => $userId
			],
			__METHOD__
		);

		return (bool)$haveIPInfo;
	}

	/**
	 * Does this wiki have a checkuser table?
	 *
	 * @param Database $dbr Database to check
	 * @return bool
	 */
	private function hasCheckUserTables( Database $dbr ) {
		if ( !$dbr->tableExists( 'cu_changes' ) ) {
			$this->log->warning( "LoginNotify: No checkuser table on {wikiId}", [
				'method' => __METHOD__,
				'wikiId' => $dbr->getWikiID()
			] );
			return false;
		}
		return true;
	}

	/**
	 * Give the user a cookie saying that they've previously logged in from this computer.
	 *
	 * @note If user already has a cookie, this will refresh it.
	 * @param User $user User in question who just logged in.
	 */
	private function setLoginCookie( User $user ) {
		$cookie = $this->getPrevLoginCookie( $user->getRequest() );
		list( , $newCookie ) = $this->checkAndGenerateCookie( $user, $cookie );
		$expire = time() + $this->config->get( 'LoginNotifyCookieExpire' );
		$resp = $user->getRequest()->response();
		$resp->setCookie(
			self::COOKIE_NAME,
			$newCookie,
			$expire,
			[
				'domain' => $this->config->get( 'LoginNotifyCookieDomain' ),
				// Allow sharing this cookie between wikis
				'prefix' => ''
			]
		);
	}

	/**
	 * Give the user a cookie and cache address in memcache
	 *
	 * It is expected this be called upon successful log in.
	 *
	 * @param User $user The user in question.
	 */
	public function setCurrentAddressAsKnown( User $user ) {
		$this->cacheLoginIP( $user );
		$this->setLoginCookie( $user );

		$this->log->debug( 'Recording user {user} as known',
			[
				'function' => __METHOD__,
				'user' => $user->getName(),
			]
		);
	}

	/**
	 * Cache the current IP subnet as being a known location for the given user.
	 *
	 * @param User $user The user.
	 */
	private function cacheLoginIP( User $user ) {
		// For simplicity, this only stores the last IP subnet used.
		// Its assumed that most of the time, we'll be able to rely on
		// the cookie or checkuser data.
		$expiry = $this->config->get( 'LoginNotifyCacheLoginIPExpiry' );
		if ( $expiry !== false ) {
			$ipPrefix = $this->getIPNetwork( $user->getRequest()->getIP() );
			$key = $this->getKey( $user, 'prevSubnet' );
			$this->cache->set( $key, $ipPrefix, $expiry );
		}
	}

	/**
	 * Merges results of various isKnownSystem*() checks
	 *
	 * @param string $x One of USER_* constants
	 * @param string $y One of USER_* constants
	 * @return string
	 */
	private function mergeResults( $x, $y ) {
		if ( $x === self::USER_KNOWN || $y === self::USER_KNOWN ) {
			return self::USER_KNOWN;
		}
		if ( $x === self::USER_NOT_KNOWN || $y === self::USER_NOT_KNOWN ) {
			return self::USER_NOT_KNOWN;
		}
		return self::USER_NO_INFO;
	}

	/**
	 * Check if a certain user is in the cookie.
	 *
	 * @param User $user User in question
	 * @param WebRequest $request
	 * @return string One of USER_* constants
	 */
	private function userIsInCookie( User $user, WebRequest $request ) {
		$cookie = $this->getPrevLoginCookie( $request );

		// FIXME, does this really make sense?
		if ( $cookie === '' ) {
			$result = self::USER_NO_INFO;
		} else {
			list( $userKnown, ) = $this->checkAndGenerateCookie( $user, $cookie );
			$result = $userKnown ? self::USER_KNOWN : self::USER_NOT_KNOWN;
		}

		return $result;
	}

	/**
	 * Get the cookie with previous login names in it
	 *
	 * @param WebRequest $req
	 * @return string The cookie. Empty string if no cookie.
	 */
	private function getPrevLoginCookie( WebRequest $req ) {
		return $req->getCookie( self::COOKIE_NAME, '', '' );
	}

	/**
	 * Check if user is in cookie, and generate a new cookie with user record
	 *
	 * When generating a new cookie, it will add the current user to the top,
	 * remove any previous instances of the current user, and remove older user
	 * references, if there are too many records.
	 *
	 * @param User $user User that person is attempting to log in as.
	 * @param string $cookie A cookie, which has records separated by '.'.
	 * @return array Element 0 is boolean (user seen before?), 1 is the new cookie value.
	 */
	private function checkAndGenerateCookie( User $user, $cookie ) {
		$userSeenBefore = false;
		if ( $cookie === '' ) {
			$cookieRecords = [];
		} else {
			$cookieRecords = explode( '.', $cookie );
		}
		$newCookie = $this->generateUserCookieRecord( $user->getName() );
		$maxCookieRecords = $this->config->get( 'LoginNotifyMaxCookieRecords' );

		$totalCookieRecord = count( $cookieRecords );
		for ( $i = 0; $i < $totalCookieRecord; $i++ ) {
			if ( !$this->validateCookieRecord( $cookieRecords[$i] ) ) {
				// Skip invalid or old cookie records.
				continue;
			}
			$curUser = $this->isUserRecordGivenCookie( $user, $cookieRecords[$i] );
			$userSeenBefore = $userSeenBefore || $curUser;
			if ( $i < $maxCookieRecords && !$curUser ) {
				$newCookie .= '.' . $cookieRecords[$i];
			}
		}
		return [ $userSeenBefore, $newCookie ];
	}

	/**
	 * See if a specific cookie record is for a specific user.
	 *
	 * Cookie record format is: Year - 32-bit salt - hash
	 * where hash is sha1-HMAC of username + | + year + salt
	 * Salt and hash is base 36 encoded.
	 *
	 * The point of the salt is to ensure that a given user creates
	 * different cookies on different machines, so that nobody
	 * can after the fact figure out a single user has used both
	 * machines.
	 *
	 * @param User $user
	 * @param $cookieRecord
	 * @return bool
	 */
	private function isUserRecordGivenCookie( User $user, $cookieRecord ) {
		if ( !$this->validateCookieRecord( $cookieRecord ) ) {
			// Most callers will probably already check this, but
			// doesn't hurt to be careful.
			return false;
		}
		$parts = explode( "-", $cookieRecord, 3 );
		$hash = $this->generateUserCookieRecord( $user->getName(), $parts[0], $parts[1] );
		return hash_equals( $hash, $cookieRecord );
	}

	/**
	 * Check if cookie is valid (Is not too old, has 3 fields)
	 *
	 * @param string $cookieRecord Cookie record
	 * @return bool true if valid
	 */
	private function validateCookieRecord( $cookieRecord ) {
		$parts = explode( "-", $cookieRecord, 3 );
		if ( count( $parts ) !== 3 || strlen( $parts[0] ) !== 4 ) {
			$this->log->warning( "Got cookie with invalid format",
				[
					'method' => __METHOD__,
					'cookieRecord' => $cookieRecord
				]
			);
			return false;
		}
		if ( (int)$parts[0] < gmdate( 'Y' ) - 3 ) {
			// Record is too old. If user hasn't logged in from this
			// computer in two years, should probably not consider it trusted.
			return false;
		}
		return true;
	}

	/**
	 * Generate a single record for use in the previous login cookie
	 *
	 * The format is YYYY-SSSSSSS-HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
	 * where Y is the year, S is a 32-bit salt, H is an sha1-hmac.
	 * Both S and H are base-36 encoded. The actual cookie consists
	 * of several of these records separated by a ".".
	 *
	 * When checking if a hash is valid, provide all three arguments.
	 * When generating a new hash, only use the first argument.
	 *
	 * @param string $username Username,
	 * @param int|bool $year int [Optional] Year. Default to current year
	 * @param string|bool $salt [Optional] Salt (expected to be base-36 encoded)
	 * @return string A record for the cookie
	 */
	private function generateUserCookieRecord( $username, $year = false, $salt = false ) {
		if ( $year === false ) {
			$year = gmdate( 'Y' );
		}

		if ( $salt === false ) {
			$salt = $this->gSalt;
		}

		// FIXME Maybe shorten, e.g. User only half the hash?
		$res = hash_hmac( 'sha1', $username . '|' . $year . $salt, $this->secret );
		if ( !is_string( $res ) ) {
			throw new UnexpectedValueException( "Hash failed" );
		}
		$encoded = $year . '-' . $salt . '-' . \Wikimedia\base_convert( $res, 16, 36 );
		return $encoded;
	}

	/**
	 * Get the cache key for the counter.
	 *
	 * @param $user User
	 * @param $type string 'known' or 'new'
	 * @return string The cache key
	 */
	private function getKey( User $user, $type ) {
		$userHash = \Wikimedia\base_convert( sha1( $user->getName() ), 16, 36, 31 );
		return $this->cache->makeGlobalKey(
			'loginnotify', $type, $userHash
		);
	}

	/**
	 * Increment hit counters for a failed login from an unknown computer.
	 *
	 * If a sufficient number of hits have accumulated, send an echo notice.
	 *
	 * @param User $user
	 */
	private function recordLoginFailureFromUnknownSystem( User $user ) {
		$key = $this->getKey( $user, 'new' );
		$count = $this->checkAndIncKey(
			$key,
			$this->config->get( 'LoginNotifyAttemptsNewIP' ),
			$this->config->get( 'LoginNotifyExpiryNewIP' )
		);
		if ( $count ) {
			$this->incrStats( 'fail.unknown.notifications' );
			$this->sendNotice( $user, 'login-fail-new', $count );
		}
	}

	/**
	 * Increment hit counters for a failed login from a known computer.
	 *
	 * If a sufficient number of hits have accumulated, send an echo notice.
	 *
	 * @param User $user
	 */
	private function recordLoginFailureFromKnownSystem( User $user ) {
		$key = $this->getKey( $user, 'known' );
		$count = $this->checkAndIncKey(
			$key,
			$this->config->get( 'LoginNotifyAttemptsKnownIP' ),
			$this->config->get( 'LoginNotifyExpiryKnownIP' )
		);
		if ( $count ) {
			$this->incrStats( 'fail.known.notifications' );
			$this->sendNotice( $user, 'login-fail-known', $count );
		}
	}

	/**
	 * Send a notice about login attempts
	 *
	 * @param User $user The account in question
	 * @param string $type 'login-fail-new' or 'login-fail-known'
	 * @param int $count [Optional] How many failed attempts
	 */
	private function sendNotice( User $user, $type, $count = null ) {
		$extra = [ 'notifyAgent' => true ];
		if ( $count !== null ) {
			$extra['count'] = $count;
		}
		EchoEvent::create( [
			'type' => $type,
			'extra' => $extra,
			'agent' => $user,
		] );

		$this->log->info( 'Sending a {type} notification to {user}',
			[
				'function' => __METHOD__,
				'type' => $type,
				'user' => $user->getName(),
			]
		);
	}

	/**
	 * Check if we've reached limit, and increment cache key.
	 *
	 * @param string $key cache key
	 * @param int $interval The interval of one to send notice
	 * @param int $expiry When to expire cache key.
	 * @return bool|int false to not send notice, or number of hits
	 */
	private function checkAndIncKey( $key, $interval, $expiry ) {
		$cache = $this->cache;
		$cur = $cache->incr( $key );
		if ( !$cur ) {
			$cache->add( $key, 1, $expiry );
			$cur = 1;
		}
		if ( $cur % $interval === 0 ) {
			return $cur;
		}
		return false;
	}

	/**
	 * Clear attempt counter for user.
	 *
	 * When a user successfully logs in, we start back from 0, as
	 * otherwise a mistake here and there will trigger the warning.
	 *
	 * @param User $user The user for whom to clear the attempt counter.
	 */
	public function clearCounters( User $user ) {
		$cache = $this->cache;
		$keyKnown = $this->getKey( $user, 'known' );
		$keyNew = $this->getKey( $user, 'new' );

		$cache->delete( $keyKnown );
		$cache->delete( $keyNew );
	}

	/**
	 * On login failure, record failure and maybe send notice
	 *
	 * @param User $user User in question
	 */
	public function recordFailure( User $user ) {
		$this->incrStats( 'fail.total' );

		if ( $user->isAnon() ) {
			// Login failed because user doesn't exist
			// skip this user.
			$this->log->debug( "Skipping recording failure for {user} - no account",
				[ 'user' => $user->getName() ]
			);
			return;
		}

		$known = $this->isKnownSystemFast( $user, $user->getRequest() );
		if ( $known === self::USER_KNOWN ) {
			$this->recordLoginFailureFromKnownSystem( $user );
		} else {
			$this->createJob( DeferredChecksJob::TYPE_LOGIN_FAILED,
				$user, $user->getRequest(), $known
			);
		}
	}

	/**
	 * Asynchronous part of recordFailure(), to be called from DeferredChecksJob
	 *
	 * @param User $user User in question
	 * @param string $subnet User's current subnet
	 * @param string $resultSoFar Value returned by isKnownSystemFast()
	 */
	public function recordFailureDeferred( User $user, $subnet, $resultSoFar ) {
		$isKnown = $this->isKnownSystemSlow( $user, $subnet, $resultSoFar );
		if ( !$isKnown ) {
			$this->recordLoginFailureFromUnknownSystem( $user );
		}
	}

	/**
	 * Send a notice on successful login from an unknown IP
	 *
	 * @param User $user User account in question.
	 */
	public function sendSuccessNotice( User $user ) {
		if ( !$this->config->get( 'LoginNotifyEnableOnSuccess' ) ) {
			return;
		}
		$this->incrStats( 'success.total' );
		$result = $this->isKnownSystemFast( $user, $user->getRequest() );
		if ( $result !== self::USER_KNOWN ) {
			$this->createJob( DeferredChecksJob::TYPE_LOGIN_SUCCESS,
				$user, $user->getRequest(), $result
			);
		}
	}

	/**
	 * Asynchronous part of sendSuccessNotice(), to be called from DeferredChecksJob
	 *
	 * @param User $user User in question
	 * @param string $subnet User's current subnet
	 * @param string $resultSoFar Value returned by isKnownSystemFast()
	 */
	public function sendSuccessNoticeDeferred( User $user, $subnet, $resultSoFar ) {
		$isKnown = $this->isKnownSystemSlow( $user, $subnet, $resultSoFar );
		if ( !$isKnown ) {
			$this->incrStats( 'success.notifications' );
			$this->sendNotice( $user, 'login-success' );
		}
	}

	/**
	 * Creates and enqueues a job to do asynchronous processing of user login success/failure
	 *
	 * @param string $type Job type, one of DeferredChecksJob::TYPE_* constants
	 * @param User $user User in question
	 * @param WebRequest $request
	 * @param string $resultSoFar Value returned by isKnownSystemFast()
	 */
	private function createJob( $type, User $user, WebRequest $request, $resultSoFar ) {
		$subnet = $this->getIPNetwork( $request->getIP() );
		$job = new JobSpecification( 'LoginNotifyChecks',
			[
				'checkType' => $type,
				'userId' => $user->getId(),
				'subnet' => $subnet,
				'resultSoFar' => $resultSoFar,
			]
		);
		JobQueueGroup::singleton()->lazyPush( $job );

		$this->log->debug( 'Login {status}, creating a job to verify {user}, result so far: {result}',
			[
				'function' => __METHOD__,
				'status' => $type,
				'user' => $user->getName(),
				'result' => $resultSoFar,
			]
		);
	}

	/**
	 * Increments the given statistic
	 *
	 * @param string $metric
	 */
	private function incrStats( $metric ) {
		$this->stats->increment( "loginnotify.$metric" );
	}
}
