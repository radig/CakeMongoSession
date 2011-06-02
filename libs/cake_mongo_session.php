<?php
if (!class_exists('Security')) {
	App::import('Core', 'Security');
}

class CakeMongoSession extends Object
{
	/**
 * True if the Session is still valid
 *
 * @var boolean
 * @access public
 */
	public $valid = false;

/**
 * Error messages for this session
 *
 * @var array
 * @access public
 */
	public $error = false;

/**
 * User agent string
 *
 * @var string
 * @access protected
 */
	protected $_userAgent = '';

/**
 * Path to where the session is active.
 *
 * @var string
 * @access public
 */
	public $path = '/';

/**
 * Error number of last occurred error
 *
 * @var integer
 * @access public
 */
	public $lastError = null;

/**
 * 'Security.level' setting, "high", "medium", or "low".
 *
 * @var string
 * @access public
 */
	public $security = null;

/**
 * Start time for this session.
 *
 * @var integer
 * @access public
 */
	public $time = false;

/**
 * Time when this session becomes invalid.
 *
 * @var integer
 * @access public
 */
	public $sessionTime = false;

/**
 * The number of seconds to set for session.cookie_lifetime.  0 means
 * at browser close.
 *
 * @var integer
 */
	public $cookieLifeTime = false;

/**
 * Keeps track of keys to watch for writes on
 *
 * @var array
 * @access public
 */
	public $watchKeys = array();

/**
 * Current Session id
 *
 * @var string
 * @access public
 */
	public $id = null;

/**
 * Hostname
 *
 * @var string
 * @access public
 */
	public $host = null;

/**
 * Session timeout multiplier factor
 *
 * @var integer
 * @access public
 */
	public $timeout = null;
	
/**
 * Lib MongoSession
 * 
 * @var Mongo
 * @access protected
 */
	protected $_mongo = null;

/**
 * Conection with database
 * 
 * @var Object
 * @access protected
 */
	protected $_connections = null;
	
/**
 * 
 * 
 * @var array
 * @access protected
 */
	protected $_settings = array(
		'database' => null,
		'collection' => null,	
		'servers' => array(
			array(
				'host' => null,
				'port' => null,
				'username' => null,
				'password' => null,
			)
		),
		'persistent' => null,
		'persistentId' => null,
		'replicaSet' => null
	);
	
	public function __construct($base = null, $start = true)
	{
		App::import('Core', array('Set', 'Security'));
		$this->time = time();

		if (Configure::read('Session.checkAgent') === true || Configure::read('Session.checkAgent') === null)
		{
			if (env('HTTP_USER_AGENT') != null)
			{
				$this->_userAgent = md5(env('HTTP_USER_AGENT') . Configure::read('Security.salt'));
			}
		}
		
		$this->_settings = Set::merge($this->_settings, Configure::read('MongoSession'));
		
		if ($start === true)
		{
			if (!empty($base))
			{
				$this->path = $base;
				
				if (strpos($base, 'index.php') !== false)
				{
				   $this->path = str_replace('index.php', '', $base);
				}
				
				if (strpos($base, '?') !== false)
				{
				   $this->path = str_replace('?', '', $base);
				}
			}
			
			$this->host = env('HTTP_HOST');

			if (strpos($this->host, ':') !== false)
			{
				$this->host = substr($this->host, 0, strpos($this->host, ':'));
			}
		}
		
		if (isset($_SESSION) || $start === true)
		{
			$this->sessionTime = $this->time + (Security::inactiveMins() * Configure::read('Session.timeout'));
			$this->security = Configure::read('Security.level');
		}
		
		parent::__construct();
	}
	
/**
 * Starts the Session.
 *
 * @return boolean True if session was started
 * @access public
 */
	public function start() {
		if ($this->started()) {
			return true;
		}
		if (function_exists('session_write_close')) {
			session_write_close();
		}
		$this->__initSession();
		$this->__startSession();
		return $this->started();
	}

/**
 * Determine if Session has been started.
 *
 * @access public
 * @return boolean True if session has been started.
 */
	public function started() {
		if (isset($_SESSION) && session_id()) {
			return true;
		}
		return false;
	}

/**
 * Returns true if given variable is set in session.
 *
 * @param string $name Variable name to check for
 * @return boolean True if variable is there
 * @access public
 */
	public function check($name) {
		if (empty($name)) {
			return false;
		}
		$result = Set::classicExtract($_SESSION, $name);
		return isset($result);
	}

/**
 * Returns the Session id
 *
 * @param id $name string
 * @return string Session id
 * @access public
 */
	public function id($id = null) {
		if ($id) {
			$this->id = $id;
			session_id($this->id);
		}
		if ($this->started()) {
			return session_id();
		} else {
			return $this->id;
		}
	}

/**
 * Removes a variable from session.
 *
 * @param string $name Session variable to remove
 * @return boolean Success
 * @access public
 */
	public function delete($name) {
		if ($this->check($name)) {
			if (in_array($name, $this->watchKeys)) {
				trigger_error(sprintf(__('Deleting session key {%s}', true), $name), E_USER_NOTICE);
			}
			$this->__overwrite($_SESSION, Set::remove($_SESSION, $name));
			return ($this->check($name) == false);
		}
		$this->__setError(2, sprintf(__("%s doesn't exist", true), $name));
		return false;
	}

/**
 * Returns last occurred error as a string, if any.
 *
 * @return mixed Error description as a string, or false.
 * @access public
 */
	private function error() {
		if ($this->lastError) {
			return $this->__error($this->lastError);
		} else {
			return false;
		}
	}

/**
 * Returns true if session is valid.
 *
 * @return boolean Success
 * @access public
 */
	public function valid() {
		if ($this->read('Config')) {
			if ((Configure::read('Session.checkAgent') === false || $this->_userAgent == $this->read('Config.userAgent')) && $this->time <= $this->read('Config.time')) {
				if ($this->error === false) {
					$this->valid = true;
				}
			} else {
				$this->valid = false;
				$this->__setError(1, 'Session Highjacking Attempted !!!');
			}
		}
		return $this->valid;
	}

/**
 * Returns given session variable, or all of them, if no parameters given.
 *
 * @param mixed $name The name of the session variable (or a path as sent to Set.extract)
 * @return mixed The value of the session variable
 * @access public
 */
	public function read($name = null) {
		if (is_null($name)) {
			return $this->__returnSessionVars();
		}
		if (empty($name)) {
			return false;
		}
		$result = Set::classicExtract($_SESSION, $name);

		if (!is_null($result)) {
			return $result;
		}
		$this->__setError(2, "$name doesn't exist");
		return null;
	}

/**
 * Tells Session to write a notification when a certain session path or subpath is written to
 *
 * @param mixed $var The variable path to watch
 * @return void
 * @access public
 */
	public function watch($var) {
		if (empty($var)) {
			return false;
		}
		if (!in_array($var, $this->watchKeys, true)) {
			$this->watchKeys[] = $var;
		}
	}

/**
 * Tells Session to stop watching a given key path
 *
 * @param mixed $var The variable path to watch
 * @return void
 * @access public
 */
	public function ignore($var) {
		if (!in_array($var, $this->watchKeys)) {
			return;
		}
		foreach ($this->watchKeys as $i => $key) {
			if ($key == $var) {
				unset($this->watchKeys[$i]);
				$this->watchKeys = array_values($this->watchKeys);
				return;
			}
		}
	}

/**
 * Writes value to given session variable name.
 *
 * @param mixed $name Name of variable
 * @param string $value Value to write
 * @return boolean True if the write was successful, false if the write failed
 * @access public
 */
	public function write($name, $value) {
		if (empty($name)) {
			return false;
		}
		if (in_array($name, $this->watchKeys)) {
			trigger_error(sprintf(__('Writing session key {%s}: %s', true), $name, Debugger::exportVar($value)), E_USER_NOTICE);
		}
		$this->__overwrite($_SESSION, Set::insert($_SESSION, $name, $value));
		return (Set::classicExtract($_SESSION, $name) === $value);
	}

/**
 * Helper method to destroy invalid sessions.
 *
 * @return void
 * @access public
 */
	public function destroy() {
		if ($this->started()) {
			session_destroy();
		}
		$_SESSION = null;
		$this->__construct($this->path);
		$this->start();
		$this->renew();
		$this->_checkValid();
	}

/**
 * Restarts this session.
 *
 * @access public
 */
	private function renew() {
		$this->__regenerateId();
	}
	
	/**
	 * Create a global lock for the specified document.
	 *
	 * @author	Benson Wong (mostlygeek@gmail.com)
	 * @access	protected
	 * @param	string	$id
	 */
	protected function _lock($id)
	{
//		$remaining = 30000000;
		$remaining = 10000;
		$timeout = 5000;
		
		do {
			
			try {
				$query = array('session_id' => $id, 'lock' => 0);
				$update = array('$set' => array('lock' => 1));
				$options = array('safe' => true, 'upsert' => true);
				
				$result = $this->_mongo->update($query, $update, $options);
				
				if ($result['ok'] == 1)
				{
					return true;
				}
			}
			catch (MongoException $e)
			{
				if ($e->getCode() != 11000)
				{
					throw $e; // Not duplicate index
				}
			}
			
			// force delay in microseconds
			usleep($timeout);
			$remaining -= $timeout;
			
			// backoff on timeout, save a tree. max wait 1 second
			$timeout = ($timeout < 1000000) ? $timeout * 2 : 1000000;
		
		} while ($remaining > 0);
		
		// aww shit.
		//throw new Exception('Could not obtain a session lock.');
	}

	private function __initSession()
	{
		$iniSet = function_exists('ini_set');
		if ($iniSet && env('HTTPS')) {
			ini_set('session.cookie_secure', 1);
		}
		if ($iniSet && ($this->security === 'high' || $this->security === 'medium')) {
			ini_set('session.referer_check', $this->host);
		}

		if ($this->security == 'high')
		{
			$this->cookieLifeTime = 0;
		}
		else
		{
			$this->cookieLifeTime = Configure::read('Session.timeout') * (Security::inactiveMins() * 60);
		}

		if ($iniSet)
		{
			ini_set('session.use_trans_sid', 0);
			ini_set('url_rewriter.tags', '');
			ini_set('session.save_handler', 'user');
			ini_set('session.serialize_handler', 'php');
			ini_set('session.use_cookies', 1);
			ini_set('session.name', Configure::read('Session.cookie'));
			ini_set('session.cookie_lifetime', $this->cookieLifeTime);
			ini_set('session.cookie_path', $this->path);
			ini_set('session.auto_start', 0);
		}
		
		session_set_save_handler(
			array('CakeMongoSession','__open'),
			array('CakeMongoSession', '__close'),
			array('CakeMongoSession', '__read'),
			array('CakeMongoSession', '__write'),
			array('CakeMongoSession', '__destroy'),
			array('CakeMongoSession', '__gc')
		);
		
		$this->__initMongoSession();
	}
	
	private function __initMongoSession()
	{
		// generate server connection strings
		$connections = array();
		
		if (!empty($this->_settings['servers']))
		{
			foreach ($this->_settings['servers'] as $server)
			{
				$str = '';
				if (!empty($server['username']) && !empty($server['password']))
				{
					$str .= $server['username'] . ':' . $server['password'] . '@';
				}
				
				$str .= !empty($server['host']) ? $server['host'] : Mongo::DEFAULT_HOST;
				$str .= ':' . (!empty($server['port']) ? (int) $server['port'] : Mongo::DEFAULT_PORT);
				array_push($connections, $str);
			}
		} else {
			// use default connection settings
			array_push($connections, Mongo::DEFAULT_HOST . ':' . Mongo::DEFAULT_PORT);
		}
		
		// add immediate connection
		$opts = array('connect' => true);
		
		// support persistent connections
		if ($this->_settings['persistent'] && !empty($this->_settings['persistentId']))
		{
			$opts['persist'] = $this->_settings['persistentId'];
		}
		
		// support replica sets
		if ($this->_settings['replicaSet'])
		{
			$opts['replicaSet'] = true;
		}
		
		// load mongo server connection
		try {
			$this->_connection = new Mongo('mongodb://' . implode(',', $connections), $opts);
		} catch (Exception $e) {
			throw new Exception('Can\'t connect to the MongoDB server.');
		}
		
		// load the db
		try {
			$mongo = $this->_connection->selectDB($this->_settings['database']);
		} catch (InvalidArgumentException $e) {
			throw new Exception('The MongoDB database specified in the config does not exist.');
		}
        
		// load collection
		try {
			$this->_mongo = $mongo->selectCollection($this->_settings['collection']);
		} catch(Exception $e) {
			throw new Exception('The MongoDB collection specified in the config does not exist.');
		}
		
		// proper indexing on the expiration
		$this->_mongo->ensureIndex(
			array('expiry' => 1),
			array('name' => 'expiry',
					'unique' => true,
					'dropDups' => true,
					'safe' => true
			)
		);
		
		// proper indexing of session id and lock
		$this->_mongo->ensureIndex(
			array('session_id' => 1, 'lock' => 1),
			array('name' => 'session_id',
				'unique' => true,
				'dropDups' => true,
				'safe' => true
			)
		);
	}
	
/**
 * Helper method to start a session
 *
 * @access public
 */
	public function __startSession() {
		if (headers_sent()) {
			if (empty($_SESSION)) {
				$_SESSION = array();
			}
			return true;
		} elseif (!isset($_SESSION)) {
			session_cache_limiter ("must-revalidate");
			session_start();
			header ('P3P: CP="NOI ADM DEV PSAi COM NAV OUR OTRo STP IND DEM"');
			return true;
		} else {
			session_start();
			return true;
		}
	}
	
/**
 * Helper method to create a new session.
 *
 * @return void
 * @access protected
 */
	protected function _checkValid() {
		if ($this->read('Config')) {
			if ((Configure::read('Session.checkAgent') === false || $this->_userAgent == $this->read('Config.userAgent')) && $this->time <= $this->read('Config.time')) {
				$time = $this->read('Config.time');
				$this->write('Config.time', $this->sessionTime);
				if (Configure::read('Security.level') === 'high') {
					$check = $this->read('Config.timeout');
					$check -= 1;
					$this->write('Config.timeout', $check);

					if (time() > ($time - (Security::inactiveMins() * Configure::read('Session.timeout')) + 2) || $check < 1) {
						$this->renew();
						$this->write('Config.timeout', 10);
					}
				}
				$this->valid = true;
			} else {
				$this->destroy();
				$this->valid = false;
				$this->__setError(1, 'Session Highjacking Attempted !!!');
			}
		} else {
			$this->write('Config.userAgent', $this->_userAgent);
			$this->write('Config.time', $this->sessionTime);
			$this->write('Config.timeout', 10);
			$this->valid = true;
			$this->__setError(1, 'Session is valid');
		}
	}

/**
 * Used to write new data to _SESSION, since PHP doesn't like us setting the _SESSION var itself
 *
 * @param array $old Set of old variables => values
 * @param array $new New set of variable => value
 * @access private
 */
	private function __overwrite(&$old, $new) {
		if (!empty($old)) {
			foreach ($old as $key => $var) {
				if (!isset($new[$key])) {
					unset($old[$key]);
				}
			}
		}
		foreach ($new as $key => $var) {
			$old[$key] = $var;
		}
	}

/**
 * Return error description for given error number.
 *
 * @param integer $errorNumber Error to set
 * @return string Error as string
 * @access private
 */
	private function __error($errorNumber) {
		if (!is_array($this->error) || !array_key_exists($errorNumber, $this->error)) {
			return false;
		} else {
			return $this->error[$errorNumber];
		}
	}	

/**
 * Helper method to set an internal error message.
 *
 * @param integer $errorNumber Number of the error
 * @param string $errorMessage Description of the error
 * @return void
 * @access private
 */
	private function __setError($errorNumber, $errorMessage)
	{
		if ($this->error === false)
		{
			$this->error = array();
		}
		
		$this->error[$errorNumber] = $errorMessage;
		$this->lastError = $errorNumber;
	}
	
/**
 * Returns all session variables.
 *
 * @return mixed Full $_SESSION array, or false on error.
 * @access private
 */
	private function __returnSessionVars() {
		if (!empty($_SESSION)) {
			return $_SESSION;
		}
		
		$this->__setError(2, "No Session vars set");
		return false;
	}

/**
 * Method called on open of a database session.
 *
 * @return boolean Success
 * @access private
 */
	public function __open() {
		return true;
	}

/**
 * Method called on close of a database session.
 *
 * @return boolean Success
 * @access private
 */
	private function __close()
	{
		CakeMongoSession::__gc();
		return true;
	}

/**
 * Method used to read from a database session.
 *
 * @param mixed $id The key of the value to read
 * @return mixed The value of the key or false if it does not exist
 * @access private
 */
	public function __read($id)
	{
		// obtain a read lock on the data, or subsequently wait for
		// the lock to be released
//		$this->_lock($id);

        // exclude results that are inactive or expired
        $result = $this->_mongo->findOne(
			array(
				'session_id'	=> $id,
				'expiry'    	=> array('$gte' => time()),
				'active'    	=> 1
			)
		);

        if (isset($result['data'])) {
            $this->_session = $result;
            return $result['data'];
        }

        return '';
	}

/**
 * Helper function called on write for database sessions.
 *
 * @param integer $id ID that uniquely identifies session in database
 * @param mixed $data The value of the data to be saved.
 * @return boolean True for successful write, false otherwise.
 * @access private
 */
	public function __write($id, $data)
	{
		if (!$id) {
			return false;
		}
		// create expires
        $expiry = time() + Configure::read('Session.timeout') * Security::inactiveMins();

        // create new session data
        $new_obj = array(
            'data'		=> $data,
			'lock'		=> 0,
            'active'		=> 1,
            'expiry'		=> $expiry
        );
        
        // check for existing session for merge
        if (!empty($this->_session))
        {
            $obj = (array) $this->_session;
            $new_obj = array_merge($obj, $new_obj);
        }

		// atomic update
		$query = array('session_id' => $id);
		
		// update options
		$options = array(
			'upsert' 	=> TRUE,
			'safe'		=> TRUE,
			'fsync'		=> TRUE
		);
  
		// perform the update or insert
		try {
			$result = $this->_mongo->update($query, array('$set' => $new_obj), $options);
			return $result['ok'] == 1;
		} catch (Exception $e) {
			return false;
		}
		
        return true;
	}

/**
 * Method called on the destruction of a database session.
 *
 * @param integer $id ID that uniquely identifies session in database
 * @return boolean True for successful delete, false otherwise.
 * @access private
 */
	public function __destroy($id)
	{
		$this->_mongo->remove(array('session_id' => $id), true);
		return true;
	}

/**
 * Helper function called on gc for database sessions.
 *
 * @param integer $expiry Timestamp (defaults to current time)
 * @return boolean Success
 * @access private
 */
	public function __gc($expiry = null)
	{
		if (!$expiry)
		{
			$expiry = time();
		}
		
		// define the query
		$query = array('expiry' => array('$lt' => $expiry));
		
		// specify the update vars
		$update = array('$set' => array('active' => 0));
		
		// update options
		$options = array(
			'multiple'	=> TRUE,
			'safe'		=> TRUE,
			'fsync'		=> TRUE
		);
		
		// update expired elements and set to inactive
		$this->_mongo->update($query, $update, $options);

		return true;
	}
	
	/**
	 * Solves issues with write() and close() throwing exceptions.
	 *
	 * @access	public
	 * @return	void
	 */
	public function __destruct()
	{
		session_write_close();
	}
}