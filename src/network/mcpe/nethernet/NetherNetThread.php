<?php

/*
 *
 *  ____            _        _   __  __ _                  __  __ ____
 * |  _ \ ___   ___| | _____| |_|  \/  (_)_ __   ___      |  \/  |  _ \
 * | |_) / _ \ / __| |/ / _ \ __| |\/| | | '_ \ / _ \_____| |\/| | |_) |
 * |  __/ (_) | (__|   <  __/ |_| |  | | | | | | |  __/_____| |  | |  __/
 * |_|   \___/ \___|_|\_\___|\__|_|  |_|_|_| |_|\___|     |_|  |_|_|
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * @author PocketMine Team
 * @link http://www.pocketmine.net/
 *
 *
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\nethernet;

use pocketmine\nethernet\discovery\LanSignaling;
use pocketmine\nethernet\discovery\MutableServerDataProvider;
use pocketmine\nethernet\discovery\ServerData;
use pocketmine\nethernet\identity\AssertionIdentityVerifier;
use pocketmine\nethernet\identity\SelfSignedIdentityProvider;
use pocketmine\nethernet\identity\ServerIdentity;
use pocketmine\nethernet\negotiation\ConfiguredPeerConnectionFactory;
use pocketmine\nethernet\NetherNetException;
use pocketmine\nethernet\NetherNetServer;
use pocketmine\nethernet\ServerConfiguration;
use pocketmine\nethernet\signaling\http\HttpSignaling;
use pocketmine\nethernet\signaling\http\MutableServerStatusProvider;
use pocketmine\nethernet\signaling\http\ReverseProxy;
use pocketmine\nethernet\signaling\SignalingException;
use pocketmine\network\NetworkInterfaceStartException;
use pocketmine\snooze\SleeperNotifier;
use pocketmine\thread\Thread;
use pocketmine\utils\BinaryStream;
use pocketmine\utils\Utils;
use function array_values;
use function get_debug_type;
use function is_array;
use function is_string;
use function microtime;
use function time_sleep_until;
use const PTHREADS_INHERIT_NONE;

final class NetherNetThread extends Thread{
	private const TPS = 100;
	private const TICK_DURATION = 1 / self::TPS;
	private const SHUTDOWN_DRAIN_TIMEOUT = 3.0;
	/** @var \ThreadedLogger */
	protected $logger;
	/** @var \Threaded */
	protected $mainToThread;
	/** @var \Threaded */
	protected $threadToMain;
	/** @var string */
	protected $ip;
	/** @var int */
	protected $port;
	/** @var string */
	protected $identityPem;
	/** @var string|null */
	protected $tlsCertFile;
	/** @var string|null */
	protected $tlsKeyFile;
	/** @var int */
	protected $maxMtu;
	/** @var int */
	protected $networkId;
	/** @var bool */
	protected $allowAnonymous;
	/** @var SleeperNotifier */
	protected $sleeperNotifier;
	/** @var NetherNetIceConfiguration */
	protected $iceConfig;
	/** @var \Threaded|null */
	protected $reverseProxyNetworks;
	/** @var int */
	protected $ticks = 0;
	/** @var int */
	protected $consumedBytes = 0;
	/** @var bool */
	protected $ready = false;
	/** @var string|null */
	protected $startupError = null;
	/** @var string|null */
	protected $failure = null;

	public function __construct(
		\ThreadedLogger $logger,
		\Threaded $mainToThread,
		\Threaded $threadToMain,
		string $ip,
		int $port,
		string $identityPem,
		?string $tlsCertFile,
		?string $tlsKeyFile,
		int $maxMtu,
		int $networkId,
		bool $allowAnonymous,
		NetherNetIceConfiguration $iceConfig,
		?\Threaded $reverseProxyNetworks,
		SleeperNotifier $sleeperNotifier
	){
		$this->logger = $logger;
		$this->mainToThread = $mainToThread;
		$this->threadToMain = $threadToMain;
		$this->ip = $ip;
		$this->port = $port;
		$this->identityPem = $identityPem;
		$this->tlsCertFile = $tlsCertFile;
		$this->tlsKeyFile = $tlsKeyFile;
		$this->maxMtu = $maxMtu;
		$this->networkId = $networkId;
		$this->allowAnonymous = $allowAnonymous;
		$this->iceConfig = $iceConfig;
		$this->reverseProxyNetworks = $reverseProxyNetworks;
		$this->sleeperNotifier = $sleeperNotifier;
	}

	/**
	 * @return \Threaded
	 */
	public static function parseReverseProxyNetworks(mixed $trustedIps) : \Threaded{
		if($trustedIps === null){
			$trustedIps = [];
		}elseif(!is_array($trustedIps)){
			throw new \InvalidArgumentException("Trusted IPs must be a list of addresses or CIDR blocks, got " . get_debug_type($trustedIps));
		}
		$networks = [];
		foreach(Utils::promoteKeys($trustedIps) as $index => $entry){
			if(!is_string($entry) || $entry === ""){
				throw new \InvalidArgumentException("Trusted IPs entry $index must be an address or CIDR block");
			}
			$networks[] = $entry;
		}
		self::createReverseProxy($networks);
		$result = new \Threaded();
		foreach($networks as $network){
			$result[] = $network;
		}

		return $result;
	}

	/**
	 * @param string[] $networks
	 */
	private static function createReverseProxy(array $networks) : ReverseProxy{
		return new ReverseProxy(
			[ReverseProxy::HEADER_FORWARDED_FOR, ReverseProxy::HEADER_REAL_IP, ReverseProxy::HEADER_CF_CONNECTING_IP],
			$networks
		);
	}

	public function setConsumedBytes(int $bytes) : void{
		$this->consumedBytes = $bytes;
	}

	/**
	 * @throws NetworkInterfaceStartException
	 */
	public function startAndWait(int $options = PTHREADS_INHERIT_NONE) : void{
		$this->start($options);
		$this->synchronized(function() : void{
			while(!$this->ready && !$this->isTerminated()){
				$this->wait();
			}
		});

		if($this->startupError !== null){
			throw new NetworkInterfaceStartException($this->startupError);
		}
	}

	protected function onRun() : void{
		try{
			$in = new NetherNetChannel($this->mainToThread);
			$out = new NetherNetChannel($this->threadToMain, $this->sleeperNotifier);
			$listener = new NetherNetSessionListener($out);
			$advert = new MutableServerDataProvider(new ServerData(serverName: "", levelName: ""));
			$status = new MutableServerStatusProvider();

			try{
				$server = $this->createServer($listener, $advert, $status, true);
				$server->start();
			}catch(SignalingException $e){
				$this->logger->warning("LAN discovery could not start (" . $e->getMessage() . "); continuing without it");
				$server = $this->createServer($listener, $advert, $status, false);
				$server->start();
			}
			$this->markReady();

			try{
				while(!$this->isKilled){
					$start = microtime(true);
					$listener->setConsumedBytes($this->consumedBytes);
					$server->tick();
					$this->handleInbound($in, $server, $listener, $advert, $status);
					$listener->updateBandwidthStats();
					if(++$this->ticks % self::TPS === 0){
						$listener->flushBandwidthStats();
					}
					self::sleepUntilNextTick($start);
				}
				$this->handleInbound($in, $server, $listener, $advert, $status);

				$deadline = microtime(true) + self::SHUTDOWN_DRAIN_TIMEOUT;
				while($server->getSessionManager()->count() > 0 && microtime(true) < $deadline){
					$start = microtime(true);
					$listener->setConsumedBytes($this->consumedBytes);
					$server->tick();
					self::sleepUntilNextTick($start);
				}
			}finally{
				$listener->updateBandwidthStats();
				$listener->flushBandwidthStats();
				$server->shutdown();
			}
		}catch(NetherNetException|\InvalidArgumentException $e){
			$this->markFailed($e->getMessage());
		}catch(\Throwable $e){
			$this->markFailed($e->getMessage());
			$this->logger->logException($e);
		}
	}

	/**
	 * @throws NetherNetException
	 */
	private function createServer(
		NetherNetSessionListener $listener,
		MutableServerDataProvider $advert,
		MutableServerStatusProvider $status,
		bool $enableLan
	) : NetherNetServer{
		$iceServers = [];
		foreach($this->iceConfig->getServers() as $iceServer){
			$iceServers[] = $iceServer->isTurn()
				? \pmmp\webrtc\IceServer::turn($iceServer->getHost(), $iceServer->getPort(), $iceServer->getUsername(), $iceServer->getPassword())
				: \pmmp\webrtc\IceServer::stun($iceServer->getHost(), $iceServer->getPort());
		}
		$server = NetherNetServer::create(
			new ServerConfiguration(
				identityProvider: new SelfSignedIdentityProvider(ServerIdentity::fromPrivateKeyPem($this->identityPem)),
				identityVerifier: new AssertionIdentityVerifier(allowAnonymous: $this->allowAnonymous),
				peerConnectionFactory: new ConfiguredPeerConnectionFactory(
					iceServers: $iceServers,
					portRangeBegin: $this->iceConfig->getPortRangeBegin(),
					portRangeEnd: $this->iceConfig->getPortRangeEnd(),
					iceUdpMuxEnabled: $this->iceConfig->isUdpMux(),
					mtu: $this->maxMtu
				),
				logger: $this->logger
			),
			$listener
		);

		$tlsContext = $this->tlsCertFile !== null && $this->tlsKeyFile !== null
			? ["local_cert" => $this->tlsCertFile, "local_pk" => $this->tlsKeyFile]
			: null;
		$reverseProxy = $this->reverseProxyNetworks !== null
			? self::createReverseProxy(array_values((array) $this->reverseProxyNetworks))
			: null;
		$server->addSignaling(new HttpSignaling(
			$server->getNegotiator(),
			$this->ip,
			$this->port,
			$tlsContext,
			$this->logger,
			HttpSignaling::DEFAULT_MAX_CONNECTIONS,
			$status,
			$reverseProxy
		));
		if($enableLan){
			$server->addSignaling(new LanSignaling(
				$server->getNegotiator(),
				$advert,
				$this->networkId,
				"0.0.0.0",
				LanSignaling::DEFAULT_PORT,
				$this->logger
			));
		}

		return $server;
	}

	private function handleInbound(
		NetherNetChannel $in,
		NetherNetServer $server,
		NetherNetSessionListener $listener,
		MutableServerDataProvider $advert,
		MutableServerStatusProvider $status
	) : void{
		while(($message = $in->read()) !== null){
			$reader = new BinaryStream($message);
			$type = $reader->getByte();
			if($type === NetherNetIpc::M2T_SET_SERVER_DATA){
				$pong = self::readRemaining($reader);
				$data = ServerData::fromPongData($pong);
				if($data !== null){
					$advert->setServerData($data);
				}
				$status->setPongData($pong);
				continue;
			}

			if($type === NetherNetIpc::M2T_BLOCK_ADDRESS){
				$address = $reader->get($reader->getUnsignedVarInt());
				$server->blockAddress($address, $reader->getVarInt());
				continue;
			}

			if($type === NetherNetIpc::M2T_UNBLOCK_ADDRESS){
				$server->unblockAddress($reader->get($reader->getUnsignedVarInt()));
				continue;
			}

			$sessionId = $reader->getUnsignedVarInt();
			if($type === NetherNetIpc::M2T_CLOSE_SESSION){
				$listener->close($sessionId);
				continue;
			}
			if($type !== NetherNetIpc::M2T_SEND){
				throw new \UnexpectedValueException("Unknown NetherNet IPC message type $type");
			}

			$reader->getUnsignedVarInt();
			$listener->send($sessionId, self::readRemaining($reader));
		}
	}

	private static function readRemaining(BinaryStream $stream) : string{
		return $stream->feof() ? "" : $stream->getRemaining();
	}

	private static function sleepUntilNextTick(float $start) : void{
		if(microtime(true) - $start < self::TICK_DURATION){
			@time_sleep_until($start + self::TICK_DURATION);
		}
	}

	private function markReady() : void{
		$this->synchronized(function() : void{
			$this->ready = true;
			$this->notify();
		});
	}

	private function markFailed(string $message) : void{
		$this->synchronized(function() use ($message) : void{
			if(!$this->ready){
				$this->startupError = $message;
				$this->ready = true;
				$this->notify();
			}else{
				$this->failure = $message;
			}
		});
	}

	public function getFailure() : ?string{
		return $this->synchronized(fn() => $this->failure);
	}

	public function getThreadName() : string{
		return "NetherNet";
	}
}
