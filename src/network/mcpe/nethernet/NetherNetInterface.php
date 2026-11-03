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

use pocketmine\nethernet\crypto\CryptoException;
use pocketmine\nethernet\identity\ServerIdentity;
use pocketmine\network\AdvancedNetworkInterface;
use pocketmine\network\mcpe\compression\ZlibCompressor;
use pocketmine\network\mcpe\EntityEventBroadcaster;
use pocketmine\network\mcpe\NetworkSession;
use pocketmine\network\mcpe\PacketBroadcaster;
use pocketmine\network\mcpe\protocol\PacketPool;
use pocketmine\network\mcpe\ServerPongData;
use pocketmine\network\Network;
use pocketmine\network\NetworkInterfaceStartException;
use pocketmine\network\PacketHandlingException;
use pocketmine\Server;
use pocketmine\snooze\SleeperNotifier;
use pocketmine\timings\Timings;
use pocketmine\utils\BinaryStream;
use pocketmine\utils\Utils;
use Symfony\Component\Filesystem\Path;
use function bin2hex;
use function chmod;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function hash;
use function implode;
use function is_dir;
use function is_file;
use function mkdir;
use function substr;
use function umask;
use function unpack;
use const PHP_INT_MAX;

final class NetherNetInterface implements AdvancedNetworkInterface{
	private const TLS_CERT_FILE = "nethernet-cert.pem";
	private const TLS_KEY_FILE = "nethernet-key.pem";

	private NetherNetThread $thread;
	private NetherNetChannel $toThread;
	private NetherNetChannel $fromThread;
	private SleeperNotifier $sleeper;
	private const CONSUMPTION_REPORT_INTERVAL = 1024;
	private int $networkId;
	private ?Network $network = null;
	private PacketBroadcaster $packetBroadcaster;
	private EntityEventBroadcaster $entityEventBroadcaster;

	/** @var array<int, NetworkSession> */
	private array $sessions = [];

	/**
	 * @throws NetworkInterfaceStartException
	 */
	public function __construct(
		private Server $server,
		string $ip,
		int $port,
		string $identityKeyFile,
		PacketBroadcaster $packetBroadcaster,
		EntityEventBroadcaster $entityEventBroadcaster
	){
		$this->packetBroadcaster = $packetBroadcaster;
		$this->entityEventBroadcaster = $entityEventBroadcaster;
		$this->sleeper = new SleeperNotifier();
		$mainToThread = new \Threaded();
		$threadToMain = new \Threaded();
		$this->toThread = new NetherNetChannel($mainToThread);
		$this->fromThread = new NetherNetChannel($threadToMain);

		[$certificate, $key] = $this->findTlsFiles();
		$identityPem = $this->loadOrCreateIdentityPem($identityKeyFile);
		$this->networkId = self::networkIdOf($identityPem);
		try{
			$config = $this->server->getConfigGroup();
			$iceConfig = NetherNetIceConfiguration::parse(
				$config->getProperty("transport.nethernet.ice-servers", []),
				$config->getProperty("transport.nethernet.port-range", []),
				$config->getPropertyBool("transport.nethernet.ice-udp-mux", false)
			);
			$reverseProxyNetworks = null;
			if($config->getPropertyBool("transport.nethernet.reverse-proxy.enabled", false)){
				$reverseProxyNetworks = NetherNetThread::parseReverseProxyNetworks($config->getProperty("transport.nethernet.reverse-proxy.trusted-ips", []));
			}
		}catch(\InvalidArgumentException $e){
			throw new NetworkInterfaceStartException("Invalid NetherNet configuration: " . $e->getMessage(), 0, $e);
		}

		$this->thread = new NetherNetThread(
			$this->server->getLogger(),
			$mainToThread,
			$threadToMain,
			$ip,
			$port,
			$identityPem,
			$certificate,
			$key,
			$this->server->getConfigGroup()->getPropertyInt("network.max-mtu-size", 1492),
			$this->networkId,
			!$this->server->getOnlineMode(),
			$iceConfig,
			$reverseProxyNetworks,
			$this->sleeper
		);
	}

	public function start() : void{
		$this->server->getTickSleeper()->addNotifier($this->sleeper, function() : void{
			Timings::$connection->startTiming();
			try{
				$handled = 0;
				while($this->handleMessage()){
					if(++$handled % self::CONSUMPTION_REPORT_INTERVAL === 0){
						$this->thread->setConsumedBytes($this->fromThread->getTotalBytes());
					}
				}
				$this->thread->setConsumedBytes($this->fromThread->getTotalBytes());
			}finally{
				Timings::$connection->stopTiming();
			}
		});

		$this->server->getLogger()->debug("Waiting for NetherNet to start...");
		try{
			$this->thread->startAndWait();
		}catch(NetworkInterfaceStartException $e){
			$this->server->getTickSleeper()->removeNotifier($this->sleeper);
			$this->thread->quit();
			throw $e;
		}
		$this->server->getLogger()->debug("NetherNet booted successfully");
	}

	/**
	 * @throws NetworkInterfaceStartException
	 */
	private function loadOrCreateIdentityPem(string $identityKeyFile) : string{
		$path = Path::makeAbsolute($identityKeyFile, $this->server->getDataPath());
		if(is_file($path)){
			$pem = file_get_contents($path);
			if($pem === false){
				throw new NetworkInterfaceStartException("The NetherNet identity key at $path exists but could not be read");
			}
			try{
				ServerIdentity::fromPrivateKeyPem($pem);
			}catch(CryptoException $e){
				throw new NetworkInterfaceStartException("The NetherNet identity key at $path is invalid: " . $e->getMessage(), 0, $e);
			}

			return $pem;
		}

		try{
			$pem = ServerIdentity::generate()->exportPrivateKeyPem();
		}catch(CryptoException $e){
			throw new NetworkInterfaceStartException("Could not create a NetherNet identity: " . $e->getMessage(), 0, $e);
		}

		$directory = dirname($path);
		if(!is_dir($directory)){
			@mkdir($directory, 0700, true);
		}

		$previousUmask = umask(0077);
		try{
			$written = file_put_contents($path, $pem);
		}finally{
			umask($previousUmask);
		}
		if($written === false){
			$this->server->getLogger()->warning("Could not save the NetherNet identity key to $path; players will be prompted again after a restart");
		}else{
			@chmod($path, 0600);
		}

		return $pem;
	}

	/**
	 * @return array{?string, ?string}
	 */
	private function findTlsFiles() : array{
		$certificate = Path::join($this->server->getDataPath(), self::TLS_CERT_FILE);
		$key = Path::join($this->server->getDataPath(), self::TLS_KEY_FILE);
		if(!is_file($certificate) || !is_file($key)){
			$this->server->getLogger()->notice("NetherNet signaling will use plain HTTP; install " . self::TLS_CERT_FILE . " and " . self::TLS_KEY_FILE . " to enable HTTPS");
			return [null, null];
		}

		return [$certificate, $key];
	}

	public function tick() : void{
		if(!$this->thread->isRunning()){
			throw new \RuntimeException("NetherNet thread stopped unexpectedly" . ($this->thread->getFailure() !== null ? ": " . $this->thread->getFailure() : ""));
		}
	}

	private function handleMessage() : bool{
		$message = $this->fromThread->read();
		if($message === null){
			return false;
		}

		$reader = new BinaryStream($message);
		$type = $reader->getByte();
		$sessionId = $reader->getUnsignedVarInt();

		switch($type){
			case NetherNetIpc::T2M_SESSION_OPEN:
				$address = $reader->get($reader->getUnsignedVarInt());
				$port = $reader->getUnsignedVarInt();
				$publicKeyDigest = self::readRemaining($reader);
				$this->openSession($sessionId, $address, $port, $publicKeyDigest);
				break;
			case NetherNetIpc::T2M_PACKET:
				$this->handlePacket($sessionId, self::readRemaining($reader));
				break;
			case NetherNetIpc::T2M_SESSION_CLOSE:
				$reason = \pocketmine\nethernet\session\DisconnectReason::tryFrom($reader->getUnsignedVarInt());
				$session = $this->sessions[$sessionId] ?? null;
				unset($this->sessions[$sessionId]);
				$session?->onClientDisconnect(self::disconnectReason($reason));
				break;
			case NetherNetIpc::T2M_BANDWIDTH_STATS:
				$this->getNetwork()->getBandwidthTracker()->add($reader->getUnsignedVarLong(), $reader->getUnsignedVarLong());
				break;
			default:
				throw new \UnexpectedValueException("Unknown NetherNet IPC message type $type");
		}

		return true;
	}

	private static function disconnectReason(?\pocketmine\nethernet\session\DisconnectReason $reason) : string{
		if($reason === null){
			return "Unknown NetherNet disconnect reason";
		}
		if($reason === \pocketmine\nethernet\session\DisconnectReason::PEER_DISCONNECT){
			return "Client disconnected";
		}

		return "NetherNet: " . $reason->getMessage();
	}

	private static function readRemaining(BinaryStream $stream) : string{
		return $stream->feof() ? "" : $stream->getRemaining();
	}

	private function openSession(int $sessionId, string $address, int $port, string $publicKeyDigest) : void{
		$session = new NetworkSession(
			$this->server,
			$this->server->getNetwork()->getSessionManager(),
			PacketPool::getInstance(),
			new NetherNetPacketSender($sessionId, $this),
			$this->packetBroadcaster,
			$this->entityEventBroadcaster,
			ZlibCompressor::getInstance(),
			$address,
			$port,
			$publicKeyDigest === "" ? null : $publicKeyDigest
		);
		$this->sessions[$sessionId] = $session;

		if($publicKeyDigest !== ""){
			$session->getLogger()->debug("NetherNet identity key " . bin2hex($publicKeyDigest));
		}
	}

	private function handlePacket(int $sessionId, string $payload) : void{
		$session = $this->sessions[$sessionId] ?? null;
		if($session === null){
			return;
		}

		$name = $session->getDisplayName();
		try{
			$session->handleEncoded($payload);
		}catch(PacketHandlingException $e){
			$logger = $session->getLogger();
			$logger->error("Bad packet: " . $e->getMessage());
			$logger->debug(implode("\n", Utils::printableExceptionInfo($e)));
			$session->disconnect("Bad packet: " . $e->getMessage());
		}catch(\Throwable $e){
			$this->server->getLogger()->emergency("Crash occurred while handling a packet from session: $name");
			throw $e;
		}
	}

	public function putPacket(int $sessionId, string $payload) : void{
		if(isset($this->sessions[$sessionId])){
			$this->toThread->write(NetherNetIpc::send($sessionId, $payload));
		}
	}

	public function close(int $sessionId) : void{
		if(isset($this->sessions[$sessionId])){
			unset($this->sessions[$sessionId]);
			$this->toThread->write(NetherNetIpc::closeSession($sessionId));
		}
	}

	public function setName(string $name) : void{
		$this->toThread->write(NetherNetIpc::setServerData(ServerPongData::build($this->server, $name, $this->networkId)));
	}

	public function setNetwork(Network $network) : void{
		$this->network = $network;
	}

	private function getNetwork() : Network{
		if($this->network === null){
			throw new \LogicException("NetherNet interface has not been registered with a network");
		}

		return $this->network;
	}

	public function blockAddress(string $address, int $timeout = 300) : void{
		$this->toThread->write(NetherNetIpc::blockAddress($address, $timeout));
	}

	public function unblockAddress(string $address) : void{
		$this->toThread->write(NetherNetIpc::unblockAddress($address));
	}

	public function sendRawPacket(string $address, int $port, string $payload) : void{
		throw new \BadMethodCallException("NetherNet does not support raw packet sending");
	}

	public function addRawPacketFilter(string $regex) : void{
		// NetherNet has no raw packet channel to filter.
	}

	private static function networkIdOf(string $identityPem) : int{
		$digest = hash("sha256", $identityPem, true);
		$id = unpack("P", substr($digest, 0, 8));

		return $id === false ? 1 : (($id[1] & PHP_INT_MAX) | 1);
	}

	public function shutdown() : void{
		$this->server->getTickSleeper()->removeNotifier($this->sleeper);
		$this->thread->quit();
	}
}
