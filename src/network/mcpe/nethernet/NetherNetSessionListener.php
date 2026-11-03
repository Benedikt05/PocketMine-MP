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

use pocketmine\nethernet\ServerEventListener;
use pocketmine\nethernet\session\DisconnectReason;
use pocketmine\nethernet\session\Reliability;
use pocketmine\nethernet\session\Session;
use pocketmine\nethernet\session\SessionException;
use function strlen;
use function strrpos;
use function substr;

final class NetherNetSessionListener implements ServerEventListener{
	private const MAX_BACKLOG_SIZE = 4 * 1024 * 1024;
	private const MAX_BACKLOG_MESSAGES = 32768;

	/** @var array<int, Session> */
	private array $sessions = [];

	/** @var array<int, int> */
	private array $lastBytesSent = [];

	/** @var array<int, int> */
	private array $lastBytesReceived = [];

	private int $bytesSentDiff = 0;
	private int $bytesReceivedDiff = 0;
	private int $consumedBytes = 0;

	public function __construct(
		private NetherNetChannel $out
	){}

	public function onSessionOpen(Session $session) : void{
		$id = $session->getId();
		$this->sessions[$id] = $session;
		$this->lastBytesSent[$id] = 0;
		$this->lastBytesReceived[$id] = 0;

		[$address, $port] = self::splitAddress($session->getRemoteAddress());
		$this->out->write(NetherNetIpc::sessionOpen(
			$id,
			$address,
			$port,
			$session->getIdentity()?->publicKey->getDigest() ?? ""
		));
	}

	public function onPacketReceive(Session $session, string $payload, Reliability $reliability) : void{
		$this->out->write(NetherNetIpc::packet($session->getId(), $payload));
	}

	public function canAcceptPackets() : bool{
		return $this->out->count() < self::MAX_BACKLOG_MESSAGES
			&& $this->out->getTotalBytes() - $this->consumedBytes < self::MAX_BACKLOG_SIZE;
	}

	public function setConsumedBytes(int $bytes) : void{
		$this->consumedBytes = $bytes;
	}

	public function onSessionClose(Session $session, DisconnectReason $reason) : void{
		$id = $session->getId();
		unset($this->sessions[$id], $this->lastBytesSent[$id], $this->lastBytesReceived[$id]);
		$this->out->write(NetherNetIpc::sessionClose($id, $reason->value));
	}

	public function send(int $sessionId, string $payload) : void{
		$session = $this->sessions[$sessionId] ?? null;
		if($session === null){
			return;
		}

		try{
			$session->send($payload);
		}catch(SessionException $e){
			$session->close(DisconnectReason::SEND_FAILED);

			return;
		}
	}

	public function close(int $sessionId, DisconnectReason $reason = DisconnectReason::SERVER_DISCONNECT) : void{
		($this->sessions[$sessionId] ?? null)?->initiateDisconnect($reason);
	}

	public function updateBandwidthStats() : void{
		foreach($this->sessions as $sessionId => $session){
			if($session->isClosed()){
				continue;
			}
			$bytesSent = $session->getBytesSent();
			$bytesReceived = $session->getBytesReceived();
			$this->bytesSentDiff += $bytesSent - $this->lastBytesSent[$sessionId];
			$this->bytesReceivedDiff += $bytesReceived - $this->lastBytesReceived[$sessionId];
			$this->lastBytesSent[$sessionId] = $bytesSent;
			$this->lastBytesReceived[$sessionId] = $bytesReceived;
		}
	}

	public function flushBandwidthStats() : void{
		if($this->bytesSentDiff > 0 || $this->bytesReceivedDiff > 0){
			$this->out->write(NetherNetIpc::bandwidthStats($this->bytesSentDiff, $this->bytesReceivedDiff));
			$this->bytesSentDiff = 0;
			$this->bytesReceivedDiff = 0;
		}
	}

	/**
	 * @return array{string, int}
	 */
	private static function splitAddress(?string $address) : array{
		if($address === null){
			return ["0.0.0.0", 0];
		}

		$separator = strrpos($address, ":");
		if($separator === false){
			return [$address, 0];
		}

		return [substr($address, 0, $separator), (int) substr($address, $separator + 1)];
	}
}
