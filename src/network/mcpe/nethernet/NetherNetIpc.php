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

use pocketmine\utils\BinaryStream;
use function strlen;

final class NetherNetIpc{
	public const T2M_SESSION_OPEN = 0;
	public const T2M_PACKET = 1;
	public const T2M_SESSION_CLOSE = 2;
	public const T2M_BANDWIDTH_STATS = 3;

	public const M2T_SEND = 0;
	public const M2T_CLOSE_SESSION = 1;
	public const M2T_SET_SERVER_DATA = 2;
	public const M2T_BLOCK_ADDRESS = 3;
	public const M2T_UNBLOCK_ADDRESS = 4;

	private function __construct(){}

	public static function setServerData(string $pongData) : string{
		$out = new BinaryStream();
		$out->putByte(self::M2T_SET_SERVER_DATA);
		$out->put($pongData);

		return $out->getBuffer();
	}

	public static function sessionOpen(int $sessionId, string $address, int $port, string $publicKeyDigest) : string{
		$out = new BinaryStream();
		$out->putByte(self::T2M_SESSION_OPEN);
		$out->putUnsignedVarInt($sessionId);
		$out->putUnsignedVarInt(strlen($address));
		$out->put($address);
		$out->putUnsignedVarInt($port);
		$out->put($publicKeyDigest);

		return $out->getBuffer();
	}

	public static function packet(int $sessionId, string $payload) : string{
		$out = new BinaryStream();
		$out->putByte(self::T2M_PACKET);
		$out->putUnsignedVarInt($sessionId);
		$out->put($payload);

		return $out->getBuffer();
	}

	public static function sessionClose(int $sessionId, int $reason) : string{
		$out = new BinaryStream();
		$out->putByte(self::T2M_SESSION_CLOSE);
		$out->putUnsignedVarInt($sessionId);
		$out->putUnsignedVarInt($reason);

		return $out->getBuffer();
	}

	public static function bandwidthStats(int $bytesSent, int $bytesReceived) : string{
		$out = new BinaryStream();
		$out->putByte(self::T2M_BANDWIDTH_STATS);
		$out->putUnsignedVarInt(0);
		$out->putUnsignedVarLong($bytesSent);
		$out->putUnsignedVarLong($bytesReceived);

		return $out->getBuffer();
	}

	public static function send(int $sessionId, string $payload) : string{
		$out = new BinaryStream();
		$out->putByte(self::M2T_SEND);
		$out->putUnsignedVarInt($sessionId);
		$out->putUnsignedVarInt(0);
		$out->put($payload);

		return $out->getBuffer();
	}

	public static function closeSession(int $sessionId) : string{
		$out = new BinaryStream();
		$out->putByte(self::M2T_CLOSE_SESSION);
		$out->putUnsignedVarInt($sessionId);

		return $out->getBuffer();
	}

	public static function blockAddress(string $address, int $timeout) : string{
		$out = new BinaryStream();
		$out->putByte(self::M2T_BLOCK_ADDRESS);
		$out->putUnsignedVarInt(strlen($address));
		$out->put($address);
		$out->putVarInt($timeout);

		return $out->getBuffer();
	}

	public static function unblockAddress(string $address) : string{
		$out = new BinaryStream();
		$out->putByte(self::M2T_UNBLOCK_ADDRESS);
		$out->putUnsignedVarInt(strlen($address));
		$out->put($address);

		return $out->getBuffer();
	}
}
