<?php

/*
 *
 *  ____            _        _   __  __ _                  __  __ ____
 * |  _ \ ___   ___| | _____| |_|  \/  (_)_ __   ___      |  \/  |  _ \
 * | |_) / _ \ / __| |/ / _ \ __| |\/| | | '_ \ / _ \_____| |\/| | |_) |
 * |  __/ (_) | (__|   <  __/ |_| |  | | | | | |  __/_____| |  | |  __/
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

namespace pocketmine\world\sound;

use pocketmine\block\utils\RecordType;
use pocketmine\math\Vector3;
use pocketmine\network\mcpe\protocol\LevelSoundEventPacket;
use pocketmine\network\mcpe\protocol\PlaySoundPacket;
use pocketmine\network\mcpe\protocol\RecordStartedPacket;
use pocketmine\network\mcpe\protocol\types\BlockPosition;

class RecordSound implements Sound{
	private static int $soundHandleCount = 1;

	private int $serverSoundHandle;

	public function __construct(private RecordType $recordType){
		$this->serverSoundHandle = self::$soundHandleCount++;
	}

	public function getServerSoundHandle() : int{
		return $this->serverSoundHandle;
	}

	public function encode(Vector3 $pos) : array{
		$soundName = LevelSoundEventPacket::getIdToStringMap()[$this->recordType->getSoundId()] ?? "";
		return [
			PlaySoundPacket::create($soundName, $pos->x + 0.5, $pos->y + 0.5, $pos->z + 0.5, 1, 1, 0, true, $this->serverSoundHandle, null),
			RecordStartedPacket::create(BlockPosition::fromVector3($pos), $this->serverSoundHandle)
		];
	}
}
