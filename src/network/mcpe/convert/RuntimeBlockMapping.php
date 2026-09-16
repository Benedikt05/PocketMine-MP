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

namespace pocketmine\network\mcpe\convert;

use pocketmine\block\Block;
use pocketmine\block\BlockLegacyIds;
use pocketmine\data\bedrock\LegacyBlockIdToStringIdMap;
use pocketmine\nbt\BigEndianNbtSerializer;
use pocketmine\nbt\tag\CompoundTag;
use pocketmine\utils\AssumptionFailedError;
use pocketmine\utils\SingletonTrait;
use RuntimeException;
use function count;
use function file_get_contents;
use function json_decode;
use function zlib_decode;
use const pocketmine\RESOURCE_PATH;

/**
 * @internal
 */
final class RuntimeBlockMapping{
	use SingletonTrait;

	/** @var int[] */
	private array $legacyToRuntimeMap = [];
	/** @var int[] */
	private array $runtimeToLegacyMap = [];
	/** @var CompoundTag[]|null */
	private ?array $bedrockKnownStates = null;
	/** @var int[] runtime id -> block state network hash */
	private array $runtimeIdToHashMap = [];
	private int $unknownRid = 0;

	private static function make() : self{
		return new self();
	}

	public function __construct(){
		$bedrockKnownStates = $this->loadBedrockKnownStates();

		$legacyIdMap = LegacyBlockIdToStringIdMap::getInstance();

		$jsonPath = RESOURCE_PATH . "current/r12_to_current_block_map.json";
		$jsonRaw = file_get_contents($jsonPath);
		if($jsonRaw === false){
			throw new RuntimeException("Missing required resource file: r12_to_current_block_map.json");
		}
		$legacyStateMapJson = json_decode($jsonRaw, true);

		/**
		 * @var int[][] $idToStatesMap string id -> int[] list of candidate state indices
		 */
		$idToStatesMap = [];
		foreach($bedrockKnownStates as $k => $state){
			$name = $state->getString("name");
			$idToStatesMap[$name][] = $k;
		}

		foreach($legacyStateMapJson as $pair){
			$stringId = $pair["id"];
			$id = $legacyIdMap->stringToLegacy($stringId);
			if($id === null){
				throw new RuntimeException("No legacy ID matches " . $stringId);
			}
			$data = $pair["meta"];
			if($data > 0xf){
				//we can't handle metadata with more than 4 bits
				continue;
			}

			$targetState = $pair["blockState"];
			$mappedName = $targetState["name"] ?? "";

			if(!isset($idToStatesMap[$mappedName])){
				throw new RuntimeException("Mapped new state '$mappedName' does not appear in network table");
			}

			$matched = false;
			foreach($idToStatesMap[$mappedName] as $k){
				$networkState = $bedrockKnownStates[$k];
				if(self::compareJsonStateWithNbt($targetState, $networkState)){
					$this->registerMapping($k, $id, $data);
					$matched = true;
					break;
				}
			}

			if(!$matched){
				throw new RuntimeException("Mapped new state '$mappedName' (meta $data) does not appear in network table");
			}
		}
	}

	/**
	 * @return CompoundTag[]
	 */
	private function loadBedrockKnownStates() : array{
		$paletteRaw = file_get_contents(RESOURCE_PATH . "current/block_palette.nbt");
		if($paletteRaw === false){
			throw new AssumptionFailedError("Missing required resource file: block_palette.nbt");
		}

		$decompressed = zlib_decode($paletteRaw);
		if($decompressed === false){
			throw new RuntimeException("Failed to decompress block_palette.nbt");
		}

		$nbtReader = new BigEndianNbtSerializer();
		$root = $nbtReader->read($decompressed)->mustGetCompoundTag();

		$blocksList = $root->getListTag("blocks");
		if($blocksList === null){
			throw new RuntimeException("Missing 'blocks' tag in block_palette.nbt");
		}

		/** @var CompoundTag[] $bedrockKnownStates */
		$bedrockKnownStates = [];
		foreach($blocksList->getValue() as $k => $state){
			if($state instanceof CompoundTag){
				$this->runtimeIdToHashMap[$k] = $state->getInt("network_id");
				$state->removeTag("network_id", "name_hash");

				$bedrockKnownStates[$k] = $state;

				if($state->getString("name") === "minecraft:info_update"){
					$this->unknownRid = $this->runtimeIdToHashMap[$k] ?? 0;
				}
			}
		}

		return $bedrockKnownStates;
	}

	private static function compareJsonStateWithNbt(array $jsonState, CompoundTag $nbtState) : bool{
		if(($jsonState["name"] ?? "") !== $nbtState->getString("name")){
			return false;
		}

		$jsonStates = $jsonState["states"] ?? [];
		$nbtStatesTag = $nbtState->getCompoundTag("states");

		if(count($jsonStates) === 0){
			return $nbtStatesTag === null || count($nbtStatesTag->getValue()) === 0;
		}

		if($nbtStatesTag === null){
			return false;
		}

		foreach($jsonStates as $key => $val){
			$tag = $nbtStatesTag->getTag((string)$key);
			if($tag === null){
				return false;
			}

			if($tag->getValue() != $val){
				return false;
			}
		}

		return true;
	}

	public function toRuntimeId(int $internalStateId) : int{
		return $this->legacyToRuntimeMap[$internalStateId] ?? $this->legacyToRuntimeMap[BlockLegacyIds::INFO_UPDATE << Block::INTERNAL_METADATA_BITS] ?? $this->unknownRid;
	}

	public function fromRuntimeId(int $runtimeId) : int{
		return $this->runtimeToLegacyMap[$runtimeId] ?? (BlockLegacyIds::INFO_UPDATE << Block::INTERNAL_METADATA_BITS);
	}

	private function registerMapping(int $staticRuntimeId, int $legacyId, int $legacyMeta) : void{
		$networkId = $this->toRuntimeHash($staticRuntimeId);
		$this->legacyToRuntimeMap[($legacyId << Block::INTERNAL_METADATA_BITS) | $legacyMeta] = $networkId;
		$this->runtimeToLegacyMap[$networkId] = ($legacyId << Block::INTERNAL_METADATA_BITS) | $legacyMeta;
	}

	public function toRuntimeHash(int $runtimeId) : int{
		return $this->runtimeIdToHashMap[$runtimeId] ?? throw new RuntimeException("Unknown runtime ID $runtimeId");
	}

	/**
	 * WARNING: This method may load the palette from disk, which is a slow operation.
	 * Afterwards, it will cache the palette in memory, which requires (in some cases) tens of MB of memory.
	 * Avoid using this where possible.
	 *
	 * @deprecated
	 * @return CompoundTag[]
	 */
	public function getBedrockKnownStates() : array{
		return $this->bedrockKnownStates ??= $this->loadBedrockKnownStates();
	}
}
