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

namespace pocketmine\network\mcpe\auth;

use Closure;
use pocketmine\network\mcpe\protocol\ProtocolInfo;
use pocketmine\scheduler\AsyncTask;
use pocketmine\utils\Internet;

use function is_array;
use function is_object;
use function json_decode;

use const JSON_THROW_ON_ERROR;

class FetchAuthKeysTask extends AsyncTask{

	private const MINECRAFT_SERVICES_DISCOVERY_URL =
		"https://client.discovery.minecraft-services.net/api/v1.0/discovery/MinecraftPE/builds/" .
		ProtocolInfo::MINECRAFT_VERSION_NETWORK;

	private const AUTHORIZATION_SERVICE_URI_FALLBACK =
		"https://authorization.franchise.minecraft-services.net";

	private const AUTHORIZATION_SERVICE_OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";
	private const AUTHORIZATION_SERVICE_KEYS_PATH = "/.well-known/keys";


	/**
	 * @param Closure( array<string, array<string, string>>|null, string, string[]|null ): void $onCompletion
	 */
	public function __construct(
		private Closure $onCompletion
	){
	}

	public function onRun() : void{
		$errors = [];
		$keys = null;

		try{
			$authServiceUri = $this->getAuthServiceURI();
		}catch(\RuntimeException $e){
			$errors[] = $e->getMessage();
			$authServiceUri = self::AUTHORIZATION_SERVICE_URI_FALLBACK;
		}

		try{
			$config = $this->getOpenIdConfiguration($authServiceUri);
			$jwksUri = $config->jwks_uri ?? $authServiceUri . self::AUTHORIZATION_SERVICE_KEYS_PATH;
			$issuer = $config->issuer ?? $authServiceUri;
		}catch(\RuntimeException $e){
			$errors[] = $e->getMessage();
			$jwksUri = $authServiceUri . self::AUTHORIZATION_SERVICE_KEYS_PATH;
			$issuer = $authServiceUri;
		}

		try{
			$keys = $this->getKeys($jwksUri);
		}catch(\RuntimeException $e){
			$errors[] = $e->getMessage();
		}

		$this->setResult([
			"keys" => $keys,
			"issuer" => $issuer,
			"errors" => $errors === [] ? null : $errors
		]);
	}

	private function getAuthServiceURI() : string{
		$result = Internet::getURL(self::MINECRAFT_SERVICES_DISCOVERY_URL);
		if($result === null || $result->getCode() !== 200){
			throw new \RuntimeException("Failed to fetch discovery document");
		}

		$json = json_decode($result->getBody(), false, JSON_THROW_ON_ERROR);
		if(!is_object($json)){
			throw new \RuntimeException("Invalid JSON root type");
		}

		return $json->result->serviceEnvironments->auth->prod->serviceUri ?? throw new \RuntimeException("Missing auth URI");
	}

	private function getOpenIdConfiguration(string $uri) : object{
		$result = Internet::getURL($uri . self::AUTHORIZATION_SERVICE_OPENID_CONFIGURATION_PATH);
		if($result === null || $result->getCode() !== 200){
			throw new \RuntimeException("Failed to fetch OpenID config");
		}

		$json = json_decode($result->getBody(), false, JSON_THROW_ON_ERROR);
		if(!is_object($json)){
			throw new \RuntimeException("Invalid OpenID JSON");
		}

		return $json;
	}

	/**
	 * @return array<string, array<string, string>>
	 */
	private function getKeys(string $jwksUri) : array{
		$result = Internet::getURL($jwksUri);
		if($result === null || $result->getCode() !== 200){
			throw new \RuntimeException("Failed to fetch keys");
		}

		$json = json_decode($result->getBody(), true, JSON_THROW_ON_ERROR);
		if(!is_array($json) || !isset($json["keys"]) || !is_array($json["keys"])){
			throw new \RuntimeException("Invalid keys JSON");
		}

		$keys = [];
		foreach($json["keys"] as $key){
			if(!is_array($key) || !isset($key["kid"], $key["n"], $key["e"])) continue;

			$keys[(string) $key["kid"]] = [
				"kid" => (string) $key["kid"],
				"n" => (string) $key["n"],
				"e" => (string) $key["e"]
			];
		}

		return $keys;
	}

	public function onCompletion() : void{
		/**
		 * @var array<string, mixed> $result
		 */
		$result = $this->getResult();

		/** @var array<string, array<string, string>>|null $keys */
		$keys = $result["keys"] ?? null;

		/** @var string $issuer */
		$issuer = $result["issuer"] ?? "";

		/** @var array<string>|null $errors */
		$errors = $result["errors"] ?? null;

		($this->onCompletion)($keys, $issuer, $errors);
	}
}