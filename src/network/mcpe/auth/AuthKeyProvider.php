<?php

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

use pocketmine\network\mcpe\JwtException;
use pocketmine\network\mcpe\JwtUtils;
use pocketmine\promise\Promise;
use pocketmine\promise\PromiseResolver;
use pocketmine\scheduler\AsyncPool;
use pocketmine\utils\AssumptionFailedError;
use function array_keys;
use function count;
use function implode;
use function time;

class AuthKeyProvider {
	private const ALLOWED_REFRESH_INTERVAL = 30 * 60; // 30 minutes

	private ?AuthKeyring $keyring = null;

	/** @phpstan-var PromiseResolver<AuthKeyring>|null */
	private ?PromiseResolver $resolver = null;

	private int $lastFetch = 0;

	public function __construct(
		private readonly \Logger $logger,
		private readonly AsyncPool $asyncPool,
		private readonly int $keyRefreshIntervalSeconds = self::ALLOWED_REFRESH_INTERVAL
	){}

	/**
	 * Fetches the key for the given key ID.
	 * The promise will be resolved with an array of [issuer, pemPublicKey].
	 *
	 * @phpstan-return Promise<array{string, string}>
	 */
	public function getKey(string $keyId) : Promise {
		/** @phpstan-var PromiseResolver<array{string, string}> $resolver */
		$resolver = new PromiseResolver();

		if(
			$this->keyring === null ||
			($this->keyring->getKey($keyId) === null && $this->lastFetch < time() - $this->keyRefreshIntervalSeconds)
		){
			$this->fetchKeys()->onCompletion(
				onSuccess: fn(AuthKeyring $newKeyring) => $this->resolveKey($resolver, $newKeyring, $keyId),
				onFailure: $resolver->reject(...)
			);
		} else {
			$this->resolveKey($resolver, $this->keyring, $keyId);
		}

		return $resolver->getPromise();
	}

	/**
	 * @phpstan-param PromiseResolver<array{string, string}> $resolver
	 */
	private function resolveKey(PromiseResolver $resolver, AuthKeyring $keyring, string $keyId) : void {
		$key = $keyring->getKey($keyId);
		if($key === null){
			$this->logger->debug("Key $keyId not recognised!");
			$resolver->reject();
			return;
		}

		$this->logger->debug("Key $keyId found in keychain");
		$resolver->resolve([$keyring->getIssuer(), $key]);
	}

	/**
	 * @phpstan-param array<string, array<string, string>>|null $keys
	 * @phpstan-param string $issuer
	 * @phpstan-param array<string>|null $errors
	 */
	private function onKeysFetched(?array $keys, string $issuer, ?array $errors) : void {
		$resolver = $this->resolver;
		if($resolver === null){
			throw new AssumptionFailedError("Not expecting this to be called without a resolver present");
		}

		$this->logger->debug("Fetched raw keys: " . json_encode($keys));

		if($errors !== null){
			$this->logger->error("The following errors occurred while fetching new keys:\n\t- " . implode("\n\t-", $errors));
			//we might've still succeeded in fetching keys even if there were errors, so don't return
		}

		if($keys === null){
			$this->logger->critical("Failed to fetch authentication keys. Xbox players may not authenticate!");
			$resolver->reject();
			return;
		}

		$pemKeys = [];
		foreach($keys as $key){
			$kid = $key['kid'] ?? null;
			$n = $key['n'] ?? null;
			$e = $key['e'] ?? null;

			if($kid === null || $n === null || $e === null){
				$this->logger->warning("Skipping invalid key: missing kid/n/e");
				continue;
			}

			try {
				$derKey = JwtUtils::rsaPublicKeyModExpToDer($n, $e);
				JwtUtils::parseDerPublicKey($derKey);
			} catch(JwtException $ex){
				$this->logger->error("Failed to parse key $kid: " . $ex->getMessage());
				continue;
			}

			$pemKeys[$kid] = $derKey;
		}

		if(count($pemKeys) === 0){
			$this->logger->critical("No valid authentication keys returned. Xbox players may not authenticate!");
			$resolver->reject();
			return;
		}

		$this->logger->info("Successfully fetched " . count($pemKeys) . " keys from $issuer, key IDs: " . implode(", ", array_keys($pemKeys)));
		$this->keyring = new AuthKeyring($issuer, $pemKeys);
		$this->lastFetch = time();
		$resolver->resolve($this->keyring);
	}

	/**
	 * @phpstan-return Promise<AuthKeyring>
	 */
	private function fetchKeys() : Promise {
		if($this->resolver !== null){
			$this->logger->debug("Key refresh was requested, but it's already in progress");
			return $this->resolver->getPromise();
		}

		$this->logger->notice("Fetching new authentication keys");

		/** @phpstan-var PromiseResolver<AuthKeyring> $resolver */
		$resolver = new PromiseResolver();
		$this->resolver = $resolver;
		$this->asyncPool->submitTask(new FetchAuthKeysTask($this->onKeysFetched(...)));
		return $this->resolver->getPromise();
	}
}