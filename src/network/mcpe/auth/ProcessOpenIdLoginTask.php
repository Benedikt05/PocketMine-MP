<?php

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;
use pocketmine\entity\effect\Effect;
use pocketmine\scheduler\AsyncTask;

use function base64_decode;

class ProcessOpenIdLoginTask extends AsyncTask{

	public const MOJANG_AUDIENCE = "api://auth-minecraft-services/multiplayer";

	private \Closure $onCompletion;

	private ?string $error = "Unknown";
	private bool $authenticated = false;
	private ?string $clientPublicKeyDer = null;

	public function __construct(
		private string $jwt,
		private string $issuer,
		private string $mojangPublicKeyDer,
		private string $clientDataJwt,
		private bool $authRequired,
		\Closure $onCompletion
	){
		$this->onCompletion = $onCompletion;
	}

	public function onRun() : void{
		try{
			$this->clientPublicKeyDer = $this->validateChain();
			$this->error = null;
		}catch(VerifyLoginException $e){
			$this->error = $e->getMessage();
		}

		$this->setResult([
			"authenticated" => $this->authenticated,
			"authRequired" => $this->authRequired,
			"error" => $this->error,
			"clientKey" => $this->clientPublicKeyDer
		]);
	}

	private function validateChain() : string{
		$claims = AuthJwtHelper::validateOpenIdAuthToken(
			$this->jwt,
			$this->mojangPublicKeyDer,
			issuer: $this->issuer,
			audience: self::MOJANG_AUDIENCE
		);

		$this->authenticated = true;

		$clientDerKey = base64_decode($claims->cpk, true);
		if($clientDerKey === false){
			throw new VerifyLoginException("Invalid client public key");
		}

		AuthJwtHelper::validateSelfSignedToken($this->clientDataJwt, $clientDerKey);

		return $clientDerKey;
	}

	public function onCompletion() : void{
		/**
		 * @var array                 $result
		 * @phpstan-var array<string, mixed> $result
		 */
		$result = $this->getResult();
		($this->onCompletion)(
			$result["authenticated"] ?? false,
			$result["authRequired"] ?? false,
			$result["error"] ?? null,
			$result["clientKey"] ?? null
		);
	}
}