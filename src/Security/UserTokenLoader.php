<?php

namespace App\Security;

use App\Entity\ApiToken;
use App\Entity\User;
use App\Repository\ApiTokenRepository;
use App\Repository\UserRepository;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

final class UserTokenLoader
{
    /**
     * @var UserRepository
     */
    private $repository;

    public function __construct(ApiTokenRepository $repository)
    {
        $this->repository = $repository;
    }

    public function __invoke(string $token): ?User
    {
        $token = $this->repository->findOneBy(['token' => $token]);

        if(!$token instanceof ApiToken) {
            throw new CustomUserMessageAuthenticationException("Oh no !");
        }

        return $token->getUser();
    }
}