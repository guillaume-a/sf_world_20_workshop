<?php


namespace App\Security;


use App\Entity\ApiToken;
use App\Repository\ApiTokenRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\LogicException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Passport\UserPassportInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

class ApiTokenAuthenticator implements AuthenticatorInterface
{

    /** @var \App\Repository\ApiTokenRepository  */
    private $repository;

    public function __construct(ApiTokenRepository $repository) {
        $this->repository = $repository;
    }

    /**
     * @inheritDoc
     */
    public function supports(Request $request): ?bool
    {
        return $request->headers->has('X-TOKEN');
    }

    /**
     * @inheritDoc
     */
    public function authenticate(Request $request): PassportInterface
    {
        $token = $request->headers->get('X-TOKEN');
        $apiToken = $this->repository->findOneBy(['token' => $token]);

        $passport = new SelfValidatingPassport(
          new UserBadge(
            $request->headers->get('X-TOKEN', ''),
            function () use ($apiToken) {
                if(!$apiToken instanceof ApiToken) {
                    throw new CustomUserMessageAuthenticationException("Oh no !");
                }

                return $apiToken->getUser();
            }
          )
        );

        $passport->setAttribute('api_token', $apiToken);

        return $passport;
    }

    /**
     * @inheritDoc
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response {
        return new JsonResponse([
            'success' => false,
            'messagge' => $exception->getMessageKey(),
          ], 401
        );
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        if (!$passport instanceof SelfValidatingPassport) {
            throw new LogicException(sprintf('Passport does not contain a user, overwrite "createAuthenticatedToken()" in "%s" to create a custom authenticated token.', \get_class($this)));
        }

        $roles = $passport->getUser()->getRoles();

        /** @var ApiToken $apiToken */
        $apiToken = $passport->getAttribute('api_token');

        foreach($apiToken->getScopes() as $scope) {
            $roles[] = 'ROLE_SCOPE_' . strtoupper($scope);
        }

        return new PostAuthenticationToken($passport->getUser(), $firewallName, $roles);
    }

}