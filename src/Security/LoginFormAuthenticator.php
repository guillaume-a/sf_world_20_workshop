<?php


namespace App\Security;


use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;

class LoginFormAuthenticator implements AuthenticatorInterface
{

    /**
     * @var \Doctrine\ORM\EntityManagerInterface
     */
    private $em;

    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
    }

    public function supports(Request $request): ?bool
    {
        return
          $request->isMethod(Request::METHOD_POST) &&
          $request->attributes->get('_route') === 'app_login';
    }

    public function authenticate(Request $request): PassportInterface
    {
        $email = $request->request->get('email', '');
        $password = $request->request->get('password', '');

        $userBadge = new UserBadge($email, function($email) {
            return $this->em->getRepository(User::class)->findOneBy(['email' => $email]);
        });

        $credentials = new PasswordCredentials($password);

        return new Passport(
          $userBadge,
          $credentials
        );
    }

    public function createAuthenticatedToken(PassportInterface $passport,string $firewallName): TokenInterface {

    }

    public function onAuthenticationSuccess(Request $request,TokenInterface $token,string $firewallName): ?Response {

    }

    public function onAuthenticationFailure(Request $request,AuthenticationException $exception): ?Response {

    }

}