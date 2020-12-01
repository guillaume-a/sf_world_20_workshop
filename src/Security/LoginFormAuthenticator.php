<?php


namespace App\Security;


use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;

class LoginFormAuthenticator extends AbstractLoginFormAuthenticator
{

    /**
     * @var \Doctrine\ORM\EntityManagerInterface
     */
    private $em;

    /**
     * @var \Symfony\Component\Routing\RouterInterface
     */
    private $router;

    public function __construct(EntityManagerInterface $em, RouterInterface $router)
    {
        $this->em = $em;
        $this->router = $router;
    }

    public function authenticate(Request $request): PassportInterface
    {
        $email = $request->request->get('email', '');
        $password = $request->request->get('password', '');
        $csrfToken = $request->request->get('_csrf_token', '');

        $userBadge = new UserBadge($email, function($email) {
            $user = $this->em->getRepository(User::class)->findOneBy(['email' => $email]);

            if(!$user instanceof User) {
                throw new CustomUserMessageAuthenticationException("Oh no !");
            }

            return $user;
        });

        $credentials = new PasswordCredentials($password);

        return new Passport(
          $userBadge,
          $credentials, [
            new CsrfTokenBadge('authenticate', $csrfToken)
          ]
        );
    }

    public function onAuthenticationSuccess(Request $request,TokenInterface $token,string $firewallName): ?Response {
        return new RedirectResponse(
          $this->router->generate('app_homepage')
        );
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->router->generate('app_login');
    }

}