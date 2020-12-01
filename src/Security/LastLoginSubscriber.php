<?php


namespace App\Security;


use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

class LastLoginSubscriber implements EventSubscriberInterface
{
    /**
     * @var \Doctrine\ORM\EntityManagerInterface
     */
    private $em;

    public function __construct(EntityManagerInterface $em) {

        $this->em = $em;
    }
    /**
     * @inheritDoc
     */
    public static function getSubscribedEvents()
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
            CheckPassportEvent::class => 'onCheckPassport',
        ];
    }

    public function onCheckPassport(CheckPassportEvent $event)
    {
        $user = $event->getPassport()->getUser();

        $this->checkUser($user);

        if($user->getEmail() === 'bad_user@symfony.com') {
            throw new CustomUserMessageAccountStatusException("You're not welcome here");
        }
    }

    public function onLoginSuccess(LoginSuccessEvent $event)
    {
        $user = $event->getUser();

        $this->checkUser($user);

        $user->setLastLoginAt(new \DateTimeImmutable());
        $this->em->flush();
    }

    /**
     * @param $user
     *
     * @throws \Exception
     */
    public function checkUser($user): void
    {
        if (!$user instanceof User) {
            throw new \Exception("Wrong user entity");
        }
    }

}