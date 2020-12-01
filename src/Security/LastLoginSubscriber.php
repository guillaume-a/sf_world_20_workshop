<?php


namespace App\Security;


use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
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
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event)
    {
        $user = $event->getUser();

        if(!$user instanceof User) {
            throw new \Exception("Wrong user entity");
        }

        $user->setLastLoginAt(new \DateTimeImmutable());
        $this->em->flush();
    }

}