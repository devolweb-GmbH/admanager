<?php

namespace App\Controller;

use App\Service\LdapService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use OpenApi\Annotations as OA;

class GroupController extends AbstractController
{
    #[Route('/api/group/list', name: 'group_list', methods: ['GET'])]
    /**
     * @OA\Get(
     *     path="/api/group/list",
     *     summary="Alle Gruppen anzeigen (CNs)",
     *     @OA\Response(response=200, description="Liste aller Gruppen mit CNs")
     * )
     */
    public function listGroups(LdapService $ldapService): JsonResponse
    {
        try {
            $groups = $ldapService->getAllGroups();
            return $this->json(['success' => true, 'groups' => $groups]);
        } catch (\Exception $e) {
            return $this->json(['success' => false, 'error' => $e->getMessage()]);
        }
    }

    #[Route('/api/group/{groupName}/members', name: 'group_members', methods: ['GET'])]
    /**
     * @OA\Get(
     *     path="/api/group/{groupName}/members",
     *     summary="Mitglieder einer Gruppe anzeigen",
     *     @OA\Parameter(name="groupName", in="path", required=true, @OA\Schema(type="string")),
     *     @OA\Response(response=200, description="Liste der Gruppenmitglieder")
     * )
     */
    public function groupMembers(string $groupName, LdapService $ldapService): JsonResponse
    {
        try {
            $members = $ldapService->getGroupMembersByCn($groupName);
            return $this->json(['success' => true, 'members' => $members]);
        } catch (\Exception $e) {
            return $this->json(['success' => false, 'error' => $e->getMessage()]);
        }
    }

    #[Route('/api/user/{samAccountName}/add-to-group', name: 'user_add_to_group', methods: ['POST'])]
    /**
     * @OA\Post(
     *     path="/api/user/{samAccountName}/add-to-group",
     *     summary="Benutzer zu Gruppe hinzufügen",
     *     @OA\Parameter(name="samAccountName", in="path", required=true, @OA\Schema(type="string")),
     *     @OA\RequestBody(
     *         @OA\JsonContent(
     *             required={"group"},
     *             @OA\Property(property="group", type="string", example="IT-Admins")
     *         )
     *     ),
     *     @OA\Response(response=200, description="Benutzer wurde hinzugefügt oder Fehler zurückgegeben")
     * )
     */
    public function addToGroup(string $samAccountName, Request $request, LdapService $ldapService): JsonResponse
    {
        try {
            $groupCn = $this->extractGroupName($request);
        } catch (\InvalidArgumentException $exception) {
            return $this->json(['success' => false, 'error' => $exception->getMessage()], Response::HTTP_BAD_REQUEST);
        }

        try {
            $groupDn = $ldapService->resolveGroupDnByCn($groupCn);
            if (!$groupDn) {
                return $this->json(['success' => false, 'error' => 'Gruppe nicht gefunden']);
            }

            $ldapService->addUserToGroup($samAccountName, $groupDn);
            return $this->json(['success' => true, 'message' => 'Benutzer zur Gruppe hinzugefügt.']);
        } catch (\Exception $e) {
            return $this->json(['success' => false, 'error' => $e->getMessage()]);
        }
    }

    #[Route('/api/user/{samAccountName}/remove-from-group', name: 'user_remove_from_group', methods: ['POST'])]
    /**
     * @OA\Post(
     *     path="/api/user/{samAccountName}/remove-from-group",
     *     summary="Benutzer aus Gruppe entfernen",
     *     @OA\Parameter(name="samAccountName", in="path", required=true, @OA\Schema(type="string")),
     *     @OA\RequestBody(
     *         @OA\JsonContent(
     *             required={"group"},
     *             @OA\Property(property="group", type="string", example="IT-Admins")
     *         )
     *     ),
     *     @OA\Response(response=200, description="Benutzer wurde entfernt oder Fehler zurückgegeben")
     * )
     */
    public function removeFromGroup(string $samAccountName, Request $request, LdapService $ldapService): JsonResponse
    {
        try {
            $groupCn = $this->extractGroupName($request);
        } catch (\InvalidArgumentException $exception) {
            return $this->json(['success' => false, 'error' => $exception->getMessage()], Response::HTTP_BAD_REQUEST);
        }

        try {
            $groupDn = $ldapService->resolveGroupDnByCn($groupCn);
            if (!$groupDn) {
                return $this->json(['success' => false, 'error' => 'Gruppe nicht gefunden']);
            }

            $ldapService->removeUserFromGroup($samAccountName, $groupDn);
            return $this->json(['success' => true, 'message' => 'Benutzer aus Gruppe entfernt.']);
        } catch (\Exception $e) {
            return $this->json(['success' => false, 'error' => $e->getMessage()]);
        }
    }

    private function extractGroupName(Request $request): string
    {
        try {
            $data = $request->toArray();
        } catch (\JsonException) {
            throw new \InvalidArgumentException('Ungültiger JSON-Request-Body');
        }

        $groupCn = $data['group'] ?? null;
        if (!is_string($groupCn) || trim($groupCn) === '') {
            throw new \InvalidArgumentException('Gruppenname fehlt');
        }

        return $groupCn;
    }
}
