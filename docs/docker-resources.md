# Docker resource favorites

Local Ops discovers Docker resources through the local Docker CLI and stores an exact resource identity in a launchpad card.

## Resources

A Compose favorite stores `projectName`, absolute `workingDir`, and the ordered absolute `configFiles` reported by Docker labels. A single-container favorite stores the daemon's full 64-character container ID. Display names are never used as control identity.

`GET /api/docker/resources` returns both resource types. `GET /api/state` exposes the persisted resource, current running state, and `runtimeSource` as `dockerCompose` or `dockerContainer`.

## Control boundary

`POST /api/apps/{id}/start` and `/stop` dispatch to the Docker CLI:

- Compose: `docker compose --project-name ... --project-directory ... -f ... up --detach` or `stop`.
- Container: `docker container start <full-id>` or `docker container stop <full-id>`.

Local Ops never invokes `compose down`, removes containers or volumes, or runs `prune`. Docker daemon permissions remain authoritative. A missing CLI, unreachable daemon, or vanished exact identity fails closed and leaves the favorite intact.

Capabilities are advertised independently as `monitor_docker` and `control_docker`.
