# docker-safety

Human gates for Docker, Podman and nerdctl commands that delete data or
give a container the host. Mounting the host's root filesystem into a
container is refused. Read-only listings (`docker ps`, `images`, `* ls`,
`system df`) are allowed when nothing is chained onto them.

```yaml
version: 1
default: ask
packs: [floor, docker-safety]
```

Commands are matched at the start of a pipeline segment, after `sudo`,
`env`, `xargs`, `sh -c '…'` or `ssh host …`, and behind `VAR=value`
assignments (`DOCKER_HOST=ssh://prod docker …`). The subcommand is matched
anywhere after the binary in that segment, so global flags in front of it
(`--context prod`, `-H ssh://…`) do not hide it. `docker.exe` and
`podman.exe` match too.

| Rule | Verdict | Covers |
|---|---|---|
| `docker-host-takeover-denied` | deny | `run`/`create` with the host's `/`, `/etc`, `/root` or `/boot` bind-mounted (`-v /:/host`, `--volume=/etc:/etc`, `--mount source=/`), and `--privileged` together with `--pid=host` or `nsenter` |
| `docker-system-prune-asks` | ask, irreversible | `system prune -a` / `--all` / `--volumes`, `podman system reset` |
| `docker-volume-delete-asks` | ask, irreversible | `volume rm`, `volume prune` |
| `docker-compose-down-volumes-asks` | ask, irreversible | `docker compose down -v` / `--volumes`, `docker-compose`, `podman-compose` |
| `docker-mass-remove-asks` | ask, irreversible | `rm`/`rmi` over `$(docker ps -aq)` / `$(docker images -q)`, `… \| xargs docker rm`, `image prune -a`, `builder`/`buildx prune -a` |
| `docker-swarm-teardown-asks` | ask, irreversible | `swarm leave --force`, `swarm init --force-new-cluster`, `stack rm`, `service rm`, `node rm` |
| `docker-host-escape-run-asks` | ask | `run`/`create`/`exec` with `--privileged`, `--pid=host`, `--userns=host`, `--cgroupns=host`, `--cap-add SYS_ADMIN/ALL/SYS_PTRACE/SYS_MODULE/DAC_READ_SEARCH`, AppArmor/seccomp/SELinux `unconfined`, or the Docker/Podman/containerd socket (or the Windows `docker_engine` pipe) mounted |
| `docker-login-asks` | ask | `docker login`, `podman login` |
| `docker-context-remove-asks` | ask, irreversible | `docker context rm` |
| `docker-read-only-allowed` | allow | anchored `docker`/`podman` `ps`, `images`, `version`, `info`, `<object> ls`, `compose ps/ls/images`, `system df`, `buildx ls` with no `;`, `&`, `\|`, `$`, backticks or redirects |

Why the split between deny and ask: a host-root mount or a privileged
container in the host PID namespace is root on the machine, outside
`provio run`'s write boundary, and no normal agent task needs it.
`--privileged` alone, the Docker socket and host namespaces have real uses
(Docker-in-Docker, Testcontainers, Portainer, Traefik, node exporters), so
they ask.

## What it deliberately does not cover

- **`docker push`.** Image pushes are in `package-publish-guard`
  (`publish-image-push-asks`). Add that pack for them.
- **Plain `docker system prune`, `container prune`, `docker rm <name>`,
  `docker compose down`** without `-v`: routine cleanup that keeps volumes
  and named images. They get your policy's `default`.
- **`--net=host`** alone, `--ipc=host`, `--uts=host`, `--device`, and
  mounts of the home directory or project directories. Add your own rule
  if your threat model needs them.
- **Compose files and Dockerfiles.** `privileged: true` or a
  `/var/run/docker.sock` volume in `compose.yaml`, then `docker compose up`,
  is not seen: the pack reads the command line, not the file it points at.
- **Kubernetes, `docker exec` into a container and what runs inside it.**
  `docker exec web rm -rf /data` is a command inside the container; see
  `floor` and `k8s-prod`.
- **`docker inspect` and `docker logs`** can print environment variables
  and secrets; they are not allowed here and get your `default`.

## Tests

`fixtures/docker-safety.yaml` (52 cases): every rule with global flags,
`sudo`, `ssh host '…'`, `DOCKER_HOST=…` and `.exe` variants, plus near
misses that must not match (`docker system prune -f`, `docker run --rm`,
`-v /etc/nginx/conf.d:…`, `-H unix:///var/run/docker.sock`,
`--net=host --cap-add NET_ADMIN`, `echo "… docker volume rm …"`,
`grep 'docker system prune -a'`, `docker ps -q && rm -rf build`).
