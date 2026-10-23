# Docker fixtures

`docker_macos_*.txt` and `docker_windows_*.txt` are SYNTHETIC. They were written by hand from the
documented docker CLI output formats because no docker binary or Windows PC was available when
Task 10 was built. Replace them with real, anonymised recordings at Task 16 acceptance.

What each file stands for:

- `*_ps.txt`: `docker ps -a --no-trunc --format '{{json .}}'` (one JSON object per line)
- `*_volume_ls.txt`: `docker volume ls --format '{{json .}}'`
- `*_df.txt`: `docker system df -v --format '{{json .}}'` (a single JSON object with Images, Containers, Volumes, BuildCache)
- `*_stats.txt`: `docker stats --no-stream --no-trunc --format '{{json .}}'`
- `*_inspect.txt`: `docker inspect --format '{{json .Mounts}}' <ids of the monitoring containers>` (one line per container, in argument order)
- `*_shop_inspect.txt`: the same for one container that bind-mounts a project folder

The Windows set uses `C:\...` and `/run/desktop/mnt/host/c/...` bind-mount forms.
