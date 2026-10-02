# The agent has no service of its own: it only pushes out over HTTPS.
FROM python:3.13-alpine

# The SSH collector shells out to the system's ssh (paramiko is LGPL and was
# ruled out on purpose), and password credentials need sshpass. Without these
# two, the official image shipped with the SSH collector permanently dead --
# every sweep said "no hay binario ssh" and nobody could do anything about it.
RUN apk add --no-cache openssh-client sshpass

WORKDIR /app
COPY agent/requirements.txt ./agent/requirements.txt
RUN pip install --no-cache-dir -r agent/requirements.txt
COPY agent/ ./agent/

CMD ["python", "-m", "agent"]
