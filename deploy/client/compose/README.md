# Run a donor node with Docker Compose

One file runs the Moochy app on a server and donates tokens from it. It has two profiles:

- `api`: you donate with a provider API key (Anthropic, OpenAI, OpenRouter, DeepSeek or xAI).
- `gpu`: you donate with your own NVIDIA GPU. Ollama runs the model next to the app, on loopback only.

No port is published. The app only dials out.

## 1. Get the files

Download `compose.yaml` and `.env.example` from this directory (or from the release), then:

```sh
cp .env.example .env     # set MOOCHY_MONTHLY_LIMIT, and MOOCHY_PROVIDER or OLLAMA_MODEL
```

## 2. Write the two secrets

The secrets stay in a directory only you can open. The files inside are readable by the container user.

```sh
mkdir -m 700 secrets
(umask 022; head -c 32 /dev/urandom | base64 > secrets/passphrase)
```

Profile `api` only: type the provider key. It is not shown and does not go into your shell history.

```sh
(umask 022; read -rs -p 'Provider API key: ' k && printf '%s\n' "$k" > secrets/provider-key; unset k; echo)
```

Keep `secrets/passphrase`: it unlocks the keystore in the `moochy-data` volume.

## 3. Start it

```sh
docker compose --profile api up -d      # or: --profile gpu
docker compose logs -f moochy           # gpu: moochy-gpu
```

The first start prints a code and a link. Open the link, sign in to Moochy and confirm the code. The node then adds the key, does the safety step from `MOOCHY_MONTHLY_LIMIT`, donates when `MOOCHY_DONATE` and `MOOCHY_DONATE_CAP` are set, and runs.

Each later start skips the steps that are done. To use a new key, write it to `secrets/provider-key` and restart.

## Commands

```sh
docker compose exec moochy /moochy --home /data status
docker compose exec moochy /moochy --home /data donations
docker compose exec moochy /moochy --home /data pause
docker compose --profile api down       # stop; the volume keeps the device and the keys
```

Your key never leaves this machine. The relay sees only encrypted bytes.
