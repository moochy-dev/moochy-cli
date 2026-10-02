# SPDX-License-Identifier: Apache-2.0
# E2B sandbox template with moochy installed (CONTRACT §17).
#   e2b template build -n moochy-box -c "true"
# Do NOT enroll in the template (no `moochy-box.sh` start command): E2B snapshots the start
# command, so every sandbox would be a clone of one box. Enroll in each sandbox after it starts:
#   sbx = Sandbox("moochy-box", envs={"MOOCHY_ENROLL": token_from_your_secret_store})
#   sbx.commands.run("moochy-box.sh && cd /home/user/repo && moochy run --box-is-sandbox -- <agent>")
FROM e2bdev/code-interpreter:latest
COPY moochy-box.sh /usr/local/bin/moochy-box.sh
RUN chmod 0755 /usr/local/bin/moochy-box.sh && /usr/local/bin/moochy-box.sh --install
