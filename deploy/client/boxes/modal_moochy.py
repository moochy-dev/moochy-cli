# SPDX-License-Identifier: Apache-2.0
"""Moochy in a Modal Sandbox (CONTRACT §17).

The enrollment token lives in a Modal secret (never in code):
    modal secret create moochy-enroll MOOCHY_ENROLL=<token from `moochy box token create`>
    python modal_moochy.py
Modal sandboxes run under gVisor: when `moochy doctor` reports no user namespaces or Landlock, run
the agent with `moochy run --box-is-sandbox`.
"""
import pathlib

import modal

here = pathlib.Path(__file__).parent
image = (
    modal.Image.debian_slim()
    .apt_install("curl", "xz-utils", "ca-certificates", "git")
    .add_local_file(here / "moochy-box.sh", "/usr/local/bin/moochy-box.sh", copy=True)
    # Install only: an image never carries an enrolled box.
    .run_commands("chmod 0755 /usr/local/bin/moochy-box.sh && /usr/local/bin/moochy-box.sh --install")
)

if __name__ == "__main__":
    app = modal.App.lookup("moochy-box", create_if_missing=True)
    sb = modal.Sandbox.create(app=app, image=image, secrets=[modal.Secret.from_name("moochy-enroll")], timeout=3600)
    p = sb.exec("sh", "-c", "moochy-box.sh && moochy doctor")
    p.wait()
    print(p.stdout.read(), p.stderr.read())
    sb.terminate()
