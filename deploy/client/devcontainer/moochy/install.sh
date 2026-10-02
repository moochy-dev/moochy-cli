#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Dev container feature install (image build, as root): moochy only, never an enrollment (every
# container from the image would be a clone). postStartCommand enrolls each container at start
# with MOOCHY_ENROLL from the platform's secrets (Codespaces/Daytona secret).
set -eu
mkdir -p /usr/local/share/moochy
install -m 0755 "$(dirname "$0")/moochy-box.sh" /usr/local/share/moochy/moochy-box.sh
/usr/local/share/moochy/moochy-box.sh --install
