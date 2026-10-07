# OpenSSL 3.2 for the -saltlen version probe of the encrypt scenario. No Alpine release shipped 3.2;
# Fedora 40 did. Fedora 40 is past its end of life, so its packages come from the Fedora archive.
# Pinned 2026-10-05: fedora:40 resolved to this index digest.
FROM fedora:40@sha256:3c86d25fef9d2001712bc3d9b091fc40cf04be4767e48f1aa3b785bf58d300ed
RUN sed -i -e 's|^metalink=|#metalink=|' \
      -e 's|^#baseurl=http://download.example/pub/fedora/linux|baseurl=https://archives.fedoraproject.org/pub/archive/fedora/linux|' \
      /etc/yum.repos.d/fedora*.repo \
 && dnf -y --setopt=install_weak_deps=False install openssl && dnf clean all \
 && openssl version | grep -q '^OpenSSL 3\.2\.'
ENTRYPOINT ["openssl"]
