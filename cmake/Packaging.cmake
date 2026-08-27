# cmake/Packaging.cmake — CPack configuration for VaporWault installer
# packages (TASK-145/146).
#
# Component split mirrors the existing install-script split
# (packaging/linux/install.sh vs client_install.sh, and the two separate
# Install-VaporWault*.ps1 scripts): `server` and `client` are independently
# installable units, one package per component per format — not a single
# combined package with optional feature selection. Server and client are
# normally installed on different machines.

set(CPACK_PACKAGE_NAME "vaporwault")
set(CPACK_PACKAGE_VENDOR "VaporWault")
set(CPACK_PACKAGE_CONTACT "vapourwault@example.invalid")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "VaporWault self-hosted cloud file sync")
# Set explicitly rather than relying on CPack's PROJECT_VERSION default
# (TASK-203 added a VERSION arg to the top-level project() call, but that's
# sourced from the checked-in VERSION file, not the release tag). VW_VERSION
# defaults to the VERSION file's contents for local builds; CI passes the
# real (leading-"v"-stripped) tag, which is what actually ships.
set(CPACK_PACKAGE_VERSION "${VW_VERSION}")

# Component-based packaging: one package per component (TASK-145 design).
# CPACK_COMPONENTS_ALL restricted to exactly these two names is also what
# keeps mbedTLS/Argon2's OWN install() rules (pulled in transitively via
# FetchContent — they declare install(TARGETS ...) for their static libs
# and dev headers, tagged with no COMPONENT of their own, i.e. the default
# "Unspecified" component) out of every VaporWault package: end users
# installing a prebuilt binary package need the binary, not mbedTLS's
# static-link dev headers/.lib files. Verified empirically (TASK-146) — an
# earlier pass without CPACK_ARCHIVE_COMPONENT_INSTALL set produced a
# single non-component-partitioned archive that included mbedTLS's
# include/lib tree; every generator family needs its OWN
# "*_COMPONENT_INSTALL" flag for component mode (and thus this exclusion)
# to actually take effect — DEB/RPM/WIX have theirs set below/in
# TASK-147/148; ARCHIVE (TGZ/ZIP) needs its own. (release.yml's EXISTING
# tarball/zip step does not go through CPack at all — it copies
# build/bin/* directly — so this doesn't touch that; ARCHIVE mode here is
# purely for local `cpack -G TGZ` verification of the component split,
# which is how this bug was actually caught.)
set(CPACK_COMPONENTS_ALL server client)
set(CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE OFF)
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
# CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE alone did not stop the ARCHIVE
# generator family (TGZ/ZIP) from bundling both components into one file —
# verified empirically (TASK-146): `cpack --verbose` showed "[TGZ]
# requested component grouping = ALL_COMPONENTS_IN_ONE" regardless. The
# generator-family-agnostic knob that actually controls this is
# CPACK_COMPONENTS_GROUPING; IGNORE means "one package per component,
# ignore any CPACK_COMPONENT_<name>_GROUP association" — which is what we
# want since server/client are deliberately never grouped together.
set(CPACK_COMPONENTS_GROUPING IGNORE)

set(CPACK_COMPONENT_SERVER_DISPLAY_NAME "VaporWault Server")
set(CPACK_COMPONENT_SERVER_DESCRIPTION
    "VaporWault server: vapourwaultd, the admin CLI, vwdump, and (if built) the server GUI.")
set(CPACK_COMPONENT_CLIENT_DISPLAY_NAME "VaporWault Client")
set(CPACK_COMPONENT_CLIENT_DESCRIPTION
    "VaporWault client sync daemon, CLI, and (if built) the client GUI.")

# ── DEB (TASK-149) ───────────────────────────────────────────────────────────
set(CPACK_DEB_COMPONENT_INSTALL ON)
# Standard "<package>_<version>_<arch>.deb" naming instead of CPack's
# generic default (verified empirically, TASK-149: without this the
# per-component DEB_PACKAGE_NAME below only changed the package's internal
# `Package:` metadata field, not the physical filename).
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
set(CPACK_DEBIAN_SERVER_PACKAGE_NAME "vapourwault-server")
set(CPACK_DEBIAN_CLIENT_PACKAGE_NAME "vapourwault-client")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
# Maintainer scripts. Files must be named exactly "postinst"/"prerm"/
# "postrm" (no extension) -- dpkg looks them up by that literal name
# inside the control archive, so CPACK_DEBIAN_<COMPONENT>_PACKAGE_CONTROL_EXTRA
# entries are NOT renamed, just copied as-is; see
# packaging/linux/scripts/{server,client}/ for the bare-named scripts and
# TASK-149's implementation note for why the client side is deliberately
# near-empty (client daemon is a per-user service, not system-wide).
set(CPACK_DEBIAN_SERVER_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/server/postinst"
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/server/prerm"
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/server/postrm")
set(CPACK_DEBIAN_CLIENT_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/client/postinst"
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/client/prerm"
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/client/postrm")

# ── RPM (TASK-150) ───────────────────────────────────────────────────────────
set(CPACK_RPM_COMPONENT_INSTALL ON)
# Standard "<package>-<version>-<release>.<arch>.rpm" naming instead of
# CPack's generic default — same "*_PACKAGE_NAME only changes internal
# metadata, not the filename" surprise TASK-149 hit for DEB.
set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
set(CPACK_RPM_SERVER_PACKAGE_NAME "vapourwault-server")
set(CPACK_RPM_CLIENT_PACKAGE_NAME "vapourwault-client")
# rpmbuild requires a License tag; this project has no declared license yet
# (no LICENSE file at repo root as of TASK-150's filing) — TASK-150 must
# resolve this with the project owner before shipping real RPMs, not guess.
set(CPACK_RPM_PACKAGE_LICENSE "TBD")
# Scriptlets. %post/%preun reuse the DEB postinst/prerm scripts directly —
# their logic is idempotent and doesn't depend on DEB's argument
# convention, so nothing DEB-specific to translate. %postun is NOT shared
# (see rpm/server-postun.sh's header comment: RPM's $1 install-count
# convention is the opposite kind of signal from DEB's postrm action
# string, and RPM has no "purge" distinct from final removal at all).
set(CPACK_RPM_SERVER_POST_INSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/server/postinst")
set(CPACK_RPM_SERVER_PRE_UNINSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/server/prerm")
set(CPACK_RPM_SERVER_POST_UNINSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/rpm/server-postun.sh")
set(CPACK_RPM_CLIENT_POST_INSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/client/postinst")
set(CPACK_RPM_CLIENT_PRE_UNINSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/client/prerm")
set(CPACK_RPM_CLIENT_POST_UNINSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/linux/scripts/client/postrm")

# ── WIX / MSI (Windows, TASK-147/148) ────────────────────────────────────────
# Per-component CPACK_WIX_UPGRADE_GUID and service/scheduled-task fragments
# are set by TASK-147 (server) and TASK-148 (client) below this point.

include(CPack)
