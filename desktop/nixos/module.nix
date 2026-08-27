# NixOS module for PhoneAuth.
#
# Two agents, on purpose.
#
#   * The *system* agent authenticates things that grant root: sudo, login,
#     display-manager unlock. Its pairing store lives in /var/lib/phone-auth
#     and is root-owned, because a user who can edit the file that says which
#     phones may approve sudo can simply add their own phone.
#
#   * The *user* agent backs the tray and any user-level flow. Its store is in
#     the user's home, where the user is already the trust anchor.
#
# Running only the user agent and pointing PAM at it would look like it works
# and would be a privilege escalation.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.phone-auth;

  systemRoot = "/var/lib/phone-auth";

  # Translates pam_exec's environment into CLI arguments.
  #
  # pam_exec passes PAM_USER, PAM_SERVICE and PAM_RUSER in the environment and
  # takes no substitutions in its argument list, so the mapping has to happen
  # in a wrapper.
  pamHelper = pkgs.writeShellScript "phone-auth-pam" ''
    set -eu

    # Fail closed. PAM reads any zero exit as success, so an unset variable
    # must never reach the CLI as an empty argument.
    : "''${PAM_USER:?PAM_USER is not set}"
    : "''${PAM_SERVICE:?PAM_SERVICE is not set}"

    action="''${PAM_SERVICE}"
    if [ -n "''${PAM_RUSER:-}" ]; then
      action="''${PAM_SERVICE} (from ''${PAM_RUSER})"
    fi

    exec ${cfg.package}/bin/phone-auth authorize \
      --root ${systemRoot} \
      --service "''${PAM_SERVICE}" \
      --action "$action" \
      --resource "$(${pkgs.nettools}/bin/hostname)" \
      --user "''${PAM_USER}"
  '';

  # `sufficient` lets PhoneAuth satisfy authentication on its own while leaving
  # the password rule below it as a fallback. `required` makes the phone a
  # second factor that cannot be skipped — and locks the account out if the
  # phone is unavailable, which is why it is not the default.
  pamControl = if cfg.pam.required then "required" else "sufficient";

  pamRule = ''
    auth ${pamControl} pam_exec.so quiet ${pamHelper}
  '';
in
{
  options.services.phone-auth = {
    enable = lib.mkEnableOption "the PhoneAuth verifier agent";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { withTray = cfg.tray.enable; };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The PhoneAuth package to install.";
    };

    verifierName = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "Desktop-Casa";
      description = ''
        Name shown on the phone when it asks the user to approve. This is the
        main cue a user has to notice a request from a machine that is not
        theirs, so prefer something recognisable over the hostname.

        Null keeps whatever is already in the agent's config file.
      '';
    };

    system.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Run the root-owned agent used by PAM. Required for
        {option}`services.phone-auth.pam.services` to mean anything.
      '';
    };

    tray.enable = lib.mkOption {
      type = lib.types.bool;
      default = config.services.xserver.enable or false;
      defaultText = lib.literalExpression "config.services.xserver.enable";
      description = "Run the Electron tray UI in the user session.";
    };

    pam.services = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "sudo" "login" ];
      description = ''
        PAM services that may be authenticated by a paired phone.

        ::: {.warning}
        Do not add every service at once. Add `sudo` first, confirm it works
        and that the password fallback still works, and keep a root shell open
        while you test. A misconfigured PAM stack can lock you out of the
        machine.
        :::
      '';
    };

    pam.required = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Make the phone mandatory rather than an alternative to the password.

        This turns a lost or flat phone into a lockout. Only enable it once you
        have a tested recovery path that does not involve the phone.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      environment.systemPackages = [ cfg.package ];

      # Readers of the system agent's endpoint file. Membership means being
      # able to ask the system agent for an authorization, so it is not
      # granted to anyone by default.
      users.groups.phone-auth = { };
    }

    (lib.mkIf cfg.system.enable {
      systemd.services.phone-auth-agent = {
        description = "PhoneAuth verifier agent (system)";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];

        serviceConfig = {
          Type = "simple";
          ExecStart = "${cfg.package}/bin/phone-auth-agent --root ${systemRoot}";
          Restart = "on-failure";
          RestartSec = 2;

          StateDirectory = "phone-auth";
          RuntimeDirectory = "phone-auth";
          # pam_exec runs as root and reads the endpoint file; nothing else
          # needs to.
          UMask = "0077";

          # The agent parses bytes from an untrusted peer and holds the
          # decision that guards root. Give it as little as it can run with.
          DynamicUser = false;
          User = "root";
          NoNewPrivileges = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
          # Loopback only today. A real transport will need this widened, and
          # that change belongs in the same review as the transport itself.
          RestrictAddressFamilies = [ "AF_INET" "AF_UNIX" ];
          IPAddressAllow = [ "localhost" ];
          IPAddressDeny = "any";
          CapabilityBoundingSet = [ "" ];
        };
      };
    })

    (lib.mkIf (cfg.pam.services != [ ]) {
      assertions = [
        {
          assertion = cfg.system.enable;
          message = ''
            services.phone-auth.pam.services is set but
            services.phone-auth.system.enable is false. PAM runs as root and
            cannot reach a per-user agent, so the rules would always fail.
          '';
        }
      ];

      security.pam.services = lib.genAttrs cfg.pam.services (_: {
        text = lib.mkBefore pamRule;
      });
    })

    (lib.mkIf cfg.tray.enable {
      systemd.user.services.phone-auth-tray = {
        description = "PhoneAuth tray";
        wantedBy = [ "graphical-session.target" ];
        partOf = [ "graphical-session.target" ];
        after = [ "graphical-session.target" ];

        serviceConfig = {
          Type = "simple";
          ExecStart = "${cfg.package}/bin/phone-auth-tray";
          Restart = "on-failure";
          RestartSec = 3;
        };
      };

      # The user agent, which the tray talks to. Separate store, separate
      # authority; it never satisfies a PAM rule.
      systemd.user.services.phone-auth-agent = {
        description = "PhoneAuth verifier agent (user session)";
        wantedBy = [ "default.target" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = "${cfg.package}/bin/phone-auth-agent";
          Restart = "on-failure";
          RestartSec = 2;
        };
      };
    })

    (lib.mkIf (cfg.verifierName != null) {
      # Written before the agent starts so that first run picks it up rather
      # than defaulting to the hostname.
      systemd.services.phone-auth-agent.preStart = lib.mkIf cfg.system.enable ''
        config=${systemRoot}/config/agent.json
        if [ -f "$config" ]; then
          ${pkgs.jq}/bin/jq --arg name ${lib.escapeShellArg cfg.verifierName} \
            '.verifierName = $name' "$config" > "$config.tmp"
          mv "$config.tmp" "$config"
        fi
      '';
    })
  ]);

  meta.maintainers = [ ];
}
