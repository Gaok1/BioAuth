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
{ config, lib, pkgs, utils, ... }:

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

    boot = {
      enable = lib.mkEnableOption ''
        unlocking encrypted volumes from a phone on the USB cable during early
        boot.

        The phone is an *alternative* to the passphrase, never a replacement:
        every failure path here leaves the normal prompt in place
      '';

      verifierId = lib.mkOption {
        type = lib.types.str;
        default = "";
        example = "9f2c1d8e4b6a";
        description = ''
          Desktop id this machine was paired under, as stored by the phone.

          Early boot has no agent to ask, so the id has to be written down.
          `phone-auth status` prints it on a running system.
        '';
      };

      verifierName = lib.mkOption {
        type = lib.types.str;
        default = config.networking.hostName;
        defaultText = lib.literalExpression "config.networking.hostName";
        description = ''
          Name shown in the phone's biometric prompt while booting. It is the
          only cue the user has that the request came from their own machine.
        '';
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 8765;
        description = ''
          TCP port the initrd listens on over the cable. The phone finds the
          address on its own but not the port, so this must stay the port the
          pairing record carries.
        '';
      };

      timeout = lib.mkOption {
        type = lib.types.ints.between 1 300;
        default = 60;
        description = ''
          Seconds to wait for the phone before falling back to the passphrase
          prompt. The clock covers plugging the cable in, turning USB tethering
          on and approving with a fingerprint, so it is not only transfer time.
        '';
      };

      identityFile = lib.mkOption {
        type = lib.types.path;
        default = "${systemRoot}/initrd/identity.pkcs8";
        description = ''
          Private handshake key the initrd authenticates with.

          Copied into the initrd by {option}`boot.initrd.secrets`, which
          appends it at `nixos-rebuild` time and keeps it out of the Nix store
          — a store path is world-readable, which would hand this key to every
          local user. It still lands on unencrypted boot media, so it is a
          secret against the cable, not against someone holding the disk.
        '';
      };

      storeFile = lib.mkOption {
        type = lib.types.path;
        default = "${systemRoot}/initrd/devices.json";
        description = ''
          Pairing store the initrd reads: public keys and policy only. It says
          which phone may be asked, so it must not be writable by anyone who is
          not already root.
        '';
      };

      usbTether.enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Configure the USB tether link in the initrd: the drivers Android's
          RNDIS/NCM gadget needs, and DHCP on whatever interface they bind.

          The phone is the DHCP server and the only other host on that subnet,
          so this needs no network of any kind — which is the point at boot,
          where there usually is none. IPv6, DNS and default routes from the
          phone are all refused: the cable is a link to one host, not an
          uplink.
        '';
      };

      volumes = lib.mkOption {
        default = { };
        example = lib.literalExpression ''
          { cryptroot.wrappedKeyFile = "/var/lib/phone-auth/initrd/cryptroot.cbor"; }
        '';
        description = ''
          Volumes a phone may unlock, keyed by the mapped name used in
          {option}`boot.initrd.luks.devices`. LUKS1 and LUKS2 both work: the
          keyslot is an ordinary passphrase slot and nothing here uses a LUKS2
          token.

          Every volume must keep a separate, tested, offline recovery keyslot.
        '';
        type = lib.types.attrsOf (lib.types.submodule ({ name, ... }: {
          options = {
            wrappedKeyFile = lib.mkOption {
              type = lib.types.path;
              description = ''
                Public wrapped volume credential written by
                `phone-auth luks enroll`: a binding, a credential id and an
                opaque wrapper. No disk key, no private key.
              '';
            };

            credential = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Which disk-unlock credential to use. Only needed when more than
                one phone is enrolled: the initrd refuses to guess rather than
                let file order decide which phone opens the machine.
              '';
            };

            displayName = lib.mkOption {
              type = lib.types.str;
              default = name;
              description = ''
                Volume name shown in the phone's prompt. The user approves this
                string, so it should say what is being opened.
              '';
            };
          };
        }));
      };
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
    (lib.mkIf cfg.boot.enable (
      let
        # systemd-cryptsetup reads a key from a file, or it asks the user. That
        # is the whole fallback design: this script writes the file only when
        # the phone actually answered, and never fails the boot when it did not.
        keyFile = name: "/run/phone-auth/${name}.key";

        unlockScript = pkgs.writeShellScript "phone-auth-boot-unlock" ''
          set -u
          volume="$1"
          key="$2"
          shift 2

          umask 077
          if ${cfg.package}/bin/phone-auth-initrd "$@" > "$key.partial"; then
            mv "$key.partial" "$key"
          else
            status=$?
            rm -f "$key.partial"
            echo "phone-auth: no key for $volume (exit $status);" \
                 "the passphrase prompt stands" >&2
          fi

          # Always zero. A declined request, a phone that is not on the cable
          # and a phone that is flat are all fallbacks, not failed boots.
          exit 0
        '';

        cryptUnit = name:
          "systemd-cryptsetup@${utils.escapeSystemdPath name}.service";

        unlockUnits = lib.mapAttrs' (name: volume:
          lib.nameValuePair "phone-auth-unlock-${name}" {
            description = "Ask a paired phone to unlock ${name}";

            # Ordered inside the dependency window of the cryptsetup unit, so
            # the key exists before the volume is opened, and the prompt is
            # still there when it does not.
            before = [ (cryptUnit name) ];
            wantedBy = [ (cryptUnit name) ];
            after = [ "network-online.target" ];
            wants = [ "network-online.target" ];
            unitConfig.DefaultDependencies = false;

            serviceConfig = {
              Type = "oneshot";
              # The key file lives in this runtime directory. Letting systemd
              # remove it when the unit stops would take it away before
              # cryptsetup has read it.
              RemainAfterExit = true;
              RuntimeDirectory = "phone-auth";
              RuntimeDirectoryMode = "0700";
              UMask = "0077";
              ExecStart = lib.escapeShellArgs ([
                unlockScript
                volume.displayName
                (keyFile name)
                "--volume" volume.displayName
                "--store" "/etc/phone-auth/devices.json"
                "--identity" "/etc/phone-auth/identity.pkcs8"
                "--wrapped-key" "/etc/phone-auth/${name}.cbor"
                "--verifier-id" cfg.boot.verifierId
                "--verifier-name" cfg.boot.verifierName
                "--port" (toString cfg.boot.port)
                "--timeout" (toString cfg.boot.timeout)
              ] ++ lib.optionals (volume.credential != null) [
                "--credential" volume.credential
              ]);
            };
          }) cfg.boot.volumes;

        # /run is handed to the real system at switch-root, so a disk key left
        # in it does not stay behind in the initrd: it boots with the machine.
        # This unit is what keeps a 32-byte volume key out of the running
        # system.
        shredUnit = {
          phone-auth-shred-keys = {
            description = "Remove disk keys before handing /run to the system";
            after = [ "cryptsetup.target" ];
            before = [ "initrd-switch-root.target" ];
            wantedBy = [ "initrd-switch-root.target" ];
            unitConfig.DefaultDependencies = false;
            serviceConfig = {
              Type = "oneshot";
              ExecStart = "${pkgs.coreutils}/bin/rm -rf /run/phone-auth";
            };
          };
        };
      in
      {
        assertions = [
          {
            assertion = config.boot.initrd.systemd.enable;
            message = ''
              services.phone-auth.boot.enable needs boot.initrd.systemd.enable.
              The unlock runs as a unit ordered against systemd-cryptsetup, and
              the scripted initrd has neither.
            '';
          }
          {
            assertion = cfg.boot.verifierId != "";
            message = ''
              services.phone-auth.boot.verifierId is empty. Early boot has no
              agent to ask which desktop this is, so the id the phone stored
              has to be written down; `phone-auth status` prints it.
            '';
          }
          {
            assertion = cfg.boot.volumes != { };
            message = ''
              services.phone-auth.boot.enable is on with no volumes, which
              installs a boot-time listener that can never unlock anything.
            '';
          }
        ] ++ lib.mapAttrsToList (name: _: {
          assertion = config.boot.initrd.luks.devices ? ${name};
          message = ''
            services.phone-auth.boot.volumes.${name} has no matching
            boot.initrd.luks.devices.${name}. The unlock is ordered against the
            cryptsetup unit of that volume, and there is none.
          '';
        }) cfg.boot.volumes;

        # The USB gadget of an Android phone arrives as one of these. Matching
        # the driver rather than the interface name keeps it working whether
        # the kernel calls the link usb0 or enp0s20f0u1.
        boot.initrd.availableKernelModules =
          lib.mkIf cfg.boot.usbTether.enable [
            "usbnet"
            "rndis_host"
            "cdc_ether"
            "cdc_ncm"
            "cdc_eem"
          ];

        boot.initrd.network.enable = lib.mkDefault true;

        boot.initrd.systemd.network.networks."40-phone-auth-usb" =
          lib.mkIf cfg.boot.usbTether.enable {
            matchConfig.Driver = "rndis_host cdc_ether cdc_ncm cdc_eem";
            # The DHCP server runs on the phone, at the other end of the cable,
            # so this needs no network of any kind, which is the point at boot
            # where there is none. It is also not an uplink: no DNS, no default
            # route, no IPv6.
            networkConfig = {
              DHCP = "ipv4";
              IPv6AcceptRA = false;
              LinkLocalAddressing = "no";
            };
            dhcpV4Config = {
              UseDNS = false;
              UseNTP = false;
              UseGateway = false;
              UseRoutes = false;
            };
            linkConfig.RequiredForOnline = "routable";
          };

        # Appended to the initrd at nixos-rebuild time instead of going through
        # the store, which is world-readable. The handshake key is the one file
        # here that must not be public.
        boot.initrd.secrets = {
          "/etc/phone-auth/identity.pkcs8" = cfg.boot.identityFile;
          "/etc/phone-auth/devices.json" = cfg.boot.storeFile;
        } // lib.mapAttrs' (name: volume:
          lib.nameValuePair "/etc/phone-auth/${name}.cbor" volume.wrappedKeyFile
        ) cfg.boot.volumes;

        boot.initrd.systemd.storePaths = [
          "${cfg.package}/bin/phone-auth-initrd"
          unlockScript
          "${pkgs.coreutils}/bin/rm"
        ];

        boot.initrd.systemd.services = unlockUnits // shredUnit;

        # mkDefault throughout: a machine that already unlocks this volume some
        # other way keeps its own configuration, and the phone is an addition.
        boot.initrd.luks.devices = lib.mapAttrs (name: _: {
          keyFile = lib.mkDefault (keyFile name);
          keyFileTimeout = lib.mkDefault cfg.boot.timeout;
        }) cfg.boot.volumes;
      }
    ))
  ]);

  meta.maintainers = [ ];
}
