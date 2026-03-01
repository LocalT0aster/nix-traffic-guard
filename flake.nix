{
  description = "TrafficGuard - iptables/ipset scanner blocking utility";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { ... }: {
    nixosModules.default =
      {
        config,
        lib,
        pkgs,
        ...
      }:
      let
        cfg = config.services.traffic-guard;

        quotedUrls = lib.concatMapStringsSep "\n" (u: "  " + lib.escapeShellArg u) cfg.urls;

        logRuleV4 = ''
          ${pkgs.iptables}/bin/iptables -A SCANNERS-BLOCK \
            -m set --match-set SCANNERS-BLOCK-V4 src \
            -m limit --limit 10/min --limit-burst 5 \
            -j LOG --log-prefix "ANTISCAN-v4: " --log-level 4
        '';

        logRuleV6 = ''
          ${pkgs.iptables}/bin/ip6tables -A SCANNERS-BLOCK \
            -m set --match-set SCANNERS-BLOCK-V6 src \
            -m limit --limit 10/min --limit-burst 5 \
            -j LOG --log-prefix "ANTISCAN-v6: " --log-level 4
        '';

        applyRulesScript = pkgs.writeShellScript "traffic-guard-apply-rules.sh" ''
          set -euo pipefail

          ipset_conf="${cfg.stateDir}/ipset.conf"
          if [ ! -f "$ipset_conf" ]; then
            echo "traffic-guard: skip apply, missing $ipset_conf"
            exit 0
          fi

          ${pkgs.ipset}/bin/ipset restore -exist -file "$ipset_conf"

          ${pkgs.iptables}/bin/iptables -N SCANNERS-BLOCK 2>/dev/null || true
          ${pkgs.iptables}/bin/iptables -F SCANNERS-BLOCK
          ${pkgs.iptables}/bin/iptables -C INPUT -j SCANNERS-BLOCK 2>/dev/null || \
            ${pkgs.iptables}/bin/iptables -I INPUT 1 -j SCANNERS-BLOCK

          ${lib.optionalString cfg.enableLogging logRuleV4}
          ${pkgs.iptables}/bin/iptables -A SCANNERS-BLOCK \
            -m set --match-set SCANNERS-BLOCK-V4 src -j DROP

          ${pkgs.iptables}/bin/ip6tables -N SCANNERS-BLOCK 2>/dev/null || true
          ${pkgs.iptables}/bin/ip6tables -F SCANNERS-BLOCK
          ${pkgs.iptables}/bin/ip6tables -C INPUT -j SCANNERS-BLOCK 2>/dev/null || \
            ${pkgs.iptables}/bin/ip6tables -I INPUT 1 -j SCANNERS-BLOCK

          ${lib.optionalString cfg.enableLogging logRuleV6}
          ${pkgs.iptables}/bin/ip6tables -A SCANNERS-BLOCK \
            -m set --match-set SCANNERS-BLOCK-V6 src -j DROP
        '';

        refreshScript = pkgs.writeShellScript "traffic-guard-refresh.sh" ''
          set -euo pipefail

          mkdir -p ${lib.escapeShellArg cfg.stateDir}
          tmp_dir="$(${pkgs.coreutils}/bin/mktemp -d)"
          trap '${pkgs.coreutils}/bin/rm -rf "$tmp_dir"' EXIT

          merged="$tmp_dir/merged.list"
          clean="$tmp_dir/clean.list"
          ipset_new="${cfg.stateDir}/ipset.conf.new"
          ipset_conf="${cfg.stateDir}/ipset.conf"

          : > "$merged"

          urls=(
        ${quotedUrls}
          )

          for url in "''${urls[@]}"; do
            echo "traffic-guard: downloading $url"
            ${pkgs.curl}/bin/curl --fail --silent --show-error --location "$url" >> "$merged"
            echo >> "$merged"
          done

          ${pkgs.gawk}/bin/awk '
            {
              sub(/\r$/, "");
            }
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*$/ { next }
            {
              gsub(/^[[:space:]]+|[[:space:]]+$/, "");
              print;
            }
          ' "$merged" | ${pkgs.coreutils}/bin/sort -u > "$clean"

          {
            echo "create SCANNERS-BLOCK-V4 hash:net family inet hashsize 1024 maxelem 262144 -exist"
            echo "create SCANNERS-BLOCK-V6 hash:net family inet6 hashsize 1024 maxelem 131072 -exist"
            echo "flush SCANNERS-BLOCK-V4"
            echo "flush SCANNERS-BLOCK-V6"

            while IFS= read -r subnet; do
              case "$subnet" in
                *:*)
                  echo "add SCANNERS-BLOCK-V6 $subnet"
                  ;;
                *.*)
                  echo "add SCANNERS-BLOCK-V4 $subnet"
                  ;;
              esac
            done < "$clean"
          } > "$ipset_new"

          ${pkgs.coreutils}/bin/mv "$ipset_new" "$ipset_conf"
          ${pkgs.coreutils}/bin/chmod 0644 "$ipset_conf"

          ${applyRulesScript}
        '';
      in
      {
        options.services.traffic-guard = {
          enable = lib.mkEnableOption "TrafficGuard declarative iptables/ipset protection";

          urls = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            example = [
              "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list"
              "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list"
            ];
            description = ''
              List URLs (same idea as repeated `-u`) that contain CIDR blocks.
              Lists are downloaded on `nixos-rebuild switch/test`.
            '';
          };

          enableLogging = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Add iptables/ip6tables LOG rule before DROP with rate limit (10/min, burst 5).";
          };

          stateDir = lib.mkOption {
            type = lib.types.str;
            default = "/var/lib/traffic-guard";
            description = "Directory where generated ipset state is cached.";
          };
        };

        config = lib.mkIf cfg.enable {
          assertions = [
            {
              assertion = cfg.urls != [ ];
              message = "services.traffic-guard.urls must contain at least one URL.";
            }
            {
              assertion = !config.networking.nftables.enable;
              message = "services.traffic-guard currently expects iptables backend; disable nftables or extend the module.";
            }
          ];

          boot.kernelModules = [ "ip_set_hash_net" ];

          systemd.tmpfiles.rules = [
            "d ${cfg.stateDir} 0755 root root -"
          ];

          # Lightweight restore at boot (no downloads).
          systemd.services.traffic-guard-restore = {
            description = "TrafficGuard restore ipset/iptables from cached state";
            wantedBy = [ "multi-user.target" ];
            after = [ "firewall.service" ];
            wants = [ "firewall.service" ];
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
            };
            script = "${applyRulesScript}";
          };

          # Full refresh with URL downloads, triggered on nixos-rebuild switch/test.
          systemd.services.traffic-guard-refresh = {
            description = "TrafficGuard refresh lists and apply rules";
            serviceConfig = {
              Type = "oneshot";
            };
            script = "${refreshScript}";
          };

          system.activationScripts.traffic-guard-refresh = lib.stringAfter [ "restart-systemd" ] ''
            if [ "''${NIXOS_ACTION:-}" = "switch" ] || [ "''${NIXOS_ACTION:-}" = "test" ]; then
              echo "traffic-guard: refreshing lists for action=$NIXOS_ACTION"
              ${pkgs.systemd}/bin/systemctl start traffic-guard-refresh.service
            fi
          '';
        };
      };
  };
}
