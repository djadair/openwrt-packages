{%
// Template for banip block chain table.
//
// Since the table is flushed rather than deleted any existing block sets
// will NOT be removed, nft will silently ignore the empty ones created here.
//
// An updated configuration may add or remove source tables atomically but
// no longer referenced ip lists must be manually removed AFTER the update.
//

 if ( type(config) != "object" ) {
     warn("banrules.uc:  called directly, sets not configured\n");
     let banip = require("bancfg");
     banip.load();
     config = banip.state.config;
     runtime = banip.state.runtime;

     // This is purposely inside config check so we can
     // print with no set elements by passing source null.
     if ( type(source) != "object" ) {
	 if ( type(banip?.source) == "object" ) {
	     source = banip.source;
	 } else {
	     source = require("bansource");
	     source.load( config );
	 }
     }

 };
 warn("\nRendering banIP ruleset\n");
 warn("config: " + config + "\n\n");
 warn("runtime: " + runtime + "\n\n");
 let rule_ctr = "";
-%}

table inet {{ config.ban_chain }}
flush table inet {{ config.ban_chain }}

add set inet {{ config.ban_chain }} ban_ifaces { typeof iifname; }
flush set inet {{ config.ban_chain }} ban_ifaces

{% // Flush all known sets, add is ignored if it exists
 for (let name, set in runtime.ipsets):
     if (! ( set.src || set.dst ) ) {
       continue;
     }
      // All sets refernced by rules
%}
add set inet {{ config.ban_chain }} {{ name }} {
	    typeof {{ runtime.ban_match[ `src${set.proto}` ] }}
{%   if (set.flags != null): %}
	    flags {{ set.flags }}
	    auto-merge
{%   endif
     if (set.timeout > 0): %}
            timeout {{ set.timeout }}
{%   endif %}
{%   if (set.counter): %}
	    counter
{%   endif %}
	}
flush set inet {{ config.ban_chain }} {{ name }}
{% endfor %}

table inet {{ config.ban_chain }} {

{%
//  A verdict map would be more efficient but nft list can not
//  parse it so save/restore would be broken.
//  Likewise iif/oif is faster but can not work with transient
//  interfaces such as tun0.
//  example:
//	map banmapin {
//	    typeof iif . meta nfproto : verdict
//	    elements = {
// {% for (let ifc in runtime.ban_devs): %}
//  	   	{{ ifc }} . ipv4 : goto banIP_src_4,
//  		{{ ifc }} . ipv6 : goto banIP_src_6,
// {% endfor %}
//	    }
//	}
%}
	set ban_ifaces {
      		typeof iifname
		elements = {
{% for (let ifc in runtime.ban_devs): %}
	  	   	{{ ifc }},
{% endfor %}
		}
	}

	# hook after fw4 so we only process traffic that has been
	# accepted.
	chain input {
		type filter hook input priority filter +10; policy accept;
		ct state established,related accept
{% if ( config.ban_autowhitelist ): %}
		# WAN whitelist has catch-22 if we dont get DHCP address.
		udp sport 67-68 udp dport 67-68 counter return
{% endif %}

{% if ( config.ban_proto4_enabled ): %}
 		iifname @ban_ifaces meta nfproto ipv4 goto banIP_src_4
{% endif
   if ( config.ban_proto6_enabled ): %}
		iifname @ban_ifaces meta nfproto ipv6 goto banIP_src_6
{% endif %}
	}

{% // hack set output chain in debug mode.
   if ( config.ban_debug ): %}
	chain output {
		type filter hook output priority filter +10; policy accept;
		ct state established,related accept
{% if ( config.ban_autowhitelist ): %}
 		# WAN whitelist has catch-22 if we dont get DHCP address.
		udp sport 67-68 udp dport 67-68 counter return
{% endif %}

{% if ( config.ban_proto4_enabled ): %}
 		oifname @ban_ifaces meta nfproto ipv4 goto banIP_dst_4
{% endif
   if ( config.ban_proto6_enabled ): %}
		oifname @ban_ifaces meta nfproto ipv6 goto banIP_dst_6
{% endif %}
                counter comment "banIP: iface mismatch"	    
	}

{% endif %}
	chain forward {
		type filter hook forward priority filter +10; policy accept;
		ct state established,related accept
{% if ( config.ban_proto4_enabled ): %}
		oifname @ban_ifaces meta nfproto ipv4 goto banIP_dst_4
 		iifname @ban_ifaces meta nfproto ipv4 goto banIP_src_4
{% endif
   if ( config.ban_proto6_enabled ): %}
		oifname @ban_ifaces meta nfproto ipv6 goto banIP_dst_6
		iifname @ban_ifaces meta nfproto ipv6 goto banIP_src_6
{% endif %}
	}


{% for ( let proto in [ "4", "6" ] ): %}
{%   if ( ( proto == 4 ) && !config.ban_proto4_enabled ):
       continue;
     endif %}
{%   if ( ( proto == 6 ) && !config.ban_proto6_enabled ):
       continue;
     endif %} 
{%   for ( let dir in [ "src", "dst" ] ): %}
{%
// Generate chain for each dir, proto
%}
	chain banIP_{{ dir }}_{{ proto }} {
		# speed up stuff useless to check
		ct state != new counter return

{%
//     Local sources always included even with whitelist-only
%}
{%     for (let name, set in runtime.ipsets):
         if (! ((set.local) &&
	        ((set.proto == proto) || ("mac" == set.proto)) &&
	        (( set.src && ("src" == dir)) ||
		 ( set.dst && ("dst" == dir))))) {
		 continue;
         }
	 rule_ctr = (set.counter ? " " : "counter ");

	 // matching local counters
%}
	        {{ runtime.ban_match[ `${dir}${set.proto}` ] }} @{{ name }} {{ rule_ctr }}{{ set.act[ dir ] }}
{%     endfor %}
{%
//     stop if whitelistonly
%}
{%     if ( config.ban_whitelistonly ): %}
      		{{ runtime.ban_action[ dir ] }}
{%       continue; %}		
{%     endif %}
{%
//     Otherwise create rules for each table
%}
{%     for (let name, set in runtime.ipsets):
         if (! ((! set.local) &&
	        ((set.proto == proto) || ("-" == set.proto)) &&
	        (( set.src && ("src" == dir)) ||
		 ( set.dst && ("dst" == dir))) &&
		 ( "country" != set.list))):
		 continue;
         endif // not matching non-local counters except country
	 rule_ctr = (set.counter ? " " : "counter ");
%}
	        {{ runtime.ban_match[ `${dir}${set.proto}` ] }} @{{ name }} {{ rule_ctr }}{{ set.act[ dir ] }}
{%     endfor

//     Country last so we can use country whitelist
%}
{%     let name = "country_" + proto;
       let set = runtime.ipsets[ name ];
       if ((set != null) &&
	   ((set.proto == proto) || ("-" == set.proto)) &&
	   (( set.src && ("src" == dir)) ||
	    ( set.dst && ("dst" == dir)))):

 	 rule_ctr = (set.counter ? " " : "counter ");
         if ( config.country_whitelist ):
%}
		{{ runtime.ban_match[ `${dir}${proto}` ] }} @{{ name }} accept
		counter {{ set.act[ dir ] }} comment "banIP: invalid country"
{%       else %}
	        {{ runtime.ban_match[ `${dir}${set.proto}` ] }} @{{ name }} {{ rule_ctr }}{{ set.act[ dir ] }}
{%       endif %}
{%     endif // have country
%}
	        counter comment "banIP: filtered dest"
	}

{%   endfor  // for dir
%}
{% endfor // for proto
%}

{% for (let name, set in runtime.ipsets):
     if (! ( set.src || set.dst ) ) {
       continue;
     }
      // All sets refernced by rules
%}
	set {{ name }} {
	    typeof {{ runtime.ban_match[ `src${set.proto}` ] }}
{%   if (set.flags != null): %}
	    flags {{ set.flags }}
	    auto-merge
{%   endif
     if (set.timeout > 0): %}
            timeout {{ set.timeout }}
{%   endif %}
{%   if (set.counter): %}
	    counter
{%   endif %}
{%   if ( source?.print_set != null ):
	    source.print_set( set.list, set.proto, true );
     endif %}	    
	}
	
{% endfor %}

        chain {{ config.ban_logchain_dst }} {
		limit rate 2/second burst 5 packets counter log prefix "[{{ runtime.ban_ver }}, dst/{{ config.ban_target_dst }}] "
		counter {{ lc(config.ban_target_dst) }}
	}

        chain {{ config.ban_logchain_src }} {
		limit rate 2/second burst 5 packets counter log prefix "[{{ runtime.ban_ver }}, src/{{ config.ban_target_src }}] "
		counter {{ lc(config.ban_target_src) }}
	}

}
