const fs = require("fs");
const uci = require("uci");
const ubus = require("ubus");
const fw4 = require("fw4");  // for parsers

const STATEFILE = "/var/run/banip.state";
const BAN_JSON_FILE = "ban_report.json";

const BAN_VER      = "0.8.1";

const PARSE_LIST   = 0x01;
const FLATTEN_LIST = 0x02;
const NO_INVERT    = 0x04;
const UNSUPPORTED  = 0x08;
const REQUIRED     = 0x10;
const DEPRECATED   = 0x20;

const ban_options = {
    ban_enabled: [ "bool", 0 ],
    ban_autodetect: [ "bool", 1 ],
    ban_proto4_enabled: [ "bool", 0 ],
    ban_proto6_enabled: [ "bool", 0 ],
    ban_debug: [ "bool", 0 ],
    ban_monitor_enabled: [ "bool", 0 ],
    ban_logsrc_enabled: [ "bool", 0 ],
    ban_logdst_enabled: [ "bool", 0 ],
    ban_autoblacklist:  [ "bool", 1 ],
    ban_autowhitelist:  [ "bool", 1 ],
    ban_whitelistonly:  [ "bool", 0 ],
    ban_maxqueue: [ "int", 4 ],
    ban_tmpbase: [ "string", "/tmp" ],
    ban_reportdir: [ "string", "/tmp/banIP-Report" ],
    ban_backupdir: [ "string", "/tmp/banIP-Backup" ],
    ban_mail_enabled: [ "bool", 0 ],
    ban_mailreceiver: [ "string" ],
    ban_mailsender:   [ "string", "no-reply@banIP" ],
    ban_mailtopic:    [ "string", "banIP notification" ],
    ban_mailprofile:  [ "string", "ban_notify" ],
    ban_ifaces: [ "string", null, PARSE_LIST | NO_INVERT ],
    ban_sources: [ "string", null, PARSE_LIST | NO_INVERT ],
    ban_countries: [ "string", null, PARSE_LIST | NO_INVERT ],
    ban_asns: [ "string", null, PARSE_LIST | NO_INVERT ],
    ban_country_whitelist: [ "bool", 0 ],
    
    ban_localsources: [ "string", [ "maclist", "whitelist", "blacklist" ], PARSE_LIST | NO_INVERT ],
    ban_extrasources: [ "string", null, PARSE_LIST | NO_INVERT ],
    ban_logterms:     [ "string", [ "dropbear", "sshd", "luci", "nginx" ], PARSE_LIST | NO_INVERT ],
    ban_loglimit:     [ "int", 100 ],
    ban_ssh_logcount: [ "int", 3 ],
    ban_luci_logcount: [ "int", 3 ],
    ban_nginx_logcount: [ "int", 3],
    ban_settype_src:  [ "string", null, PARSE_LIST | NO_INVERT ],
    ban_settype_dst:  [ "string", null, PARSE_LIST | NO_INVERT ],
    ban_settype_all:  [ "string", null, PARSE_LIST | NO_INVERT ],

    // We don't need these with NFT
    ban_lan_inputchains_4: [ "string", null, PARSE_LIST | NO_INVERT | DEPRECATED | UNSUPPORTED ],
    ban_lan_inputchains_6: [ "string", null, PARSE_LIST | NO_INVERT | DEPRECATED | UNSUPPORTED ],
    ban_lan_forwardchains_4: [ "string", null, PARSE_LIST | NO_INVERT | DEPRECATED | UNSUPPORTED ],
    ban_lan_forwardchains_6: [ "string", null, PARSE_LIST | NO_INVERT | DEPRECATED | UNSUPPORTED ],
    ban_wan_inputchains_4: [ "string", null, PARSE_LIST | NO_INVERT | DEPRECATED | UNSUPPORTED ],
    ban_wan_inputchains_6: [ "string", null, PARSE_LIST | NO_INVERT | DEPRECATED | UNSUPPORTED ],
    ban_wan_forwardchains_4: [ "string", null, PARSE_LIST | NO_INVERT | DEPRECATED | UNSUPPORTED ],
    ban_wan_forwardchains_6: [ "string", null, PARSE_LIST | NO_INVERT | DEPRECATED | UNSUPPORTED ],

    ban_logchain_src: [ "string", "banIP_log_src" ],
    ban_logchain_dst: [ "string", "banIP_log_dst" ],
    // Used for table name
    ban_chain: [ "string", "banIP" ],
    ban_global_settype: [ "ban_settype", "src+dst" ],
    ban_target_src: [ "string", "drop" ],
    ban_target_dst: [ "string", "reject" ],
    ban_fetchutil: [ "string", "-" ],
    ban_fetchparm: [ "string", "-" ],
    ban_fetchinsecure: [ "bool", 0 ],
    ban_srcarc: [ "string", "/etc/banip/banip.sources.gz" ],
    ban_maclist_timeout: [ "int", 0 ],
    ban_whitelist_timout: [ "int", 0],
    ban_blacklist_timout: [ "int", 0],

    ban_nice: [ "int", 0, DEPRECATED | UNSUPPORTED ],
    ban_trigger: [ "string", null, DEPRECATED | UNSUPPORTED],
    ban_triggerdelay: [ "int", 5, DEPRECATED | UNSUPPORTED]
};

function to_mask(bits, v6) {
    let m = [], n = false;

    if (bits < 0) {
	n = true;
	bits = -bits;
    }

    if (bits > (v6 ? 128 : 32))
	return null;

    for (let i = 0; i < (v6 ? 16 : 4); i++) {
	let b = (bits < 8) ? bits : 8;
	m[i] = (n ? ~(0xff << (8 - b)) : (0xff << (8 - b))) & 0xff;
	bits -= b;
    }

    return arrtoip(m);
}

function to_bits(mask) {
    let a = iptoarr(mask);

    if (!a)
	return null;

    let bits = 0;

    for (let i = 0, z = false; i < length(a); i++) {
	z ||= !a[i];

	while (!z && (a[i] & 0x80)) {
	    a[i] = (a[i] << 1) & 0xff;
	    bits++;
	}

	if (a[i])
	    return null;
    }

    return bits;
}

function apply_mask(addr, mask) {
    let a = iptoarr(addr);

    if (!a)
	return null;

    if (type(mask) == "int") {
	for (let i = 0; i < length(a); i++) {
	    let b = (mask < 8) ? mask : 8;
	    a[i] &= (0xff << (8 - b)) & 0xff;
	    mask -= b;
	}
    }
    else {
	let m = iptoarr(mask);

	if (!m || length(a) != length(m))
	    return null;

	for (let i = 0; i < length(a); i++)
	    a[i] &= m[i];
    }

    return arrtoip(a);
}

// From fw4, counters not present in terse output.
function nft_json_command(full, ...args) {
    let cmd = [ ];
    if (full)
	cmd = [ "/usr/sbin/nft", "--json", ...args ];
    else
	cmd = [ "/usr/sbin/nft", "--terse", "--json", ...args ];
	
    let nft = fs.popen(join(" ", cmd), "r");
    let info;
    warn("cmd: " + join(" ", cmd) + "\n");
    if (nft) {
	try {
	    info = filter(json(nft.read("all"))?.nftables,
			  item => (type(item) == "object" && !item.metainfo));
	}
	catch (e) {
	    warn(`Unable to parse nftables JSON output: ${e}\n`);
	}

	nft.close();
    }
    else {
	warn(`Unable to popen() ${cmd}: ${fs.error()}\n`);
    }

    return info || [];
}


function parse_ban_settype (val, def) {
    let rval = fw4.parse_enum(val, [
	"src",
	"dst",
	"src+dst"
    ]);
    if ( rval == null )
	rval = def;
    return rval;
}

function translate_counter(state, ctr) {
    let rctr = {
	type: state.runtime.ipsets[ ctr.name ].mtype,
	count: 0,
	count_ip: 0,
	count_cidr: 0,
	count_range: 0,
	count_mac: 0,
	count_acc: 0,
	member_acc: [],
    };

    map(ctr.elem, e => {
	rctr.count++;
	let res = {
	    packets: e.packets,
	};
	
	if ( ctr.type == "ether_addr" ) {
	    rctr.count_mac++;
	    res.member = e.val;
	} else if (type(e.val?.prefix) == "object") {
	    rctr.count_cidr++;
	    res.member = "" + e.val?.prefix?.addr + "/" + e.val?.prefix?.len;
	} else if (type(e.val?.range) == "array") {
	    rctr.count_range++;
	    res.member = "" + e.val.range[0] + "-" + e.val.range[1];
	} else {
	    rctr.count_ip++;
	    res.member = e.val;
	}

	if (e.packets != 0) {
	    rctr.count_acc++;
	    push(rctr.member_acc, res);
	}
    });
    return rctr;
}

// Find physical devices where ban rules should
// be applied.  This requires config and ubus to
// already be loaded.  Not public because users should
// use result from state.runtime.ban_devs.
function get_ban_devs( state ) {
    let res = [];
    let nets = state.networks;
    let cfg = state.config;

	
    for ( let iface in cfg.ban_ifaces ) {
	for ( let name, obj in nets ) {
	    if ( obj?.physdev == null )
		continue;
	    // Be forgiving user might not understand
	    // interface -vs- device.
	    if (( name == iface ) ||
		( obj?.interface == iface ) ||
		( obj?.physdev == iface ) ||
		( obj?.device == iface ))
		push (res, obj.physdev);
	}
    }
    return uniq(res);
};

return 	{
    state: {
	config: {},     // banip uci conf
	networks: {},	// current network state
	board: {},	// ubus system.board info
	runtime: {},	// derived values for templates
	loaded: false
    },
    source: null,

    read_kernel_version: function() {
	let fd = fs.open("/proc/version", "r"),
	v = 0;

	if (fd) {
	    let m = match(fd.read("line"), /^Linux version ([0-9]+)\.([0-9]+)\.([0-9]+)/);
	    v = m ? (+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) : 0;
	    fd.close();
	}

	return v;
    },

    // Run nft command.
    nft_command: function( args ) {
	let cmd = [ "/usr/sbin/nft", ...args ];
	let nft = fs.popen(join(" ", cmd), "r");
	let res = -1;
	let info;
	
	warn("cmd: " + join(" ", cmd) + "\n");
	if (nft) {
		try {
		    info = nft.read("all");
		    res = nft.close();
		}
		catch (e) {
		    warn(`nft command failed: ${e}\n`);
		}
	}
	else {
		warn(`Unable to popen() ${cmd}: ${fs.error()}\n`);
	}

	if (res != 0) {
	    warn("nft command failed output: \n");
	    warn(info + "\n");
	    info = null;
	}

	return info;

    },

    run_command: function(fcn, ...args) {
	let cmd = [],
	    nft = {},
	    out = null,
	    res = -1;
    
	if (type(fcn) in [ "array", "object" ]) {
	    cmd = [ ...fcn, ...args ];
	} else {
	    cmd = [ fcn, ...args ];
	}
	warn("cmd: " + join(" ", cmd) + "\n");
	nft = fs.popen(join(" ", cmd), "r");

	if (nft) {
	    try {
		out = nft.read("all");
	    }
	    catch (e) {
		warn(`Unable to read command: ${e}\n`);
	    }
	    res = nft.close();
	    warn("close: " + res + "\n");
	}
	else {
	    warn(`Unable to popen() ${cmd}: ${fs.error()}\n`);
	}

	if ((res == 0) && (out != null))
	    return(split(out, "\n"));
	else
	    return(null);
    },

    read_ubus: function() {
	let self = this,
	    ifaces, board,
	    rules = [], networks = {},
	    bus = ubus.connect();

	if (bus) {
	    ifaces = bus.call("network.interface", "dump");
	    board = bus.call("system", "board");
	    bus.disconnect();
	}
	else {
	    warn(`Unable to connect to ubus: ${ubus.error()}\n`);
	}


	//
	// Gather logical network information from ubus
	//

	if (type(ifaces?.interface) == "array") {
	    for (let ifc in ifaces.interface) {
		let net = {
		    interface: ifc.interface,
		    up:        ifc.up,
		    device:    ifc.l3_device,
		    physdev:   ifc.device,
		    zone:      ifc.data?.zone,
		    
		    ipv4_public:   false,	// interface has active ipv4 default route
		    ipv4_inactive: false,	// interface has inactive ipv4 default route
		    ipv4_nexthop:  [],		// upstream gateway
		    ipv6_public:   false,	// interface has active ipv6 default route
		    ipv6_inactive: false,	// interface has inactive ipv6 default route
		    ipv6_nexthop:  []		// upstream gateway
		};

		if (type(ifc["ipv4-address"]) == "array") {
		    for (let addr in ifc["ipv4-address"]) {
			push(net.ipaddrs ||= [], {
				family: 4,
				addr: addr.address,
				mask: to_mask(addr.mask, false),
				bits: addr.mask
			    });
		    }
		}

		if (type(ifc["ipv6-address"]) == "array") {
		    for (let addr in ifc["ipv6-address"]) {
			push(net.ipaddrs ||= [], {
				family: 6,
				addr: addr.address,
				mask: to_mask(addr.mask, true),
				bits: addr.mask
			    });
		    }
		}

		if (type(ifc["ipv6-prefix-assignment"]) == "array") {
		    for (let addr in ifc["ipv6-prefix-assignment"]) {
			if (addr["local-address"]) {
			    push(net.ipaddrs ||= [], {
				    family: 6,
				    addr: addr["local-address"].address,
				    mask: to_mask(addr["local-address"].mask, true),
				    bits: addr["local-address"].mask
				});
			}
		    }
		}

		if (type(ifc["route"]) == "array") {
		    for (let route in ifc["route"]) {
			if (route.target == "0.0.0.0") {
			    net.ipv4_public = true;
			    push(net.ipv4_nexthop, route.nexthop);
			}
			if (route.target == "::") {
			    net.ipv6_public = true;
			    push(net.ipv6_nexthop, route.nexthop);
			}
		    }
		}

		if (exists(ifc["inactive"]) &&
		    exists(ifc.inactive.route)) {
		    for (let route in ifc.inactive.route) {
			if (route.target == "0.0.0.0") {
			    net.ipv4_inactive = true;
			    push(net.ipv4_nexthop, route.nexthop);
			}
			if (route.target == "::") {
			    net.ipv6_inactive = true;
			    push(net.ipv6_nexthop, route.nexthop);
			}
		    }
		}
		networks[ifc.interface] = net;
	    }
	}

	warn("networks: " + networks);
	warn("board: " + board);
	this.state.networks = networks;
	this.state.board = board;

    },

    // list of sets without counters
    get_sets: function() {
	let sets = {};

	for (let item in filter(nft_json_command(false, "list", "sets", "inet"),
				item => (exists(item, "set") && exists(item.set, "table") &&
					 item.set.table == this.state.config.ban_chain))) {
	    sets[item.set.name] = item.set;
	}
	return sets;
    },

    // get state for counters.  Sadly --json does not do this for whole set at once
    // so we have to read counter by counter.
    get_counters: function(sets) {

	if (sets == null) {
	    sets = this.get_sets();
	} else {
	    sets = { ...sets };
	}

	for (let name, set in sets) {
	    let item = nft_json_command(true, "list", "set", "inet",
					this.state.config.ban_chain,
					name);
	    set.elem   = [];
	    if (type(item[0].set?.elem) == "array") {
		for (let elem in item[0].set.elem) {
		    let e = {};
		    // symetrical schema would make this too easy ...
		    if ((type(elem) == "string") ||
			(type(elem?.prefix) == "object") ||
			(type(elem?.range) == "array")) {

			e = {val: elem, packets: 0};
		    } else {
			warn( elem + "\n");
			// either of above with counter
			e = {val: elem.elem.val, bytes: 0, packets: 0 };
			if (type(elem.elem.counter) == "object") {
			    e.bytes = elem.elem.counter.bytes;
			    e.packets = elem.elem.counter.packets;
			}
		    }
		    push(set.elem, e);
		}
	    }
			    
	}
	
	return sets || [];
    },
    
    ban_query: function( matcharg ) {
	let matchtbl = [];

	for (let tbl, e in this.state.runtime.ipsets) {
	    let nft  = fs.popen("nft get element inet " +
				this.state.config.ban_chain +
				" " + tbl + " { " + matcharg + " } 2>&1", "r");
	    nft.read("all");
	    // result of match would be nice but blasted thing does not work with json
	    if (0 == nft.close()) {
		push(matchtbl, { set: tbl });
	    }
	}
	
	return(matchtbl);
    },
    
    ban_report: function() {
	let _jfile = "" + this.state.runtime.json_report;
	let report = {
	    ipsets: {},
	    timestamp: this.state.runtime.ban_date,
	    cnt_set_sum: 0,
	    cnt_ip_sum: 0,
	    cnt_cidr_sum: 0,
	    cnt_range_sum: 0,
	    cnt_mac_sum: 0,
	    cnt_sum: 0,
	    cnt_acc_sum: 0,
	};
	
	for ( let name, elem in this.get_counters() ) {
	    if (exists(this.state.runtime.ipsets, name)) {
		let t = translate_counter(this.state, elem);
		report.cnt_set_sum++;
		report.cnt_ip_sum += t.count_ip;
		report.cnt_cidr_sum += t.count_cidr;
		report.cnt_range_sum += t.count_range;
		report.cnt_mac_sum += t.count_mac;
		report.cnt_sum += t.count;
		report.cnt_acc_sum += t.count_acc;
		report.ipsets[ name ] = t;
	    }
	}

	fs.writefile( _jfile, report );
	return(report);
	
    },
    
    get: function(sid, opt) {
	return this.cursor.get("banip", sid, opt);
    },

    get_all: function(sid) {
	return this.cursor.get_all("banip", sid);
    },

    // Print current memory in banip.sh format.
    get_mem: function() {
	let cmd = "awk '/^MemTotal|^MemFree|^MemAvailable/{ORS=\"/\"; print int($2/1000)}' /proc/meminfo 2>/dev/null | awk '{print substr($0,1,length($0)-1)}'";
	return join("", this.run_command(cmd));
    },

    get_subnets: function() {
	let res = [];
	let item = {};
	let nets = this.state.networks;
	let cfg = this.state.config;

	for ( let iface in cfg.ban_ifaces ) {
	    if ((exists(nets, iface)) &&
		(nets[iface].up)) {
		map(nets[iface].ipaddrs, e => {
		    if (((e.family == 4) && (cfg.ban_proto4_enabled)) ||
			((e.family == 6) && (cfg.ban_proto6_enabled))) {
			let net="" + e.addr + "/" + e.bits;
			push(res, net)
		    }
		});
	    }
	}
	return res;
    },
    
    parse_banip_config: function(data) {

	let defs = fw4.parse_options(data, ban_options);

	// make sure source lists are defined
	if (defs.ban_localsources == null)
	    defs.ban_localsources = [];
	if (defs.ban_extrasources == null)
	    defs.ban_extrasources = [];
	if (defs.ban_sources == null)
	    defs.ban_sources = [];

	this.state.config = defs;
    },

    setup_runtime: function() {
	let defs = {
	    ban_ver: BAN_VER,
	    ban_date: join("", this.run_command( "date", "+%d.%m.%Y\\ %H:%M:%S" )),
	    ban_match:  {	// match rule for "${src}${proto}"
		"src4": "ip saddr",
		"src6": "ip6 saddr",
		"dst4": "ip daddr",
		"dst6": "ip6 daddr",
		"srcmac": "ether saddr",
		"dstmac": "ether daddr"
	    },
	    ban_devs: [ ],
	    ban_action: {}
	};
	let config = this.state.config;
	
	if (config.ban_logsrc_enabled) {
	    defs.ban_action[ "src" ] = "jump " + config.ban_logchain_src;
	} else {
	    defs.ban_action[ "src" ] = lc(config.ban_target_src);
	}
	if (config.ban_logdst_enabled) {
	    defs.ban_action[ "dst" ] = "jump " + config.ban_logchain_dst;
	} else {
	    defs.ban_action[ "dst" ] = lc(config.ban_target_dst);
	}
	let sets = {};
	map([ ...config.ban_localsources, ...config.ban_sources ], s => {
	    for (let proto in [ "4", "6" ]) {
		if ( ( proto == 4 ) && !config.ban_proto4_enabled )
		    continue;
		if ( ( proto == 6 ) && !config.ban_proto6_enabled )
		    continue;

		let tbl = ( "maclist" == s ? "" + s : s + "_" + proto ),
		    act = {},
		    l = false,
		    f = "interval",
		    t = 0;
		
		switch (s) {
		case "maclist":
		    f = null;   // mac interval seems useless
		    l = true;   // local
		    t = config.ban_maclist_timeout;
		    act = { "src": "accept", "dst": "accept" };
		    break;
		case "whitelist":
		    l = true;   // local
		    t = config.ban_whitelist_timeout;
		    act = { "src": "accept", "dst": "accept" };
		    break;
		case "blacklist":
		    l = true;   // local
		    t = config.ban_blacklist_timeout;
		default:
		    act = { "src": defs.ban_action["src"], "dst": defs.ban_action["dst"] };
		}
			    
		sets[tbl] = {
		    proto: ( "maclist" == s ? "mac" :  proto),
		    list:  s,
		    local: l,
		    counter: (s in config.ban_localsources),
		    src: ( (s in config.ban_settype_src) ||
			   (s in config.ban_settype_all) ||
			   ((! (s in config.ban_settype_dst)) && (! ("dst" == config.ban_global_settype))) ),
		    dst: ( (s in config.ban_settype_dst) ||
			   (s in config.ban_settype_all) ||
			   ((! (s in config.ban_settype_src)) && (! ("src" == config.ban_global_settype))) ),
		    act: act,
		    flags: f,
		    timeout: t,
		};
		if (sets[tbl].src && sets[tbl].dst)
		    sets[tbl].mtype = "src+dst";
		else if (sets[tbl].src)
		    sets[tbl].mtype = "src";
		else
		    sets[tbl].mtype = "dst";

	    };
	});

	// These will be displayed in reports but never touched otherwise.
	map([ ...config.ban_extrasources ], s => {
	    for (let proto in [ "4", "6" ]) {
		let tbl = s + "_" + proto;
		sets[tbl] = {
		    proto: proto,
		    list:  s,
		    local: false,
		    src:   false,
		    dst:   false,
		    act:   [ "n/a", "n/a" ],
		    mtype:  "n/a",
		};
	    }
	});
	
	defs.ipsets = sets;
	defs.json_report = config.ban_reportdir + "/" + BAN_JSON_FILE;
	defs.ban_devs = get_ban_devs( this.state );
	this.state.runtime = defs;
    },
    
    load: function() {
	if ( ! this.state.loaded ) {
	    this.cursor = uci.cursor();

	    fw4.cursor = this.cursor;
	    fw4.get = this.get;
	    fw4.get_all = this.get_all;
	    fw4.parse_ban_settype = parse_ban_settype;
	}

	this.cursor.load("banip");
	this.read_ubus();
	this.parse_banip_config(this.cursor.get_all("banip", "global"));
	this.setup_runtime();

	this.state.loaded = true;

//	this.source = require("bansource");
//	this.source.load( this.state.config );

	// Make sure directories exist.
	fs.mkdir( this.state.config.tmpbase );
	fs.mkdir( this.state.config.ban_reportdir );
	fs.mkdir( this.state.config.ban_backupdir );
    },

}

