const fs = require("fs");

const ban_srcfile = "/tmp/ban_sources.json";
const ban_srcarc = "/etc/banip/banip.sources.gz";

// Don't let reads gobble all memory in case of corrupt file.
// Current size is ~10K so this should be plenty.
const MAX_SRC_SIZE = (32 * 1024);


// crud context wrong no this.
// Internal functions
function download_one( ctx, source, dest, url, overwrite ) {

    if (fs.access(dest, "r") ||
	fs.access(dest + ".gz", "r")) {
	if (overwrite) {
	    warn("File " + dest + " exists, deleting.\n");
	    fs.unlink(dest);
	    fs.unlink(dest + ".gz");
	} else {
	    warn("File " + dest + " exists, skipping.\n");
	    return 2;
	}
    }

    let cmd = "" + ctx.fetch + " " + ctx.parm + " " + dest + " " + url + " 2>&1";
    warn("Downloading: " + cmd + "\n");
    let dl = fs.popen(cmd, "r");
    let log = dl.read("all");
    let rc = dl.close();
    return rc;
}

function download_multi( ctx, source, dest, url, overwrite ) {
    let fmt = "",
	tmpfile = "/tmp/banip.tmp.download",
	list = [],
	cmd = "",
	rc = -1;

     if (fs.access(dest, "r") ||
	fs.access(dest + ".gz", "r")) {
	if (overwrite) {
	    warn("File " + dest + " exists, deleting.\n");
	    fs.unlink(dest);
	    fs.unlink(dest + ".gz");
	} else {
	    warn("File " + dest + " exists, skipping.\n");
	    return 2;
	}
    }
   
    switch ( source ) {
    case "country":
	fmt = "%s-aggregated.zone";
	list = ctx.config.ban_countries;
	break;
    case "asn":
	fmt = "AS%s";
	list = ctx.config.ban_asns;
	break;
    default:
	return -2;
    }

    for (let i in list) {
	let u = url + sprintf(fmt, i);
	rc = download_one( ctx, source, tmpfile, u, true );
	if ( 0 == rc ) {
	    let combine = "echo \"# " + u + "\" | ";
	    combine = combine + "cat - " + tmpfile + " >> " + dest;
	    cmd = fs.popen( combine );
	    cmd.read("all");
	    rc = cmd.close();
	    fs.unlink( tmpfile );
	}
    }
    return rc;
}

//
// Search calling context for banip configuration.
// we expect user of this function has:
//    this.state.config  ( from banip.uc )
//    banip              ( normal use )
//    bansource_config   ( something special )
//    config             ( templates )
//
// if none are found a new banip will be loaded.
//
let config = {};

const config_required = [
    "ban_srcarc",
    "ban_backupdir",
];

function check_config( obj ) {
    if (type(obj) != "object")
	return null;
    for (let key in config_required) {
	if (! exists(obj, key) ) {
	    warn("Configuration missing mandatory object: " + key + "\n");
	    return null;
	}
    }
    return obj;
}
     
//
// Try to find fetch command
//
const known_fetch = [
    { cmd: "aria2c", check: /./, insecure: "--check-certificate=false ",
      opts: "--timeout=20 --allow-overwrite=true --auto-file-renaming=false --log-level=warn --dir=/ -o"},
    { cmd: "curl", check: /./, insecure: "--insecure ",
      opts: "--connect-timeout 20 --silent --show-error --location -o"},
    { cmd: "wget", check: /^wget -/, insecure: "--no-check-certificate ",
      opts: "--no-cache --no-cookies --max-redirect=0 --timeout=20 -O"},
    { cmd: "uclient-fetch", check: /^libustream-/, insecure: "--no-check-certificate ",
      opts: "--timeout=20 -O"},
];

function commandpath( cmd ) {
    let check = fs.popen("command -v " + cmd + " 2>/dev/null"),
	full, res;
    
    full = rtrim(check.read("all"));
    res = check.close();
//    warn("Check: " + cmd + " full: " + full + " res: " + res + "\n");
    if (( 0 == res ) &&
	fs.access( full, "x" )) {
	return full;
    } else {
	return null;
    }
}

function opkglist() {
    let cmd = fs.popen("opkg list-installed 2>/dev/null", "r");
    let res = cmd.read("all");

    if ((0 != cmd.close()) ||
	(res == null)) {
	warn("local opkg package repository is not available, please set 'ban_fetchutil' manually\n");
	res = null;
    }

    res = split(res, "\n");

    return (res);
}

function findfetch( ctx ) {
    let packages = opkglist();
    function tmatch( cmd ) {
	for (let p in packages) {
	    if (null != match(p, cmd.check)) {
		return true;
	    }
	}
	return false;
    }
    if ((type(ctx.config.ban_fetchutil) == "string") &&
	ctx.config.ban_fetchutil != "-") {
	ctx.fetch = ctx.config.ban_fetchutil;
    } else {
	for (let cmd in known_fetch) {
	    let full = commandpath( cmd.cmd );
	    if (( null != full ) &&
		( tmatch( cmd ) ))
	    {
		ctx.fetch = cmd.cmd;
		break;
	    }
	}
    }

    if ((type(ctx.config.ban_fetchparm) == "string") &&
	ctx.config.ban_fetchparm != "-") {
	ctx.parm = ctx.config.ban_fetchparm;
    } else {
	for (let cmd in known_fetch) {
	    if (cmd.cmd == ctx.fetch) {
		ctx.parm = "" + (ctx.config.ban_fetchinsecure ? cmd.insecure : "") + cmd.opts;
	    }
	}
    }
}

const local_sources = {
    whitelist: { "file_4": "/etc/banip/banip.whitelist",
		 "file_6": "/etc/banip/banip.whitelist",
		 "rule_4": "/^(([0-9]{1,3}\\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{print \"add whitelist_4 \"$1}",
		 "rule_6": "/^(([0-9A-f]{0,4}:){1,7}[0-9A-f]{0,4}:?(\\/(1?[0-2][0-8]|[0-9][0-9]))?)([[:space:]]|$)/{print \"add whitelist_6 \"$1}",
		 "focus": "Local whitelist", },
    blacklist: { "file_4": "/etc/banip/banip.blacklist",
		 "file_6": "/etc/banip/banip.blacklist",
		 "rule_4": "/^(([0-9]{1,3}\\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{print \"add blacklist_4 \"$1}",
		 "rule_6": "/^(([0-9A-f]{0,4}:){1,7}[0-9A-f]{0,4}:?(\\/(1?[0-2][0-8]|[0-9][0-9]))?)([[:space:]]|$)/{print \"add blacklist_6 \"$1}",
		 "focus": "Local blacklist", },
    maclist:   { "file_mac": "/etc/banip/banip.maclist",
		 "rule_mac": "/^([0-9A-z][0-9A-z]:){5}[0-9A-z]{2}([[:space:]]|$)/{print \"add ${src_name} \"toupper(\$1)}",
		 "focus": "Local MAC list", },
};

function add_localsources( srctable )
{
    for (let key, obj in local_sources) {
	if ( ! exists( srctable, key ))
	    srctable[ key ] = obj;
    }
}

return {
    sourcelist: {
	// key: {  // url's for remote files
	//        url_4:  download url for ipv4,
	//        url_6:  download url for ipv6,
	//         // local files w/o url
	//        file_4: local file for ipv4,
	//        file_6: local file for ipv6,
	//         // awk rule to process all files
	//        rule_4: awk rule for ipv4.
	//        rule_6: awk rule for ipv4
	//        focus:  description of source
	//        descurl: URL for info about list
    },
    config: null,
    fetch:  null,
    parm:   null,

    dummy: function() {
	warn("hi\n");
    },

    load_json_obj: function( srcfile ) {
	let res = null;
	if (fs.access( srcfile, "r" )) {
	    try {
		res = json( fs.readfile( srcfile, MAX_SRC_SIZE ) );
	    }
	    catch (e) {
		warn(`Unable to load banIP source list: ${e}\n`);
	    }
	}
	return res;
    },


    // require does not allow parameters so we need to explicitly set
    // up context to avoid loop banip -> bansource -> banip.
    load:  function( config ) {
	if (config == null) {
	    warn("Config not specified, loading from banip\n");
	    let banip = require("banip");
	    banip.load();
	    this.config = check_config( banip.state.config );
	} else {
	    this.config = check_config( config );
	}
	
	if (this.config == null) {
	    warn("Invalid banip configuration, aborting.\n");
	    return -1;
	}

	// set fetch, parm
	findfetch( this );

	// get sourcelists
	this.sourcelist = this.load_json_obj( ban_srcfile );
	if (null == this.sourcelist) {
	    let arc = config?.ban_srcarc ? config.ban_srcarc : ban_srcarc;
	    let cmd = fs.popen("zcat " + arc + " >" + ban_srcfile + " 2>/dev/null");
	    cmd.read("all");
	    if (0 == cmd.close()) {
		this.sourcelist = this.load_json_obj( ban_srcfile );
	    } else {
		warn("Could not de-compress source archive");
		return -1;
	    }
	}
	add_localsources( this.sourcelist );
    },

    // Download one ban source list
    download: function( source, overwrite ) {
	if ( null == this.config ) {
	    warn("ERROR:  bansource object not loaded\n");
	    return -1;
	}
	if ( source in this.config.ban_localsources ) {
	    // Nothing to download for local sources.
	    // they by definition should be in directory.
	    return 0;
	}
	if ( ! exists( this.sourcelist, source ) ) {
	    warn("Unknown source: " + source + " , skipping\n");
	    return -3;
	}
	
	let src = this.sourcelist[ source ],
	    rc = -1;
	for (proto in [ 4, 6 ]) {
	    let u = "url_" + proto;
	    if ( exists(src, u) ) {
		let dest = "" + this.config.ban_backupdir + "/banIP." + source + "_" + proto;
		if (src?.comp)
		    dest = dest + "." + src.comp;

		if ( source in ["country", "asn" ] )
		    rc = download_multi( this, source, dest, src[ u ], overwrite);
		else
		    rc = download_one( this, source, dest, src[ u ], overwrite);

		if ((0 == rc) &&
		    (type(src?.comp) != "string")) {
		    let cmd = fs.popen("gzip " + dest, "r");
		    cmd.read("all");
		    cmd.close();
		}
	    }
	}
    },

    for_elements:  function( source, proto, fcn ) {
	let rarray = [];

	function deffilter( line ) {
	    return(rtrim(split(line, " ")[2]));
	};
	
	let r = "rule_" + proto;
	let src = this.sourcelist[ source ];
	let args = "", dest = "";

	if ( ( src == null ) ||
	     (! exists(src, r)) ) {
		 warn("Source: " + source + " , proto: " + proto + " not found\n");
		 return;
	}

	if ((!exists(src, `url_${proto}`)) &&
	    (exists(src,  `file_${proto}`))) {
	    dest = src[ `file_${proto}` ];
	    args = "awk -e '" + src[ r ] + "' " + dest + "\n";
	} else {
	    dest = "" + this.config.ban_backupdir + "/banIP." + source + "_" + proto + ".gz";
	    args = "zcat " + dest + " | awk -e '" + src[ r ] + "'";
	}
	warn(args + "\n");
	let cmd = fs.popen( args, "r" );
	let line = "", f;
	while ((line = cmd.read("line")) && !(line === "")) {
	    if ( fcn == null )
		f = deffilter( rtrim(line) );
	    else
		f = fcn( rtrim(line) );

	    if (null != f)
		push(rarray, f);
	}
	cmd.close();

	if (rarray[0] != null)
	    return rarray;
	else
	    return null;
    },

    // Fetch ipset info from source.
    //
    // For most uses runtime counts from bancfg are more
    // useful but this allows luci interface to have summary
    // data even if banip is stopped/disabled.
    source_counts: function( proto_list ) {
	let res = {
	    local_ipsets: 0,
	    local_cnt:    0,
	    ext_ipsets:   0,
	    ext_cnt:      0,
	};
	let plist = [];
	let local = false;

	function count_elem( line ) {
	    if (local)
		res.local_cnt++;
	    else
		res.ext_cnt++;
	}

	if (null == proto_list) {
	    if (this.config.ban_proto4_enabled)
		push(plist, "4");

	    if (this.config.ban_proto6_enabled)
		push(plist, "6");

	    push(plist, "mac");
	} else {
	    plist = proto_list;
	}

	for ( let s,o in this.sourcelist ) {
	    if (! (s in [ ...this.config.ban_sources, ...this.config.ban_localsources ]))
		continue;
	    for ( let proto in plist ) {
		if (exists(o, "rule_" + proto)) {
		    if (exists(o, "file_" + proto)) {
			local = true;
			res.local_ipsets++;
		    } else {
			local = false;
			res.ext_ipsets++;
		    }
		    this.for_elements( s, proto, count_elem );
		}
	    }
	}

	return res;
    },
    
    // Print set to stdout e.g. for nft -f-
    //   source: name of source e.g. "whitelist"
    //   proto:  4,6,"mac".
    //   bare:   true:   print only element = { ...contents }
    //           false:  print with table/set too.
    //
    //  example:  s.print_set("tor", "4") | nft -f-
    //            set tor_4 {
    //              ... other settings
    //              {{ s.print_set("tor", "4", true); }}
    //            }
    //
    print_set: function(source, proto, bare) {
	let element_count = 0;
	let table = this.config.ban_chain;
	let chain = null;
	let match = null;
	let print_hdr = print;
	let print_bare = function( ...args ){ return 0; };

	// bare = null/false:  output entire table suitable for nft -f-
	// bare = true:        output element = { ..elements } suitable for template.
	if (bare) {
	    print_hdr = function( ...args ){ return 0; };
	    print_bare = print;
	}
	
	switch ( proto ) {
	case "4":
	case 4:
	    chain = source + "_4";
	    match = "ip saddr";
	    break;
	case "6":
	case 6:
	    chain = source + "_6";
	    match = "ip6 saddr";
	    break;
	case "mac":
	    chain = source;
	    match = "ether saddr";
	    break;
	default:
	    warn("Unknown protocol: " + proto + ", aborting\n");
	    return -1;
	}
	
	// To avoid OOM during nft we need a new table every few elements.
	function set_header() {
	    if ((element_count) == 0) {
		print_hdr("table inet " + table + " {\n");
		print_bare("\t    elements = {");
	    }
	    print_hdr("    set " + chain + " {\n");
	    print_hdr("        typeof " +  match + "\n");
	    print_hdr("        flags interval\n");
	    print_hdr("        auto-merge\n");
	    print_hdr("        elements = {");
	}
 
	function print_elem( line ) {
	    let t = split(line, " ");
	    // element_count % elements_per_header
	    if ((element_count) == 0) {
		if (element_count) {
		    print_hdr("}\n    }\n");
		}
		set_header();
	    }
	    element_count++;	 
	    if (t[2]) {
		printf(" %s,", t[2]);
	    }
	    return null;
	}

	// Flush even if table empty
	print_hdr("flush set inet " + table + " " + chain + "\n");

	this.for_elements( source, proto, print_elem );

	if (element_count) {
	    // close last element and set
	    print_hdr("}\n    }\n");
	    // close table.
 	    print_hdr("}\n");
	    // close element
	    print_bare(" }\n");
	}

    },
    
    // Load set
    load_set: function(source, proto) {
	let element_count = 0;
	let chain = null;
	let match = null;
	let element_cmd = "";
	const NFT_CMD = "nft add element inet " + this.config.ban_chain + " %s '{ ";
	
	switch ( proto ) {
	case "4":
	case 4:
	    chain = source + "_4";
	    match = "ip saddr";
	    break;
	case "6":
	case 6:
	    chain = source + "_6";
	    match = "ip6 saddr";
	    break;
	case "mac":
	    chain = source;
	    match = "ether saddr";
	    break;
	default:
	    warn("Unknown protocol: " + proto + ", aborting\n");
	    return -1;
	}
	
	// To avoid OOM during nft we need a new table every few elements.
	function set_header() {
	    element_cmd = sprintf(NFT_CMD, chain);
	}
 
	function print_elem( line ) {
	    let t = split(line, " ");
	    if (t[2]) {
		if ((element_count % 40) == 0) {
		    if (element_count) {
			element_cmd = element_cmd + " }'\n";
			print( element_cmd );
		    }
		    set_header();
		}
		element_count++;	 
		element_cmd = element_cmd + sprintf(" %s,", t[2]);
	    }
	    return null;
	}

	print("nft flush set inet " + this.config.ban_chain + " " + chain + "\n");

	this.for_elements( source, proto, print_elem );

	// close last element and set
	element_cmd = element_cmd + " }'\n";
	print( element_cmd );
    },
    
}
