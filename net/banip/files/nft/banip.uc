#!/usr/share/banip/utpcmd.sh
{%
 // above uses lock, alternative: #!/usr/bin/utpl -S
 // Run banip command.  Options from banip.sh:
 //    refresh:  Update report, status, and local tables
 //    stop:     Destroy tables.
 //    restart:  Re-download and set up tables.
 //    suspend:  Pause ban processing.
 //    resume:   Re-enable ban processing.
 //    query:    Test if argv[2] in current lists
 //    report:   Refresh and print report to stdout
 //    start:    Start from backup
 //    reload:   Re-download files and refresh

 
 let banip = require("bancfg");
 let bansrc = require("bansource");
 let fs = require("fs");
 banip.load();

 let config = banip.state.config;
 let runtime = banip.state.runtime;
 const NFT_BACKUP = config.ban_backupdir + "/banIP.save.nft";
 const PIDFILE = "/var/run/banip.pid";
 
 let cmd = "";
 let res = -1;


 cmd = ARGV[0];
 if (null == cmd)
     cmd = getenv("BAN_ACTION");

 if (null == cmd)
     cmd = "status";

 //
 // warning:  This uses fs, bansrc, config, runtime
 //
const jsonStatus = (() => {
    let _ban_status = null;
    let _loaded = false;
    const JSON_STATE = config.ban_tmpbase + "/ban_runtime.json";
    
    function counterSummary() {
	let res = "";
	if (bansrc?.config != null) {
	    let cnt = bansrc.source_counts();
	    res = "" + cnt.ext_ipsets + " IPSets with " + (cnt.ext_cnt + cnt.local_cnt) + " IPs/Prefixes";
	} else {
	    res = "xx IPSets with yyyy IPs\/Prefixes";
	}

	return res;
    }

    // Save status to json file.
    //    hmm, should have flock but how ? ....
    function save() {
	let fd = fs.open(JSON_STATE, "w");

	if (fd) {
	    fd.write( _ban_status );
	    fd.close();
	} else {
	    warn("Could not write: " + JSON_STATE + "\n");
	}
    }

    // Load json file or refresh from current state.
    function load() {
	let fd = fs.open(JSON_STATE, "r");
	let tstate = null;
	if (fd) {
	    try {
		tstate = json(fd.read("all"));
	    }
	    catch (e) {
		warn(`Unable to parse '${JSON_STATE}': ${e}\n`);
		tstate = null;
	    }
	    fd.close();
	}

	// If load fails, fall back to refresh
	if ((null == tstate) ||
	    (runtime.ban_ver != tstate.version)) {
	    warn("banIP: state file not found, re-creating\n");
	    tstate = null;
	}

	return tstate;
    }

    function info() {
	let _info = [];
	let _flags = [];

	// "settype: src+dst, backup_dir: \/tmp\/banIP-Backup, report_dir: \/tmp\/banIP-Report", "run_flags": "protocols (4\/6): ✔\/✘, log (src\/dst): ✘\/✔, monitor: ✘, mail: ✘, whitelist only: ✘"

	function _pflag( bvar ) {
	    return( bvar ? "✔" : "✘")
	}

	push( _flags, "protocols (4/6): " +
	      _pflag(config.ban_proto4_enabled) + "/" +
	      _pflag(config.ban_proto6_enabled) );
	push( _flags, "log (src/dst): " +
	      _pflag(config.ban_logsrc_enabled) + "/" +
	      _pflag(config.ban_logdst_enabled) );
	push( _flags, "monitor: " +
	      _pflag(config.ban_monitor_enabled) );
	push( _flags, "mail: " +
	      _pflag(config.ban_mail_enabled) );
	push( _flags, "whitelist only: " +
	      _pflag(config.ban_whitelistonly) );
	
	push( _info, "settype: " + config.ban_global_settype );
	push( _info, "backup_dir: " + config.ban_backupdir );
	push( _info, "report_dir: " + config.ban_reportdir );
	push( _info, "run_flags: " + join(", ", _flags) );
	      
	return join(", ", _info);
    }
    
    return {
	status: function() {
	    // Try to load config if we are not initialized
	    if (null == _ban_status)
		_ban_status = load();
	    
	    // If load fails fall back to full refresh
	    if (null == _ban_status)
		this.refresh( "running" );
	    
	    return _ban_status
	},

	// Same as above but return previous status rather than new status.
	file_status: function() {
	    let _tstatus = {};
	    let _rval = "disabled";
	    
	    if (null != _ban_status) {
		rval = _ban_status.status;
	    } else {
		_tstatus = load();
		if (null != _tstatus) {
		    _rval = _tstatus.status;
		    _ban_status = _tstatus;
		} else {
		    this.refresh( "running" );
		}
	    }

	    return _rval;
	},
	
	// Reload entire config from current state
	refresh: function( state ) {
	    _ban_status = {
		status:          (null != state) ? state : "running",
		// "enabled", "disabled", "running", "suspended", "paused", "error"
		version:         runtime.ban_ver,
		ipset_info:      counterSummary(),    // "xx IPSets with yyyy IPs\/Prefixes"
		active_sources:  map(config.ban_sources, e => { return { source: "" + e }; }),
		active_devs:     map(runtime.ban_devs, e => { return { dev: "" + e }; }),
		active_ifaces:   map(config.ban_ifaces, e => { return { iface: "" + e }; }),
		active_logterms: map(config.ban_logterms, e => { return { term: "" + e }; }),
		active_subnets:  map(banip.get_subnets(), e => { return { subnet: e }; }),
		run_infos:       info(),
		last_run:        "" + cmd + ", " + "n\/a" + " " + banip.get_mem() + " " + runtime.ban_date,
		system:          banip.state.board.model + ", " + banip.state.board.release.description,
	    };
	    save();
	},

	// Fast update for state changes w/o scanning source files.
	update: function( state, command ) {
	    let _state = ((null == state) ? "running" : state);
	    let _command = ((null == command) ? cmd : command);
	    
	    if (null == _ban_status) {
		this.refresh( _state );
	    } else {
		_ban_status.status = _state;
		// n/a is run time, tbd.
		_ban_status.last_run = "" +
		    _command + ", " + "n\/a" + " " + banip.get_mem() + " " + runtime.ban_date;
		save();
	    }

	},


    };
})();

 function checkSource() {
     if (null == bansrc.config)
	 bansrc.load( config );
 }
 
 // Returns true if table is loaded
 function checkTable() {
     let _args = [ "-st", "list", "table", "inet", config.ban_chain, "2>&1 >/dev/null" ];
     let _res = banip.nft_command( _args );

     // we through away output so result shoudl be "" or null
     return( (null == _res) ? false : true );
 }

 function deleteBackups() {
     warn("deleting backups\n");
     system("rm -f " + config.ban_backupdir + "/banIP*");
 }
 
 // Returns true if table is loaded
 function deleteTable() {
     let _args = [ "flush", "table", "inet", config.ban_chain, "2>&1 >/dev/null" ],
	 _res = null;

     // If counters were enabled this probably requires flush of each set too.
     if (checkTable()) {
	 _res = banip.nft_command( _args );
	 _args[0] = "delete";
	 _res = banip.nft_command( _args );
     }

     fs.unlink( NFT_BACKUP );
     
     // we through away output so result shoudl be "" or null
     return( (null == _res) ? false : true );
 }

 function saveTables() {
     fs.unlink( NFT_BACKUP );
     fs.writefile( NFT_BACKUP,
		   render("bansave.uc", { source: bansrc, config: config, runtime: runtime }) );
 }

 function checkDownload( overwrite ) {

     checkSource();
     for (let sname in config.ban_sources) {
	 bansrc.download( sname, overwrite );
     }
 
 }
 
 // This kind of sucks but I can't figure out how
 // to pipe the include/render output.
 function loadTables( force ) {
     let _args = [ "-f", NFT_BACKUP ];
     let _res = null;

     if ( force || (! fs.access( NFT_BACKUP, "r" )) ) {
	 warn("Backup file missing, creating\n");
	 checkSource();
	 checkDownload( false );
	 fs.unlink( NFT_BACKUP );
	 fs.writefile( NFT_BACKUP,
		       render("banrules.uc", { source: bansrc, config: config, runtime: runtime }) );
     }

     warn("Loading " + NFT_BACKUP + "\n");
     banip.nft_command( _args );

     return checkTable();
 }

 // runtime status json
 let ban_status = jsonStatus.file_status();
 

  let _force_load = true;
 
 switch (cmd) {

 //    refresh:  Update report, status, and local tables
 //    stop:     Destroy tables.
 //    restart:  Re-download and set up tables.
 //    suspend:  Pause ban processing.
 //    resume:   Re-enable ban processing.
 //    query:    Test if argv[2] in current lists
 //    report:   Refresh and print report to stdout
 //    start:    Start from backup
 //    reload:   Update report, status, and all tables.

     // Note: due to table rendering reload and refresh
     //       are the same operation -- all sets and rules
     //       are always updated.  However if a set is removed then only
     //       the rules are removed.  To remove the contents
     //       of a set a full restart is required.

 case "start":
     _force_load = false;
 case "reload":
 case "refresh":
 case "restart":
     jsonStatus.update( "running" );
     if ( ! config.ban_enabled ) {
	 printf("banIP is currently disabled, please set the config option 'ban_enabled' to '1' to use this service");
	 deleteTable();
	 jsonStatus.refresh( "disabled" );
     } else {
	 if ( "restart" == cmd ) {
	     deleteBackups();
	 }
	 checkSource();
	 // Force re-load to pick up local file changes.
	 loadTables( _force_load );
	 // Generate new report.
	 banip.ban_report();
	 // Update status
	 jsonStatus.refresh( "enabled" );
     }
     break;

 case "stop":
     jsonStatus.update( "running" );
     deleteTable();
     jsonStatus.update( "disabled" );
     break;

 case "suspend":
     jsonStatus.update( "running" );
     if (checkTable()) {
	 let _scmd = [ "add table inet", config.ban_chain, "'{ flags dormant; }'" ];
	 checkSource();
	 res = banip.nft_command( _scmd );
	 if (res) {
	     warn("Suspend command failed\n");
	 } else {
	     saveTables();
	 }
	 jsonStatus.refresh( "paused" );
     } else {
	 warn("banIP tables not loaded\n");
	 if ( config.ban_enabled ) 
	     jsonStatus.refresh( "error" );
	 else
	     jsonStatus.refresh( "disabled" );
     }
     break;

 case "resume":
     if (checkTable()) {
	 jsonStatus.update( "running" );
	 let _rcmd = [ "add table inet", config.ban_chain  ];
	 checkSource();
	 res = banip.nft_command( _rcmd );
	 if (res) {
	     warn("Resume command failed\n");
	     jsonStatus.refresh( "error" );
	 } else {
	     saveTables();
	     jsonStatus.refresh( "enabled" );
	 }
     } else {
	 if ( config.ban_enabled ) {
	     warn("banIP: tables not loaded, try \"start\" or \"reload\".\n");
	     jsonStatus.refresh( "error" );
	 } else {
	     jsonStatus.refresh( "disabled" );
	 }
     }
     break;
     
 case "sets":
     res=banip.get_sets();
     printf("%J\n", res);
     break;

 case "counters":
    res = banip.get_counters();
    printf("%.J\n", res);
    break;

 case "report":
     if (("json" == ARGV[1]) && ( fs.access( runtime.json_report, "r" ) )) {
	 system("cat " + runtime.json_report);
     } else {
	 res = banip.ban_report();
	 if ("gen" != ARGV[1]) 
	     printf("%.J\n", res);
     }
    break;

 case "query":
     if (null == ARGV[1]) {
	 warn("Query string required\n");
	 break;
     }
     printf("%s\n%s\n%s\n", ":::", "::: search \'" + ARGV[1] +"\' in banIP related IPSets", ":::");
     res = banip.ban_query( ARGV[1] );
     if ((res == null) || (res[0] == null)) {
	 printf("  - no match\n\n");
     } else {
	 map(res, e => {
	     printf("  - found in IPSet \'" + e.set + "\'\n");
	 });
     }
     break;

case "print":
     if ( "full" == ARGV[1] ) {
	 bansrc.load( config );
	 include("banrules.uc", { source: bansrc, config: config, runtime: runtime });
     } else {
	 include("banrules.uc", { source: null, config: config, runtime: runtime });
     }
	
    break;

case "state":
    printf("%.J", banip.state);
    break;

case "download":
     let overwrite = ((type(ARGV[1]) == "string") ? ARGV[1] : 0);
     bansrc.load( config );
 
     for (let sname in config.ban_sources) {
	 bansrc.download( sname, overwrite );
     }
     break;

case "print_set":
     let psource = ((type(ARGV[1]) == "string") ? ARGV[1] : null);
     let pproto = ((ARGV[2] in [ "4", "6", "mac" ]) ? ARGV[2] : "4");
     let pbare = ((type(ARGV[3]) == "string") ? true : false);
     bansrc.load( config );
     bansrc.print_set( psource, pproto, pbare );
     break;

case "load_set":
     let lsource = ((type(ARGV[1]) == "string") ? ARGV[1] : null);
     let lproto = ((ARGV[2] in [ "4", "6", "mac" ]) ? ARGV[2] : "4");
     bansrc.load( config );
     bansrc.load_set( lsource, lproto );
     break;

 case "status":
     printf("%.J\n", ban_status);
     break;
     
default:
    warn("command not found\n");

}

 // We didn't bother setting pid file since we are running under lock
 // but init might have so clear it.
// fs.writefile( PIDFILE, "" );
%}
