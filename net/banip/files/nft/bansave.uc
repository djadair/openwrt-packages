{%
// Template to save banip block chain table.
//
// This is a bit silly but can use object config and can potentially
// handle filtering or map deletion e.g. if we decide to use vmaps
// then extra code will be required before dump.
//
// Also notice that we save without counter stats since those will
// break import.
//
 if ( type(config) != "object" ) {
     banip = require("bancfg");
     banip.load();
     config = banip.state.config;
     runtime = banip.state.runtime;
     warn("config: " + config + "\n\n");
     warn("runtime: " + runtime + "\n\n");
 }
 let fs = require("fs");

 warn("Saving banIP config\n");
-%}


{%
   let nft  = fs.popen("nft -sT list table inet " + config.ban_chain, "r");
   let table = nft.read("all");
   print( table );
   nft.close();
%}

