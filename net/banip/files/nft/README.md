This is not as complicated as it seems but there are a few files:

utpcmd.sh      A shell interpreter to allow .uc files to be executable.
	       Normally this could be "utpl" but we have legacy locking
	       and PID behavior easier to replicate with custom interpreter.

banip.uc       The ucode replacement for banip.sh.  Logic is re-written
	       in ucode aka javascript so that we can use the very cool
	       templating features to create tables.  Look here to add
	       or modify commands.

banrules.uc    The rule template.  This file renders the inet banIP
	       table based on configuration and sources. Look here to change
	       format / contents of banIP table.

bancfg.uc      ucode library object that handles banip configuration
	       and current system configuation parsing. New configuration
	       options should go here. ( banip object ).

bansource.uc   ucode library object that handles list download and
	       conversion into nft sets. Most likely reason to look here
	       is if downloaded file format is gorfed since minimal version
	       of awk we have can't handle complex manipulation.
	       ( source object )

