#!/usr/bin/perl -w
################################################################################
### watch for blocks like this one to tell #####################################
### you where to add address data manually! ####################################
################################################################################

use 5.010;
use strict;
use warnings;
$|=1;

use Carp;
use Win32::Process::List;
use Win32::Process;
use Win32::Process::Memory;
use Compress::Zlib;
use LWP::Simple;

my ( $dwarf_pid, $pe_timestamp, $ver, $input, $show_hidden, $quiet, $no_ask,
    $help, $proc, @offsets, $update_only );

my @full_map_data;                              # array to hold the full extracted map data
my $bin_version = 1;                            # version of the binary memory map format, last changed 080103
my $version = 1.000;                            # version of the map_extract tool
my $map_name = "Fortressname";                  # default fortress name

populate_memory_data_store();

$ver = init_process_connection();

refresh_datastore() unless $ver;

say "Press enter to analyze tile under the cursor, then enter a small description.";
say "Afterwards press enter to analyze the next tile or enter q to quit.\n";

while ( $input = <STDIN> ) {
    chomp($input);
    last if $input eq 'q';
    last if $input eq 'n';
    loadmap();
    print "Next? (y/q) [y]: "
}

say "";
say "Press enter to close...";
$input = <STDIN>;

################################################################################
### script ends here ###########################################################
################################################################################




################################################################################
### functions below, edit the end of populate_memory_data_store ################
### to add memory address data #################################################
################################################################################


sub populate_memory_data_store {
    @offsets = (
    ); # OFFSETS END HERE - DO NOT REMOVE THIS COMMENT
    
################################################################################
### add memory address data above the line marking the end of the ##############
### offsets in the same manner as the other blocks are formatted ###############
################################################################################
    
}


################################################################################


sub init_process_connection {
    ### get dwarf process id #######################################################
    my %list = Win32::Process::List->new()->GetProcesses();
    for my $key ( keys %list ) {
        $dwarf_pid = $key   if ( $list{$key} =~ /dwarfort.exe/ );
    }
    croak "Couldn't find process ID, make sure DF is running and a savegame is loaded." unless ( $dwarf_pid );
    
    ### lower priority of dwarf fortress ###########################################
    Win32::Process::Open( my $dwarf_process, $dwarf_pid, 1 );
    $dwarf_process->SetPriorityClass( IDLE_PRIORITY_CLASS );
    croak "Couldn't lower process priority, this is really odd and shouldn't happen, try running as administrator or poke Mithaldu/Xenofur." unless ( $dwarf_process );
    
    ### actually read stuff from memory ############################################
    $proc = Win32::Process::Memory->new({ pid  => $dwarf_pid, access => 'read/query' });   # open process with read access
    croak "Couldn't open memory access to Dwarf Fortress, this is really odd and shouldn't happen, try running as administrator or poke Mithaldu/Xenofur." unless ( $proc );
    
    
    ### Let's Pla... erm, figure out what version this is ##########################
    
    for my $i ( 0..$#offsets ) {
        $pe_timestamp = $proc->get_u32( $offsets[$i]{pe_timestamp_offset} );
        if ( $offsets[$i]{PE} == $pe_timestamp ) {
            return $i;
        }
    }
}


################################################################################


sub refresh_datastore {
    say "Could not find DF version in local data store. Checking for new memory address data...";
    import_remote_xml();
    say "";

    $ver = init_process_connection();

    if (!$ver) {
        croak "Version could not be correctly identified. Please contact Xenofur/Mithaldu or Jifodu for updated memory addresses.\n";
    }
}

sub import_remote_xml {
    my $source = "http://www.geocities.com/jifodus/tables/dwarvis/";
    my @xml_list;

    my $list = get($source);
    die "Couldn't get it!" unless defined $list;
    
    while ( $list =~ m/<A HREF="(.+?\.xml)">/gi ) {
        push @xml_list, $1;
    }
    
    say "Found ".($#xml_list+1)." memory data files...";
    
    for my $file (@xml_list) {
        my $known = 0;
        for my $i ( 0..$#offsets ) {
            $known = 1 if $file =~ m/$offsets[$i]{version}/;
        }
        
        if ($known) {
            say "One file ($file) discarded, memory data inside already known.";
            next;
        }
        
        my $xml = get($source.$file);
        die "Couldn't get it!" unless defined $xml;
    
        my $msg_file = $file;
        $msg_file =~ s/core\.xml/messages.txt/;
        my $message = get($source.$msg_file);
        
        process_xml($xml,$message);
    }
}

sub process_xml {
    my ($xml, $message) = @_;
    my (@data_store,@new_data_store);
    
    my %config_hash;
    
    if( $xml =~ m/<version name="(.+?)" \/>/i ) {
        $config_hash{version} = $1;
    } else { return 0; }
    
    if( $xml =~ m/<pe timestamp_offset="0x(.+?)" timestamp="0x(.+?)" \/>/i ) {
        $config_hash{pe_timestamp_offset} = hex($1);
        $config_hash{PE} = hex($2);
    } else { return 0; }
    
    if( $xml =~ m/<address name="map_data" value="0x(.+?)" \/>/i ) {
        $config_hash{map_loc} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<address name="map_x_count" value="0x(.+?)" \/>/i ) {
        $config_hash{x_count} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<address name="map_y_count" value="0x(.+?)" \/>/i ) {
        $config_hash{y_count} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<address name="map_z_count" value="0x(.+?)" \/>/i ) {
        $config_hash{z_count} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<offset name="map_data_type_offset" value="0x(.+?)" \/>/i ) {
        $config_hash{type_off} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<offset name="map_data_designation_offset" value="0x(.+?)" \/>/i ) {
        $config_hash{designation_off} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<offset name="map_data_occupancy_offset" value="0x(.+?)" \/>/i ) {
        $config_hash{occupancy_off} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<address name="mouse_x" value="0x(.+?)" \/>/i ) {
        $config_hash{mouse_x} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<address name="mouse_y" value="0x(.+?)" \/>/i ) {
        $config_hash{mouse_y} = hex($1);
    } else { return 0; }
    
    if( $xml =~ m/<address name="mouse_z" value="0x(.+?)" \/>/i ) {
        $config_hash{mouse_z} = hex($1);
    } else { return 0; }
        
    for my $i ( 0..$#offsets ) {
        return 0 if $offsets[$i]{version} eq $config_hash{version};
    }
    
    say "Recognized new memory data for DF $config_hash{version}, inserting into data store.";
    say "--- -- -\n$message\n--- -- -" if defined $message;
    push @offsets, \%config_hash;

    open my $HANDLE, "<", "map_extract.pl";
    @data_store = <$HANDLE>;
    close $HANDLE;
    
    for my $line (@data_store) {
        if ( $line =~ m/OFFSETS\ END\ HERE/ ) {
            push @new_data_store, "        {\n";
            push @new_data_store, "            version => \"$config_hash{version}\",\n";
            push @new_data_store, "            PE => ".sprintf("0x%08x", $config_hash{PE}).",\n";
            push @new_data_store, "            map_loc => ".sprintf("0x%08x", $config_hash{map_loc}).",\n";
            push @new_data_store, "            x_count => ".sprintf("0x%08x", $config_hash{x_count}).",\n";
            push @new_data_store, "            y_count => ".sprintf("0x%08x", $config_hash{y_count}).",\n";
            push @new_data_store, "            z_count => ".sprintf("0x%08x", $config_hash{z_count}).",\n";
            push @new_data_store, "            pe_timestamp_offset => ".sprintf("0x%08x", $config_hash{pe_timestamp_offset}).",\n";
            push @new_data_store, "            type_off        => ".sprintf("0x%08x", $config_hash{type_off}).",\n";
            push @new_data_store, "            designation_off => ".sprintf("0x%08x", $config_hash{designation_off}).",\n";
            push @new_data_store, "            occupancy_off   => ".sprintf("0x%08x", $config_hash{occupancy_off}).",\n";
            push @new_data_store, "            mouse_x   => ".sprintf("0x%08x", $config_hash{mouse_x}).",\n";
            push @new_data_store, "            mouse_y   => ".sprintf("0x%08x", $config_hash{mouse_y}).",\n";
            push @new_data_store, "            mouse_z   => ".sprintf("0x%08x", $config_hash{mouse_z}).",\n";
            push @new_data_store, "        },\n";
        }
        push @new_data_store, $line;
    }

    open $HANDLE, ">", "map_extract.pl";
    for my $line ( @new_data_store ) {
        print $HANDLE $line;
    }
    close $HANDLE;
}


################################################################################


sub loadmap {
    my $map_base;                                   # offset of the address where the map blocks start
    my ($xcount, $ycount, $zcount);                 # dimensions of the map data we're dealing with
    my ($xmouse, $ymouse, $zmouse);                 # cursor coordinates
    my ($xcell, $ycell, $zcell);                    # cursor cell coordinates
    my ($xtile, $ytile, $ztile);                    # cursor tile coordinates inside the cell adressed above
    my (@xoffsets,@yoffsets,@zoffsets);             # arrays to store the offsets of the place where other addresses are stored
    @full_map_data=[];                              # array to hold the full extracted map data
    
    $map_base = $proc->get_u32( $offsets[$ver]{map_loc} );        # checking whether the game has a map already
    croak "Map data is not yet available, make sure you have a game loaded." unless ( $map_base );

    $xcount = $proc->get_u32( $offsets[$ver]{x_count} );         # find out how much data we're dealing with
    $ycount = $proc->get_u32( $offsets[$ver]{y_count} );
    $zcount = $proc->get_u32( $offsets[$ver]{z_count} );    
    
    $xmouse = $proc->get_u32( $offsets[$ver]{mouse_x} );         # get mouse data
    $ymouse = $proc->get_u32( $offsets[$ver]{mouse_y} );
    $ztile  = $proc->get_u32( $offsets[$ver]{mouse_z} );
    
    ($xcell, $ycell) = ( int($xmouse/16), int($ymouse/16) );
    
    ($xtile, $ytile) = ( $xmouse%16, $ymouse%16 );
    
                                                    # get the offsets of the address storages for each x-slice and cycle through
    @xoffsets = $proc->get_packs("L", 4, $map_base, $xcount);
                                                        # get the offsets of the address storages for each y-column in this x-slice and cycle through
    @yoffsets = $proc->get_packs("L", 4, $xoffsets[$xcell], $ycount);
                                                            # get the offsets of each z-block in this y-column and cycle through
    @zoffsets = $proc->get_packs("L", 4, $yoffsets[$ycell], $zcount);

	if ( $zoffsets[$ztile] == 0 ) {
        print "\n\nTile not allocated. Designate target area, even if mid-air, then restart script."; # DANGER DANGER WILL ROBINSON
        print "\nPress enter to exit."; # DANGER DANGER WILL ROBINSON
        my $input = <STDIN>;
        exit;
	}

    process_block(                                  # process the data in one block
        $zoffsets[$ztile],                             # offset of the current block
        $xtile,                                        # x location of the current block
        $ytile );                                      # y location of the current block
}

sub process_block {
    my ($block_offset, $bx, $by) = @_;

    my $tile_index = $by+($bx*16);                  # this calculates the tile index we are currently at, from the x and y coords in this block

    my $type =          $proc->get_u16( $block_offset+$offsets[$ver]{type_off}+(2*$tile_index) );   # extract type/designation/occupation for this block
    my $designation =   $proc->get_u32( $block_offset+$offsets[$ver]{designation_off}+(4*$tile_index) );
    my $ocupation =     $proc->get_u32( $block_offset+$offsets[$ver]{occupancy_off}+(4*$tile_index) );
    
    my $tile = sprintf "%04d %032b %032b", $type, $designation, $ocupation;
    say "\n$tile";
    say "Please enter a small description:";
    my $input = <STDIN>;
    
    open my $LOG, ">>", "log.txt";
    print $LOG "$tile <- $input";
    close $LOG;
}


################################################################################

sub ask { print "$_[0]"; }
