#!/usr/bin/perl
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
use Getopt::Long;
use LWP::Simple;

my ($dwarf_pid, $pe_timestamp, $ver, $input, $show_hidden, $quiet, $no_ask,
    $help, $proc, @offsets, $update_only);

my @full_map_data;                              # array to hold the full extracted map data
my $bin_version = 1;                            # version of the binary memory map format, last changed 080103
my $version = 1.000;                            # version of the map_extract tool
my $map_name = "Fortressname";                  # default fortress name

populate_memory_data_store();

parse_parameters();

$ver = init_process_connection();

refresh_datastore() unless $ver;

if ($update_only) {
    undef $proc;    # close process
    say "Version data update complete.";    
}
else {
    my ( $xcount, $ycount, $zcount ) = map_extract() if $ver;
    undef $proc;    # close process
    
    say( "Done reading DF memory, printing to files." );
    print_files( $xcount, $ycount, $zcount );
    say( "Files printed, shutting down." );
}

say "";
say "Press enter to close...";
$input = <STDIN> unless ( $quiet or $no_ask );

################################################################################
### script ends here ###########################################################
################################################################################




################################################################################
### functions below, edit the end of populate_memory_data_store ################
### to add memory address data #################################################
################################################################################


sub populate_memory_data_store {
    @offsets = (
        {
            version => "v0.27.169.33a",
            PE => 0x4729DA32,
            map_loc => 0x01458568,
            x_count => 0x01458580,
            y_count => 0x01458584,
            z_count => 0x01458588,
            pe_timestamp_offset => 0x004000F8,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.169.33b",
            PE => 0x473E7E49,
            map_loc => 0x01459568,
            x_count => 0x01459580,
            y_count => 0x01459584,
            z_count => 0x01459588,
            pe_timestamp_offset => 0x004000F8,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.169.33c",
            PE => 0x47480E76,
            map_loc => 0x0145F560,
            x_count => 0x0145F578,
            y_count => 0x0145F57C,
            z_count => 0x0145F580,
            pe_timestamp_offset => 0x004000F8,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.169.33d",
            PE => 0x475099AA,
            map_loc => 0x01460560,
            x_count => 0x01460578,
            y_count => 0x0146057C,
            z_count => 0x01460580,
            pe_timestamp_offset => 0x004000F8,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.169.33e",
            PE => 0x475B7526,
            map_loc => 0x01461560,
            x_count => 0x01461578,
            y_count => 0x0146157C,
            z_count => 0x01461580,
            pe_timestamp_offset => 0x004000F8,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.169.33f",
            PE => 0x4763710C,
            map_loc => 0x01462568,
            x_count => 0x01462580,
            y_count => 0x01462584,
            z_count => 0x01462588,
            pe_timestamp_offset => 0x004000F8,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.169.33g",
            PE => 0x476CA6CE,
            map_loc => 0x01469680,
            x_count => 0x01469698,
            y_count => 0x0146969C,
            z_count => 0x014696A0,
            pe_timestamp_offset => 0x004000F8,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.176.38a",
            PE => 0x47A7D2A6,
            map_loc => 0x014929CC,
            x_count => 0x014929E4,
            y_count => 0x014929E8,
            z_count => 0x014929EC,
            pe_timestamp_offset => 0x00400100,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.176.38a",
            PE => 0x47B6FAC2,
            map_loc => 0x014A4EAC,
            x_count => 0x014A4EC4,
            y_count => 0x014A4EC8,
            z_count => 0x014A4ECC,
            pe_timestamp_offset => 0x00400100,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.27.176.38c",
            PE => 0x47C29583,
            map_loc => 0x014A60A4,
            x_count => 0x014A60BC,
            y_count => 0x014A60C0,
            z_count => 0x014A60C4,
            pe_timestamp_offset => 0x00400100,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
        {
            version => "v0.28.181.39c",
            PE => 0x487f2f30,
            map_loc => 0x01555048,
            x_count => 0x01555060,
            y_count => 0x01555064,
            z_count => 0x01555068,
            pe_timestamp_offset => 0x00400108,
            type_off        => 0x005E,
            designation_off => 0x0260,
            occupancy_off   => 0x0660,
        },
    ); # OFFSETS END HERE - DO NOT REMOVE THIS COMMENT
    
################################################################################
### add memory address data above the line marking the end of the ##############
### offsets in the same manner as the other blocks are formatted ###############
################################################################################
    
}


################################################################################


sub parse_parameters {
    Getopt::Long::Configure ("bundling");
    GetOptions (    "n|name=s"              => \$map_name,  
                    "s|show"                => \$show_hidden,
                    "u|updateonly"          => \$update_only,
                    "h|help"                => \$help,  
                    "a|no_ask"              => \$no_ask,  
                    "q|quiet"               => \$quiet); 
                    
    if ( $help ) {
        say("
    map_extract.pl - extracts dwarf fortress map data from the memory while ingame
    
    Usage:
    
     map_extract [options]
    
     Options:
       -n, --name=NAME    sets the name of the fortress, default: Fortressname
       -s, --show         makes hidden tiles show up, can cause slow-down, def: off
       -q, --quiet        prevents the printing of informations: def: off
       -a, --no_ask       prevents requests for user input: default off
       -h, --help         displays this help   
    
    Sample:
     
     This exports a fortress with the name Axedgears, without asking the user for
     any further input, while including data about hidden tiles.
     
     map_extract -as -n=Axedgears");
    exit;
    }
    else {
        say("map_extract.pl - extracts dwarf fortress map data from the memory while ingame\nShow help with 'map_extract -h'.\n");
    }
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
            unless ( $no_ask ) {
                ask( "We seem to be using: DF $offsets[$i]{version}\nIf this is not the correct version, please contact Xenofur/Mithaldu, as you might risk disastrous and hilarious results.\n--> Is this the correct version? (yes/no) [yes] " );
                chomp( my $input = <STDIN> );
                croak "\nVersion could not be correctly identified. Please contact Xenofur/Mithaldu or Jifodu for updated memory addresses.\n"
                    if ( $input and ($input !~ /y/i) );
            }
            return $i;
        }
    }
}


################################################################################


sub refresh_datastore {
    say "Could not find DF version in local data store. Checking for new memory address data...";
    import_local_xml();
    import_remote_xml();
    say "";

    $ver = init_process_connection();

    if (!$ver) {
        croak "Version could not be correctly identified. Please contact Xenofur/Mithaldu or Jifodu for updated memory addresses.\n";
    }
}

sub import_remote_xml {
    say "  Remotely...";
    my $source = "http://www.geocities.com/jifodus/tables/dwarvis/";
    my @xml_list;

    my $list = get($source);
    die "Couldn't get it!" unless defined $list;
    
    while ( $list =~ m/<A HREF="(.+?\.xml)">/gi ) {
        push @xml_list, $1;
    }
    
    say "    Found ".($#xml_list+1)." memory data files...";
    
    for my $file (@xml_list) {
        my $known = 0;
        for my $i ( 0..$#offsets ) {
            $known = 1 if $file =~ m/$offsets[$i]{version}/;
        }
        
        if ($known) {
            say "    One file ($file) discarded, memory data inside already known.";
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

sub import_local_xml {
    say "  Locally...";
    my @xml_list = glob "..\\conf\\*.xml";
    
    say "    Found ".($#xml_list+1)." memory data files...";
    
    for my $file (@xml_list) {    
        my $known = 0;  
        for my $i ( 0..$#offsets ) {
            $known = 1 if $file =~ m/$offsets[$i]{version}/;
        }
        
        if ($known) {
            say "    One file ($file) discarded, memory data inside already known.";
            next;
        }
        
        open my $HANDLE, "<", $file;
        my $xml = do { local $/; <$HANDLE>; };
        close $HANDLE;
        
        process_xml($xml);
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
        
    for my $i ( 0..$#offsets ) {
        return 0 if $offsets[$i]{version} eq $config_hash{version};
    }
    
    say "    Recognized new memory address data for DF $config_hash{version}, inserting into data store.";
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


sub map_extract {
    unless ( $show_hidden or $no_ask ) {
        ask( "--> Do you want to show hidden tiles? (can cause slow-down) (yes/no) [no] " );
        $input = <STDIN>;
        $show_hidden = 1 if ( $input =~ /y/i  );
    }
        
    unless ( $no_ask ) {
        ask( "--> Please enter the name of your fortress (1 word, alphanumeric + _) [FortressName]: " );
        $map_name = <STDIN>;
        $map_name =~ /.*?(\w+).*?/;
        $map_name = $1;
        $map_name = "FortressName" unless $map_name;
    }
    
    say "";
    say "Processing map data.";
    
    return loadmap();
}

sub loadmap {
    say( "Loading map data." );

    my $map_base;                                   # offset of the address where the map blocks start
    my ($xcount, $ycount, $zcount);                 # dimensions of the map data we're dealing with
    my (@xoffsets,@yoffsets,@zoffsets);             # arrays to store the offsets of the place where other addresses are stored
    @full_map_data=[];                              # array to hold the full extracted map data
    
    $map_base = $proc->get_u32( $offsets[$ver]{map_loc} );        # checking whether the game has a map already
    croak "Map data is not yet available, make sure you have a game loaded." unless ( $map_base );

    $xcount = $proc->get_u32( $offsets[$ver]{x_count} );         # find out how much data we're dealing with
    $ycount = $proc->get_u32( $offsets[$ver]{y_count} );
    $zcount = $proc->get_u32( $offsets[$ver]{z_count} );
                                                    # get the offsets of the address storages for each x-slice and cycle through
    @xoffsets = $proc->get_packs("L", 4, $map_base, $xcount);
    for my $bx ( 0..$#xoffsets ) {
                                                        # get the offsets of the address storages for each y-column in this x-slice and cycle through
        @yoffsets = $proc->get_packs("L", 4, $xoffsets[$bx], $ycount);
        for my $by ( 0..$#yoffsets ) {
                                                            # get the offsets of each z-block in this y-column and cycle through
            @zoffsets = $proc->get_packs("L", 4, $yoffsets[$by], $zcount);
            for my $bz ( 0..$#zoffsets ) {

                next if ( $zoffsets[$bz] == 0 );                # go to the next block if this one is not allocated

                process_block(                                  # process the data in one block
                    $zoffsets[$bz],                             # offset of the current block
                    $bx,                                        # x location of the current block
                    $by,                                        # y location of the current block
                    $bz );                                      # z location of the current block

            }
        }
    }
    
    return ( $xcount, $ycount, $zcount );
}

sub process_block {
    my ($block_offset, $bx, $by, $bz) = @_;

    my @type_data        = $proc->get_packs(        # extract type/designation/occupation arrays for this block
        "S", 2,                                     # format and size in bytes of each data unit
        $block_offset+$offsets[$ver]{type_off},            # starting offset
        256);                                       # number of units
    my @designation_data = $proc->get_packs("L", 4, $block_offset+$offsets[$ver]{designation_off}, 256);
    my @ocupation_data   = $proc->get_packs("L", 4, $block_offset+$offsets[$ver]{occupancy_off},   256);

    for my $y ( 0..15 ) {                           # cycle through 16 x and 16 y values, which generate a total of 256 tile indexes
        for my $x ( 0..15 ) {

            my $tile_index = $y+($x*16);                # this calculates the tile index we are currently at, from the x and y coords in this block

            next if ( ( $designation_data[$tile_index] & 512 ) == 512 and !$show_hidden );    # skip tile if it is hidden

            my $real_x = ($bx*16)+$x;                   # this calculates the real x and y values of this tile on the overall map_base
            my $real_y = ($by*16)+$y;

            $full_map_data[$real_x][$real_y][$bz] =     # store in the array that holds the full map data :
                $type_data[$tile_index] . ":" .         # the type data of the tile with the current index
                $designation_data[$tile_index] . ":" .  # the designation data of the tile with the current index
                $ocupation_data[$tile_index];           # the occupation data of the tile with the current index
        }
    }
}


################################################################################

sub print_files {
    my ($xcount, $ycount, $zcount) = @_;
    my $real_z;
    
    my $page = "$map_name|$xcount|$ycount\n";               #lite
    my $page2 = "$map_name|$xcount|$ycount\n";              #full
    my $page3_head =    "DFMM". pack ( "C",$bin_version ) ."\n".
                        "$map_name\n". 
                    pack ( "C", $xcount ) . pack ( "C", $ycount );
    my $page3 = "\n";    #bin
    
    for my $z ( 0..$zcount-1 ) {
        my $map1 = sprintf ("-%03d-\n", $z);
        my $map2 = sprintf ("-%03d-\n", $z);
        my $map3;
        my $allocated;
        for my $y ( 0..($ycount*16)-1 ) {
            my $line1;
            my $line2;
            my $line3;
            for my $x ( 0..($xcount*16)-1 ) {
                if ($full_map_data[$x][$y][$z]) {
                    $line1 .= sprintf ( "%4d ", split (/:/, $full_map_data[$x][$y][$z], 2) );
                    $line2 .= $full_map_data[$x][$y][$z]."|";
                    $line3 .= pack ( "SLL", split ( /:/, $full_map_data[$x][$y][$z] ) );
                    $allocated = 1;
                }
                else {
                    $line1 .= "  -1 ";
                    $line2 .= "-1|";
                    $line3 .= pack ( "SLL", 0, 0, 0 );
                }
            }
            $line2 =~ s/\|$//;
            $map1 .= $line1."\n";
            $map2 .= $line2."\n";
            $map3 .= $line3;
        }
        
        if ($allocated) {
            $map1 =~ s/\n$//;
            $map2 =~ s/\n$//;
            $page .= $map1."\n";
            $page2 .= $map2."\n";
            $page3 .= $map3."\n";
            $real_z++;
        }
        say( " ". $z+1 ." / $zcount" );
    }
        
    $page =~ s/\n$//;
    $page2 =~ s/\n$//;
    $page3 =~ s/\n$//;
    
    $page3 = $page3_head. pack ( "C", $real_z ) .$page3;
    
    open my $DAT, ">", "lite\\lite_$map_name.txt" or croak( "horribly: $!" );
    print $DAT $page;
    close $DAT;
    
    my $gz = gzopen("save\\full_$map_name.txt.gz", "wb9") or croak( "horribly: ".$gzerrno );
    $gz->gzwrite($page2)  or croak( "horribly: ".$gzerrno );
    $gz->gzclose ;
    
    $gz = gzopen("bin_$map_name.txt.gz", "wb9") or croak( "horribly: ".$gzerrno );
    $gz->gzwrite($page3)  or croak( "horribly: ".$gzerrno );
    $gz->gzclose ;
}


################################################################################


sub ask { print "$_[0]"; }


__END__


# some notes:
################################################################################

#print "\nContent of $df_offset -> $df_offset + 0x80\n";           # do a hex dump starting at offset with given length
#print $proc->hexdump( $df_offset, 0x80 );
#
#$proc->get_buf( $df_offset, 10, my $string_buffer );                         # read and output various values
#printf ( "\n0x%X [string of length 10]   : %s\n", $df_offset, $string_buffer );
#printf ( "0x%X [unsigned int8  in hex] : %x\n", $df_offset, $proc->get_u8($df_offset) );
#printf ( "0x%X [unsigned int16 in hex] : %x\n", $df_offset, $proc->get_u16($df_offset) );
#printf ( "0x%X [unsigned int32 in hex] : %x\n", $df_offset, $proc->get_u32($df_offset) );

# Sample Output:
#
# Content of 8995724 -> 8995724 + 0x80
# 00894380 :                                     44 77 61 72 :             Dwar
# 00894390 : 66 20 46 6F 72 74 72 65 73 73 00 00 45 72 72 6F : f Fortress..Erro
# 008943A0 : 72 00 00 00 45 72 72 6F 72 20 52 65 67 69 73 74 : r...Error Regist
# 008943B0 : 65 72 69 6E 67 20 57 69 6E 64 6F 77 20 43 6C 61 : ering Window Cla
# 008943C0 : 73 73 21 00 45 72 72 6F 72 20 43 72 65 61 74 69 : ss!.Error Creati
# 008943D0 : 6E 67 20 4F 70 65 6E 47 4C 20 57 69 6E 64 6F 77 : ng OpenGL Window
# 008943E0 : 00 00 00 00 72 62 00 00 4D 6F 64 65 20 53 77 69 : ....rb..Mode Swi
# 008943F0 : 74 63 68 20 46 61 69 6C 65 64 2E 0A 52 75 6E 6E : tch Failed..Runn
# 00894400 : 69 6E 67 20 49 6E 20 57 69 6E 64 6F             : ing In Windo
#
# 0x89438C [string of length 10]   : Dwarf Fort
# 0x89438C [unsigned int8  in hex] : 44
# 0x89438C [unsigned int16 in hex] : 7744
# 0x89438C [unsigned int32 in hex] : 72617744