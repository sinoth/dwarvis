#!/usr/bin/perl
use strict;
use warnings;
use Carp;

$|=1;

use Win32::Process::List;
use Win32::Process;
use Win32::Process::Memory;
use Compress::Zlib;

### set up variables ###########################################################
################################################################################
my ($dwarf_pid, $pe_timestamp, $ver);

my $pe_timestamp_offset = 0x004000F8;

my @offsets = (
    {
        version => "v0.27.169.33d",
        PE => 0x475099AA,
        map_loc => 0x01460560,
        x_count => 0x01460578,
        y_count => 0x0146057C,
        z_count => 0x01460580,
        mouse_x => 0x008FD288,
        mouse_y => 0x008FD28C,
        mouse_z => 0x008FD290
    },
    {
        version => "v0.27.169.33e",
        PE => 0x475B7526,
        map_loc => 0x01461560,
        x_count => 0x01461578,
        y_count => 0x0146157C,
        z_count => 0x01461580,
        mouse_x => 0x008FD288,
        mouse_y => 0x008FD28C,
        mouse_z => 0x008FD290
    },
    {
        version => "v0.27.169.33f",
        PE => 0x4763710C,
        map_loc => 0x01462568,
        x_count => 0x01462580,
        y_count => 0x01462584,
        z_count => 0x01462588,
        mouse_x => 0x008FD288,
        mouse_y => 0x008FD28C,
        mouse_z => 0x008FD290
    },
    {
        version => "v0.27.169.33g",
        PE => 0x476CA6CE,
        map_loc => 0x01469680,
        x_count => 0x01469698,
        y_count => 0x0146969C,
        z_count => 0x014696A0,
        mouse_x => 0x00906288,
        mouse_y => 0x0090628C,
        mouse_z => 0x00906290
    },
);

my $tile_type_offset        = 0x005E;
my $tile_designation_offset = 0x0260;
my $tile_occupancy_offset   = 0x0660;

my $proc;

my @full_map_data;                              # array to hold the full extracted map data

### get dwarf process id #######################################################
################################################################################
my %list = Win32::Process::List->new()->GetProcesses();
for my $key ( keys %list ) {
    $dwarf_pid = $key   if ( $list{$key} =~ /dwarfort.exe/ );
}
croak "Couldn't find process ID, make sure DF is running and a savegame is loaded." unless ( $dwarf_pid );

### lower priority of dwarf fortress ###########################################
################################################################################
Win32::Process::Open( my $dwarf_process, $dwarf_pid, 1 );
$dwarf_process->SetPriorityClass( IDLE_PRIORITY_CLASS );
croak "Couldn't lower process priority, this is really odd and shouldn't happen, try running as administrator or poke Mithaldu/Xenofur." unless ( $dwarf_process );

### actually read stuff from memory ############################################
################################################################################
$proc = Win32::Process::Memory->new({ pid  => $dwarf_pid, access => 'all' });   # open process with read access
croak "Couldn't open memory access to Dwarf Fortress, this is really odd and shouldn't happen, try running as administrator or poke Mithaldu/Xenofur." unless ( $proc );


### Let's Pla... erm, figure out what version this is ##########################
################################################################################
$pe_timestamp = $proc->get_u32( $pe_timestamp_offset );
for my $i ( 0..$#offsets ) {
    if ( $offsets[$i]{PE} == $pe_timestamp ) {
        print "We seem to be using: DF $offsets[$i]{version}\nIf this is correct, press enter. If not, please CTRL+C now and contact Xenofur/Mithaldu, as you might risk disastrous and hilarious results.\n";
        $ver = $i;
        last;
    }
}
    
while ( my $input = <STDIN> ) {
    chomp($input);
    last if $input eq 'q';
    loadmap();
    print "\nPress enter to work on next tile or enter q to quit.\n";
}

undef $proc;                                                # close process



################################################################################

sub loadmap {
    my $map_base;                                   # offset of the address where the map blocks start
    my ($xcount, $ycount, $zcount);                 # dimensions of the map data we're dealing with
    my ($xmouse, $ymouse, $zmouse);                 # cursor coordinates
    my ($xcell, $ycell, $zcell);                    # cursor cell coordinates
    my ($xtile, $ytile, $ztile);                    # cursor tile coordinates inside the cell adressed above
    my (@xoffsets,@yoffsets,@zoffsets);             # arrays to store the offsets of the place where other addresses are stored
    
    $map_base = $proc->get_u32( $offsets[$ver]{map_loc} );       # checking whether the game has a map already
    croak "Map data is not yet available, make sure you have a game loaded." unless ( $map_base );

    $xcount = $proc->get_u32( $offsets[$ver]{x_count} );         # find out how much data we're dealing with
    $ycount = $proc->get_u32( $offsets[$ver]{y_count} );
    $zcount = $proc->get_u32( $offsets[$ver]{z_count} );
    
    $xmouse = $proc->get_u32( $offsets[$ver]{mouse_x} );         # get mouse data
    $ymouse = $proc->get_u32( $offsets[$ver]{mouse_y} );
    $ztile = $proc->get_u32( $offsets[$ver]{mouse_z} );
    
    ($xcell, $ycell) = ( int($xmouse/16), int($ymouse/16) );
    
    ($xtile, $ytile) = ( $xmouse%16, $ymouse%16 );
    
    
    print "Tile at [ " . (($xcell*16)+$xtile) . "x " . (($ycell*16)+$ytile) . "y $ztile"."z ] :";
    
                                                    # get the offsets of the address storages for each x-slice and extract the tile x address
    @xoffsets = $proc->get_packs("L", 4, $map_base, $xcount);
    
                                                    # get the offsets of the address storages for each y-column in this x-slice and extract the tile y address
    @yoffsets = $proc->get_packs("L", 4, $xoffsets[$xcell], $ycount);

                                                    # get the offsets of each z-block in this y-column and cycle through
    @zoffsets = $proc->get_packs("L", 4, $yoffsets[$ycell], $zcount);
    
    croak "Tile not allocated, designate target area, even if mid-air." if ( $zoffsets[$ztile] == 0 ); # DANGER DANGER WILL ROBINSON

    process_block(                                  # process the data in one block
        $zoffsets[$ztile],                          # offset of the current cell
        $xtile,                                     # x location of the current tile in the cell
        $ytile );                                   # y location of the current tile in the cell

}

sub process_block {
    my ($block_offset, $bx, $by) = @_;
    
    my $tile_index = $by+($bx*16);                  # this calculates the tile index we are currently at, from the x and y coords in this block

    my $type =          $proc->get_u16( $block_offset+$tile_type_offset+(2*$tile_index) );   # extract type/designation/occupation for this block
    my $designation =   $proc->get_u32( $block_offset+$tile_designation_offset+(4*$tile_index) );
    my $ocupation =     $proc->get_u32( $block_offset+$tile_occupancy_offset+(4*$tile_index) );
    
    print " has " . ($designation & 7) . " units of ";    
    if ( ( $designation & 67108864 ) == 67108864 ) {
        if ( (( $designation & 2097152 ) == 2097152) and (( $designation & 536870912 ) == 536870912) ) { print "lava."; }
        else { print "water."; }
    }
    else { print "no liquid."; }
    
    $designation = $designation | 67108864;
    $designation = $designation | 7;
    
    print "\nFill it with " . ($designation & 7) . " units of ";    
    if ( ( $designation & 67108864 ) == 67108864 ) {
        if ( (( $designation & 2097152 ) == 2097152) and (( $designation & 536870912 ) == 536870912) ) { print "lava? (y/n)"; }
        else { print "water? (y/n)"; }
    }
    
    my $input = <STDIN>;
    chomp($input);
    
    if ($input eq 'y') {
        $proc->set_u32( $block_offset+$tile_designation_offset+(4*$tile_index), $designation );
    }
    else {
        return;
    }

#    for my $y ( 0..15 ) {                           # cycle through 16 x and 16 y values, which generate a total of 256 tile indexes
#        for my $x ( 0..15 ) {
#
#            my $tile_index = $y+($x*16);                # this calculates the tile index we are currently at, from the x and y coords in this block
#
#		next if ( ( $designation_data[$tile_index] & 512 ) == 512 );	# skip tile if it is hidden
#
#            my $real_x = ($bx*16)+$x;                   # this calculates the real x and y values of this tile on the overall map_base
#            my $real_y = ($by*16)+$y;
#
#            $full_map_data[$real_x][$real_y][$bz] =     # store in the array that holds the full map data :
#                $type_data[$tile_index] . ":" .         # the type data of the tile with the current index
#                $designation_data[$tile_index] . ":" .  # the designation data of the tile with the current index
#                $ocupation_data[$tile_index];           # the occupation data of the tile with the current index
#        }
#    }
}

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