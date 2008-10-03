#!/usr/bin/perl

# $Id$
# $Revision$
# $HeadURL$
# $Date$
# $Source$

package Lifevis;

use 5.010;
use strict;
use warnings;

#use warnings::unused;
#use warnings::method;
#use diagnostics;

#=cut
use criticism (
    -exclude => [
        'ProhibitCallsToUndeclaredSubs',
        'ProhibitConstantPragma',
        'RequireExtendedFormatting',
        'ProhibitComplexRegexes',
        'RequireVersionVar',
        'ProhibitLongLines',
        'ProhibitMagicNumbers',        # TODO : Reconsider this.
        'ProhibitCommentedOutCode',    # TODO : Comment out in clean-up
        'ProhibitFlagComments',        # TODO : Comment out in clean-up
        'ProhibitPostfixControls',
        'RequireLineBoundaryMatching',
        'ProhibitAccessOfPrivateData',
        'RequireDotMatchAnything',
        'RequireUseOfExceptions',
        'RequireEmacsFileVariables',
        'RequirePodSections',          # TODO : Reconsider this.
        'ProhibitCallsToUnexportedSubs',
        'ProhibitTies'
    ],
    -severity => 1
);

#=cut
use Carp;
use utf8;
use English qw(-no_match_vars);
$OUTPUT_AUTOFLUSH = 1;

use lib '.';
use Lifevis::constants;
use Lifevis::df_offsets;

use threads;
use threads::shared;

use Config::Simple;

use Win32::OLE('in');

my $memory_use;
$memory_use = 0;
our $ZCOUNT;
our @TILE_TYPES;
our %DRAW_MODEL;
my %c;
tie %c, 'Config::Simple', 'lifevis.cfg';

my @OFFSETS = get_df_offsets();
my $ver;
my $proc;

my ( $xcount, $ycount )
  ;    # dimensions of the map data we're dealing with, counts in cells
my ( $x_max, $y_max )
  ;             # dimensions of the map data we're dealing with, counts in tiles
my $map_base;   # offset of the address where the map blocks start

my @cells;
my %creatures_present;
my $current_creat_proc_task = 0;
my $max_creat_proc_tasks    = 0;
my %creatures;

# cursor coordinates  in tiles at last refresh
my ( $xmouse_old, $ymouse_old, $zmouse_old ) = ( 0, 0, 15 );

# current cursor coordinates in tiles
my ( $xmouse, $ymouse, $zmouse ) = ( 0, 0, 15 );

# Camera position and rotation variables.
my ( $x_pos, $y_pos, $z_pos, $x_off, $y_off, $z_off, $x_rot, $y_rot );

# current cursor coordinates in cells
my ( $xcell, $ycell ) = ( $c{view_range}, $c{view_range} );

my $min_x_range;
my $max_x_range;
my $min_y_range;
my $max_y_range;

my $current_data_proc_task = 0;
my $max_data_proc_tasks    = 0;
my @cache;
my @cache_bucket;
my @protected_caches;

my @texture_ID;
my @creature_display_lists;
my @tiles;
my @ramps;

my $dwarf_pid;
my $pe_timestamp;

# Settings for our light.  Try playing with these (or add more lights).
my @light_ambient = ( 0.7, 0.7, 0.7, 1.0 );
my @light_diffuse = ( 0.9, 0.9, 0.9, 1.0 );

#my @light_specular  = ( 0.9,  0, 0, 1.0 );
my @light_position = ( -0.8, 1.5, 1.0, 0.0 );

my ( $submenid, $menid );
my $window_ID;
my $DF_window;
my $next_cede_time = 0;

my $middle_mouse = 0;
my $last_mouse_x;
my $last_mouse_y;
my $mouse_dist = 40;

my ( %sin_cache, %cos_cache );

__PACKAGE__->run(@ARGV) unless caller();

BEGIN {
    share($memory_use);

    sub update_memory_use {
        my @state_array;
        my $pid        = $PROCESS_ID;
        my $sleep_time = 2;
        my $WMI_service_object =
             Win32::OLE->GetObject("winmgmts:\\\\.\\root\\CIMV2")
          or croak "WMI connection failed.\n";

        while (1) {
            @state_array = in $WMI_service_object->ExecQuery(
                'SELECT PrivatePageCount FROM Win32_Process'
                  . " WHERE ProcessId = $pid",
                'WQL',
                0x10 | 0x20
            );
            $memory_use = $state_array[0]->{PrivatePageCount};
            sleep $sleep_time;
        }
        return 1;
    }
    my $thr = threads->create( { 'stack_size' => 64 }, \&update_memory_use );
    $thr->detach();

}

sub run {
    use Benchmark ':hireswallclock';

    use Time::HiRes qw ( time );
    use Coro qw[ cede ];
    $c{redraw_delay} = 1 / $c{fps_limit};

    use OpenGL qw/ :all /;
    use OpenGL::Image;
    use Math::Trig;
    use Win32;
    use Win32::Process::List;
    use Win32::Process;
    use Win32::Process::Memory;
    use LWP::Simple;
    use Image::Magick;
    use Win32::GUI::Constants qw ( :window :accelerator );
    use Win32::GuiTest qw(:FUNC :VK);

    # %DB::packages = ( 'main' => 1 );

  # Dwarf Fortress 3D Map Viewer
  #
  # The base intention of this program is to provide an OpenGL engine capable of
  # rendering ascii-based map files in such a way as to semi-accurately display
  # the interior layout of a dwarven fortress and surroundings.
  #
  # It is Public Domain software.
  #
  # This program based on this:
  #
    ### ----------------------
    ### OpenGL cube demo.
    ###
    ### Written by Chris Halsall (chalsall@chalsall.com) for the
    ### O'Reilly Network on Linux.com (oreilly.linux.com).
    ### May 2000.
    ###
    ### Released into the Public Domain; do with it as you wish.
    ### We would like to hear about interesting uses.
    ###
    ### Coded to the groovy tunes of Yello: Pocket Universe.
    ###
    ### Translated from C to Perl by J-L Morel <jl_morel@bribes.org>
    ### ( http://www.bribes.org/perl/wopengl.html )

    # Some global variables.

    # Window and texture IDs, window width and height.

    # Object and scene global variables.

    $x_pos = 0;
    $y_pos = 0;
    $z_pos = 0;
    $x_rot = -45.0;
    $y_rot = 157.5;
    reposition_camera();    # sets up initial camera position offsets

# hashes containing the functions called on certain key presses
#my ( %special_inputs, %normal_inputs ); # disabled until we actually pipe stuff to lifevis again

    $DF_window = FindWindowLike( 0, '^Dwarf Fortress$' );

    my $slice         = 0;
    my $slice_follows = 0;

    unless ( my $return = do 'df_internals.pl' ) {
        warn "couldn't parse df_internals.pl: $@" if $@;
        warn "couldn't do df_internals.pl: $!" unless defined $return;
        warn "couldn't run df_internals.pl" unless $return;
    }

# TODO: Split these and ramp-tops into seperate models. Fix texturing on ramp models where i fucked up diagonals.
    @ramps = (
        { mask => 0b0_1111_0000, func => '4S' },
        { mask => 0b0_1101_0000, func => '3S1' },
        { mask => 0b0_1110_0000, func => '3S2' },
        { mask => 0b0_0111_0000, func => '3S3' },
        { mask => 0b0_1011_0000, func => '3S4' },
        { mask => 0b0_1100_0010, func => '2S_1D1' },
        { mask => 0b0_0110_0001, func => '2S_1D2' },
        { mask => 0b0_0011_1000, func => '2S_1D3' },
        { mask => 0b0_1001_0100, func => '2S_1D4' },
        { mask => 0b0_1100_0000, func => '2S1' },
        { mask => 0b0_0110_0000, func => '2S2' },
        { mask => 0b0_0011_0000, func => '2S3' },
        { mask => 0b0_1001_0000, func => '2S4' },
        { mask => 0b0_1010_0000, func => '1S_1S1' },
        { mask => 0b0_0101_0000, func => '1S_1S2' },
        { mask => 0b0_1000_0100, func => '1S_1DL1' },
        { mask => 0b0_0100_0010, func => '1S_1DL2' },
        { mask => 0b0_0010_0001, func => '1S_1DL3' },
        { mask => 0b0_0001_1000, func => '1S_1DL4' },
        { mask => 0b0_1000_0010, func => '1S_1DR1' },
        { mask => 0b0_0100_0001, func => '1S_1DR2' },
        { mask => 0b0_0010_1000, func => '1S_1DR3' },
        { mask => 0b0_0001_0100, func => '1S_1DR4' },
        { mask => 0b0_1000_0000, func => '1S1' },
        { mask => 0b0_0100_0000, func => '1S2' },
        { mask => 0b0_0010_0000, func => '1S3' },
        { mask => 0b0_0001_0000, func => '1S4' },
        { mask => 0b0_0000_1111, func => '4D' },
        { mask => 0b0_0000_1101, func => '3D1' },
        { mask => 0b0_0000_1110, func => '3D2' },
        { mask => 0b0_0000_0111, func => '3D3' },
        { mask => 0b0_0000_1011, func => '3D4' },
        { mask => 0b0_0001_1100, func => '1S_2D4' },
        { mask => 0b0_1000_0110, func => '1S_2D1' },
        { mask => 0b0_0100_0011, func => '1S_2D2' },
        { mask => 0b0_0010_1001, func => '1S_2D3' },
        { mask => 0b0_0000_1001, func => '2D1' },
        { mask => 0b0_0000_1100, func => '2D2' },
        { mask => 0b0_0000_0110, func => '2D3' },
        { mask => 0b0_0000_0011, func => '2D4' },
        { mask => 0b0_0000_1010, func => '1D_1D1' },
        { mask => 0b0_0000_0101, func => '1D_1D2' },
        { mask => 0b0_0000_1000, func => '1D1' },
        { mask => 0b0_0000_0100, func => '1D2' },
        { mask => 0b0_0000_0010, func => '1D3' },
        { mask => 0b0_0000_0001, func => '1D4' },
        { mask => 0b1_0000_0000, func => 'N' },
    );

    unless ( my $return = do 'models.pl' ) {
        warn "couldn't parse models.pl: $@" if $@;
        warn "couldn't do models.pl: $!" unless defined $return;
        warn "couldn't run models.pl" unless $return;
    }

    # ------
    # The main() function.  Inits OpenGL.  Calls our own init function,
    # then passes control onto OpenGL.

    connect_to_DF();

    extract_base_memory_data();

    glutInit();

    print 'setting up OpenGL environment...   ';
    glutInitDisplayMode( GLUT_RGBA | GLUT_DOUBLE | GLUT_DEPTH );
    glutInitWindowSize( $c{window_width}, $c{window_height} );
    glutInitWindowPosition( 390, 250 );

    $window_ID = glutCreateWindow(PROGRAM_TITLE);    # Open a window

    create_menu();

# Set up Callback functions ####################################################

    # Register the callback function to do the drawing.
    glutDisplayFunc( \&render_scene );

    glutIdleFunc( \&idle_tasks );    # If there's nothing to do, draw.

    # It's a good idea to know when our window's resized.
    glutReshapeFunc( \&resize_scene );

    glutKeyboardFunc( \&process_key_press )
      ;                              # And let's get some keyboard input.
    glutSpecialFunc( \&process_special_key_press );

    glutMotionFunc( \&process_active_mouse_motion );
    glutMouseFunc( \&process_mouse_click );

    print "OpenGL environment ready.\n";

    print "initializing OpenGL...\n";

    # OK, OpenGL's ready to go.  Let's call our own init function.
    initialize_opengl( $c{window_width}, $c{window_height} );

    print "OpenGL initialized.\n";

    # Print out a bit of help dialog.
    print PROGRAM_TITLE, "\n";

    my $main_loop = $Coro::main;

    my $loc_loop = new Coro \&location_update_loop;
    my $success2 = $loc_loop->ready;

    my $land_loop = new Coro \&landscape_update_loop;
    my $success3  = $land_loop->ready;

    #refresh_map_data();
    generate_creature_display_lists();

    my $creat_loop = new Coro \&creature_update_loop;
    my $success    = $creat_loop->ready;

    # Pass off control to OpenGL.
    # Above functions are called as appropriate.
    print "switching to main loop...\n";

    glutMainLoop();

    print "moo";
}
################################################################################
## Rendering Functions #########################################################
################################################################################

sub extract_base_memory_data {
    $xcount = $proc->get_u32( $OFFSETS[$ver]{x_count} );    # map size in cells
    $ycount = $proc->get_u32( $OFFSETS[$ver]{y_count} );
    $ZCOUNT = $proc->get_u32( $OFFSETS[$ver]{z_count} );

    $x_max = ( $xcount * 16 ) - 1;
    $y_max = ( $ycount * 16 ) - 1;

    # checking whether the game has a map already
    $map_base = $proc->get_u32( $OFFSETS[$ver]{map_loc} );
    croak 'Map data is not yet available, make sure you have a game loaded.'
      unless ($map_base);

    # get the offsets of the address storages for each x-slice and cycle through
    my @xoffsets = $proc->get_packs( 'L', 4, $map_base, $xcount );
    for my $bx ( 0 .. $xcount - 1 ) {

        # get the offsets of the address storages
        # for each y-column in this x-slice and cycle through
        my @yoffsets = $proc->get_packs( 'L', 4, $xoffsets[$bx], $ycount );
        for my $by ( 0 .. $ycount - 1 ) {
            $cells[$bx][$by][offset] = $yoffsets[$by];
        }
    }

    return;
}

sub creature_update_loop {
    while (1) {
        my @creature_vector_offsets =
          $proc->get_packs( 'L', 4, $OFFSETS[$ver]{creature_vector} + 4, 2 );
        my $creature_list_length =
          ( $creature_vector_offsets[1] - $creature_vector_offsets[0] ) / 4;
        my @creature_offsets =
          $proc->get_packs( 'L', 4, $creature_vector_offsets[0],
            $creature_list_length );

        while ( my ( $key, $value ) = each %creatures_present ) {
            $value = 0;
        }

        for my $creature (@creature_offsets) {
            $creatures_present{$creature} = 1;
        }

        $current_creat_proc_task = 0;
        $max_creat_proc_tasks    = $#creature_offsets;

        for my $creature (@creature_offsets) {

            #        say $proc->hexdump( $creature_offsets[$creature], 0x688 );

            # extract data of current creature
            my $rx = $proc->get_u16( $creature + 148 );
            next if ( $rx > $xcount * 16 );
            my $rz = $proc->get_u16( $creature + 152 );
            next if ( $rz > $ZCOUNT + 1 );
            my $race        = $proc->get_u32( $creature + 140 );
            my $ry          = $proc->get_u16( $creature + 150 );
            my $name_length = $proc->get_u32( $creature + 20 );
            $proc->get_buf( $creature + 4, $name_length, my $name );

            # update record of current creature
            $creatures{$creature}[race] = $race;
            $creatures{$creature}[c_x]  = $rx;
            $creatures{$creature}[c_y]  = $ry;
            $creatures{$creature}[c_z]  = $rz;
            $creatures{$creature}[name] = $name;

            # get old and new cell location and compare
            my $old_x = $creatures{$creature}[cell_x];
            my $old_y = $creatures{$creature}[cell_y];
            my $bx    = int $rx / 16;
            my $by    = int $ry / 16;
            if ( !defined $old_x || $bx != $old_x || $by != $old_y ) {

                # creature moved to other cell or is new

  # get creature list of old cell then cycle through it and remove the old entry
                if ( defined $old_x ) {
                    glutPostRedisplay();
                    my $creature_list = $cells[$old_x][$old_y][creature_list];
                    for my $entry ( @{$creature_list} ) {
                        if ( $entry == $creature ) {
                            $entry = $creature_list->[$#$creature_list];
                            pop @{$creature_list};
                            last;
                        }
                    }
                }

                # add entry to new cell and update cell coordinates
                push @{ $cells[$bx][$by][creature_list] }, $creature;
                $creatures{$creature}[cell_x] = $bx;
                $creatures{$creature}[cell_y] = $by;
            }

            for ( 0 .. $c{creature_update_slow_rate} ) {
                cede();
            }
            $current_creat_proc_task++;
        }
    }
}

sub location_update_loop {

    while (1) {
        $xmouse_old = $xmouse;
        $ymouse_old = $ymouse;
        $zmouse_old = $zmouse;

        # get mouse data
        $xmouse = $proc->get_u32( $OFFSETS[$ver]{mouse_x} );
        $ymouse = $proc->get_u32( $OFFSETS[$ver]{mouse_y} );
        $zmouse = $proc->get_u32( $OFFSETS[$ver]{mouse_z} );

        #say $proc->get_u32( $OFFSETS[$ver]{menu_state} );
        #say $proc->get_u32( $OFFSETS[$ver]{view_state} );

        # use viewport coords if out of bounds, i.e. cursor not in use
        if (   $xmouse > $xcount * 16
            || $ymouse > $ycount * 16
            || $zmouse > $ZCOUNT )
        {
            $xmouse =
              $proc->get_u32( $OFFSETS[$ver]{viewport_x} ) +
              int( $proc->get_u32( $OFFSETS[$ver]{window_grid_x} ) / 6 );
            $ymouse =
              $proc->get_u32( $OFFSETS[$ver]{viewport_y} ) +
              int( $proc->get_u32( $OFFSETS[$ver]{window_grid_y} ) / 3 );
            $zmouse = $proc->get_u32( $OFFSETS[$ver]{viewport_z} );
        }

        glutPostRedisplay()
          if ( $xmouse != $xmouse_old
            || $ymouse != $ymouse_old
            || $zmouse != $zmouse_old );

        # update camera system with mouse data
        ( $x_pos, $z_pos, $y_pos ) = ( $xmouse, $ymouse, $zmouse );
        reposition_camera();    # sets up initial camera position offsets

        # calculate cell coords from mouse coords
        $xcell = int $xmouse / 16;
        $ycell = int $ymouse / 16;
        $xcell = $c{view_range} if $xcell <= $c{view_range} - 1;
        $ycell = $c{view_range} if $ycell <= $c{view_range} - 1;
        $xcell = $xcount - $c{view_range} - 1
          if $xcell >= $xcount - $c{view_range};
        $ycell = $ycount - $c{view_range} - 1
          if $ycell >= $ycount - $c{view_range};

        $min_x_range = $xcell - $c{view_range};
        $min_x_range = 0 if $min_x_range < 0;
        $max_x_range = $xcell + $c{view_range};
        $max_x_range = $xcount - 1 if $max_x_range > $xcount - 1;
        $min_y_range = $ycell - $c{view_range};
        $min_y_range = 0 if $min_y_range < 0;
        $max_y_range = $ycell + $c{view_range};
        $max_y_range = $ycount - 1 if $max_y_range > $ycount - 1;

        for ( 0 .. $c{cursor_update_slow_rate} ) {
            cede();
        }
    }
}

sub landscape_update_loop {
    while (1) {

        #TODO: When at the edge, only grab at inner edge.
        # cycle through cells in range around cursor to grab data
        for my $bx ( $min_x_range - 1 .. $max_x_range + 1 ) {
            next if ( $bx < 0 || $bx > $xcount - 1 );
            for my $by ( $min_y_range - 1 .. $max_y_range + 1 ) {
                next if ( $by < 0 || $by > $ycount - 1 );

                # cycle through slices in cell
                my @zoffsets =
                  $proc->get_packs( 'L', 4, $cells[$bx][$by][offset], $ZCOUNT );
                $cells[$bx][$by][changed] = 0
                  if !defined $cells[$bx][$by][changed];
                for my $bz ( 0 .. $#zoffsets ) {

                    # go to the next block if this one is not allocated
                    next if ( $zoffsets[$bz] == 0 );

                    # process slice in cell and set slice to changed
                    my $slice_changed = new_process_block(
                        $zoffsets[$bz],    # offset of the current slice
                        $bx,               # x location of the current slice
                        $by,               # y location of the current slice
                        $bz
                    );

                    # update changed status of cell if necessary
                    if ($slice_changed) {
                        $cells[$bx][$by][z][$bz] = 1;     # slice was changed
                        $cells[$bx][$by][changed] = 1;    # cell was changed
                    }

                    for ( 0 .. $c{landscape_update_slow_rate} ) {
                        cede();
                    }
                    $current_data_proc_task++;
                }
            }
        }

        # cycle through cells in range around cursor to generate display lists
        for my $bx ( $min_x_range .. $max_x_range ) {
            for my $by ( $min_y_range .. $max_y_range ) {

                my $cache_id;

                if ( defined $cells[$bx][$by][cache_ptr] ) {
                    $cache_id = $cells[$bx][$by][cache_ptr];

                    # cell is in cache
                    if ( $cells[$bx][$by][changed] ) {

                        # cycle through slices and
                        # create displaylists as necessary,
                        # storing the ids in the cache entry
                        my $slices = $cells[$bx][$by][z];
                        for my $slice ( 0 .. ( @{$slices} - 1 ) ) {
                            if ( @{$slices}[$slice] ) {
                                generate_display_list( $cache_id, $slice, $by,
                                    $bx );
                                @{$slices}[$slice] = 0;
                            }
                            glutPostRedisplay();
                            for ( 0 .. $c{landscape_update_slow_rate} ) {
                                cede();
                            }
                            $current_data_proc_task++;
                        }
                        $cells[$bx][$by][changed] = 0;
                    }

                    $cache[$cache_id][1]++;

                }
                else {

                    my $slices = $cells[$bx][$by][z];

                    next if !defined $slices;

                    # cell is not in cache

                  # get fresh cache id either from end of cache or out of bucket
                    $cache_id = $#cache + 1;
                    $cache_id = pop @cache_bucket if ( $#cache_bucket > -1 );

                    # set up link to cell and back-link to cache id
                    $cache[$cache_id][cell_ptr] = \$cells[$bx][$by][cache_ptr];
                    $cells[$bx][$by][cache_ptr] = $cache_id;
                    $cache[$cache_id][1]        = 0;

                    # cycle through slices and
                    # create displaylists as necessary,
                    # storing the ids in the cache entry
                    for my $slice ( 0 .. ( @{$slices} - 1 ) ) {
                        if ( defined @{$slices}[$slice] ) {
                            generate_display_list( $cache_id, $slice, $by,
                                $bx );
                            @{$slices}[$slice] = 0;
                        }
                        glutPostRedisplay();
                        for ( 0 .. $c{landscape_update_slow_rate} ) {
                            cede();
                        }
                        $current_data_proc_task++;
                    }
                    $cells[$bx][$by][changed] = 0;
                }

                $protected_caches[$cache_id] = 1;
            }
        }

        my $deletions = 0;

# TODO: Limit cache deletions so $c{view_range} is never undercut
# check that we're not using too much memory and destroy cache entries if necessary

        while ($memory_use > $c{memory_limit}
            && $deletions < ( 2 * $c{view_range} ) )
        {
            my $delete;
            my $use;

            for my $id ( 0 .. $#cache ) {

                # skip empty caches
                next if !defined $cache[$id][1];

                # skip caches we're currently looking at
                next if $protected_caches[$id];

                if ( !defined $use || $cache[$id][1] < $use ) {
                    $delete = $id;
                    $use    = $cache[$id][1];
                }
            }

            last if !defined $delete;

            my $slices = $cache[$delete];
            for my $slice ( 2 .. ( @{$slices} - 1 ) ) {
                glDeleteLists( $cache[$delete][$slice], 1 )
                  if ( $cache[$delete][$slice] );
            }

            undef ${ $cache[$delete][cell_ptr] };

            undef $cache[$delete];
            push @cache_bucket, $delete;

            $deletions++;
        }

        @protected_caches = [];

        $max_data_proc_tasks    = $current_data_proc_task;
        $current_data_proc_task = 0;
    }
    return;
}

sub generate_creature_display_lists {
    my $dl = glGenLists(1);
    push @creature_display_lists, $dl;
    glNewList( $dl, GL_COMPILE );
    glBindTexture( GL_TEXTURE_2D, $texture_ID[creature] );
    glBegin(GL_TRIANGLES);
    $DRAW_MODEL{Creature}->( 0, 0, 0, 1, 1 );
    glEnd();
    glEndList();
}

sub generate_display_list {
    my ( $id, $z, $y, $x ) = @_;
    my $dl;
    my $type;
    my $type_below;
    my $brightness_mod;

    if ( $cache[$id][ $z + 2 ] ) {
        $dl = $cache[$id][ $z + 2 ];
    }
    else {
        $dl = glGenLists(1);
        $cache[$id][ $z + 2 ] = $dl;
    }

    glNewList( $dl, GL_COMPILE );

    for my $texture ( 0 .. $#texture_ID ) {

        glBindTexture( GL_TEXTURE_2D, $texture_ID[$texture] );
        glBegin(GL_TRIANGLES);
        my $tile       = $tiles[$z][type];
        my $tile_below = $tiles[ $z - 1 ][type];
        my $tile_above = $tiles[ $z + 1 ][type];
        for my $rx ( ( $x * 16 ) .. ( $x * 16 ) + 15 ) {
            for my $ry ( ( $y * 16 ) .. ( $y * 16 ) + 15 ) {

                next if !defined $tile->[$rx][$ry];
                $type = $tile->[$rx][$ry];
                next if !defined $type;
                next if $type == 32;
                next if !defined $TILE_TYPES[$type][base_texture];
                next if $TILE_TYPES[$type][base_texture] != $texture;
                $type_below     = $tile_below->[$rx][$ry];
                $brightness_mod = $TILE_TYPES[$type][brightness_mod];

                my ( $below, $north, $south, $west, $east ) =
                  ( EMPTY, EMPTY, EMPTY, EMPTY, EMPTY );
                my ( $northeast, $southeast, $southwest, $northwest ) =
                  ( EMPTY, EMPTY, EMPTY, EMPTY );
                my $x_mod = $rx % 16;
                my $y_mod = $ry % 16;

                $below = $TILE_TYPES[$type_below][base_visual] if $type_below;

                if ( $TILE_TYPES[$type][base_visual] == WALL ) {
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;
                    die 'horribly' if !defined $DRAW_MODEL{Wall};
                    $DRAW_MODEL{Wall}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == FLOOR ) {
                    my $type_above = $tile_above->[$rx][$ry];
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                    $brightness_mod *= 0.75
                      if ( defined $type_above
                        && $TILE_TYPES[$type_above][base_visual] != EMPTY );

                    $DRAW_MODEL{Floor}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == TREE ) {
                    my $type_above = $tile_above->[$rx][$ry];
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                    $brightness_mod *= 0.75
                      if ( defined $type_above
                        && $TILE_TYPES[$type_above][base_visual] != EMPTY );

                    $DRAW_MODEL{Tree}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == SHRUB ) {
                    my $type_above = $tile_above->[$rx][$ry];
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                    $brightness_mod *= 0.75
                      if ( defined $type_above
                        && $TILE_TYPES[$type_above][base_visual] != EMPTY );

                    $DRAW_MODEL{Shrub}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == BOULDER ) {
                    my $type_above = $tile_above->[$rx][$ry];
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                    $brightness_mod *= 0.75
                      if ( defined $type_above
                        && $TILE_TYPES[$type_above][base_visual] != EMPTY );

                    $DRAW_MODEL{Boulder}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == SAPLING ) {
                    my $type_above = $tile_above->[$rx][$ry];
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                    $brightness_mod *= 0.75
                      if ( defined $type_above
                        && $TILE_TYPES[$type_above][base_visual] != EMPTY );

                    $DRAW_MODEL{Sapling}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == STAIR ) {
                    my $type_above = $tile_above->[$rx][$ry];
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                    $brightness_mod *= 0.75
                      if ( defined $type_above
                        && $TILE_TYPES[$type_above][base_visual] != EMPTY );

                    $DRAW_MODEL{Stairs}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == STAIR_UP ) {
                    my $type_above = $tile_above->[$rx][$ry];
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                    $brightness_mod *= 0.75
                      if ( defined $type_above
                        && $TILE_TYPES[$type_above][base_visual] != EMPTY );

                    $DRAW_MODEL{Stair_Up}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == STAIR_DOWN ) {
                    my $type_above = $tile_above->[$rx][$ry];
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                    $brightness_mod *= 0.75
                      if ( defined $type_above
                        && $TILE_TYPES[$type_above][base_visual] != EMPTY );

                    $DRAW_MODEL{Stair_Down}->(
                        $rx, $z, $ry, 1, $brightness_mod, $north, $west, $south,
                        $east, $below, EMPTY
                    );
                    next;
                }

                elsif ( $TILE_TYPES[$type][base_visual] == RAMP ) {
                    next
                      if ( defined $type_below
                        && $TILE_TYPES[$type_below][base_visual] == RAMP );
                    $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                      if $tile->[$rx][ $ry - 1 ] && $ry != 0;
                    $northeast =
                      $TILE_TYPES[ $tile->[ $rx + 1 ][ $ry - 1 ] ][base_visual]
                      if $tile->[ $rx + 1 ][ $ry - 1 ]
                          && ( $ry != 0 || $rx != $x_max );
                    $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                      if $tile->[ $rx + 1 ][$ry] && $rx != $x_max;
                    $southeast =
                      $TILE_TYPES[ $tile->[ $rx + 1 ][ $ry + 1 ] ][base_visual]
                      if $tile->[ $rx + 1 ][ $ry + 1 ]
                          && ( $ry != $y_max || $rx != $x_max );
                    $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                      if $tile->[$rx][ $ry + 1 ] && $ry != $y_max;
                    $southwest =
                      $TILE_TYPES[ $tile->[ $rx - 1 ][ $ry + 1 ] ][base_visual]
                      if $tile->[ $rx - 1 ][ $ry + 1 ]
                          && ( $ry != $y_max || $ry != 0 );
                    $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                      if $tile->[ $rx - 1 ][$ry] && $rx != 0;
                    $northwest =
                      $TILE_TYPES[ $tile->[ $rx - 1 ][ $ry - 1 ] ][base_visual]
                      if $tile->[ $rx - 1 ][ $ry - 1 ]
                          && ( $ry != 0 || $ry != 0 );

                    my $surroundings = 0;
                    $surroundings += ( $north == WALL )     ? 0b1000_0000 : 0;
                    $surroundings += ( $west == WALL )      ? 0b0100_0000 : 0;
                    $surroundings += ( $south == WALL )     ? 0b0010_0000 : 0;
                    $surroundings += ( $east == WALL )      ? 0b0001_0000 : 0;
                    $surroundings += ( $northwest == WALL ) ? 0b0000_1000 : 0;
                    $surroundings += ( $southwest == WALL ) ? 0b0000_0100 : 0;
                    $surroundings += ( $southeast == WALL ) ? 0b0000_0010 : 0;
                    $surroundings += ( $northeast == WALL ) ? 0b0000_0001 : 0;

                    $surroundings = 0b1_0000_0000 if ( $surroundings == 0 );

                    for my $ramp_type ( 0 .. $#ramps ) {
                        my $mask           = $ramps[$ramp_type]{mask};
                        my $bit_comparison = $mask & $surroundings;
                        if ( $bit_comparison == $mask ) {
                            my $func = $ramps[$ramp_type]{func};
                            croak "Need following ramp model: $func"
                              if !defined $DRAW_MODEL{$func};
                            $DRAW_MODEL{$func}
                              ->( $rx, $z, $ry, 1, $brightness_mod );
                            last;
                        }
                    }
                    next;
                }

            }
        }
        glEnd();
    }
    glEndList();

    return;
}

sub new_process_block {
    my ( $block_offset, $bx, $by, $bz ) = @_;
    my $changed = 0;

    my @type_data =
      $proc
      ->get_packs(   # extract type/designation/occupation arrays for this block
        'S', 2,      # format and size in bytes of each data unit
        $block_offset + $OFFSETS[$ver]{type_off},    # starting offset
        256
      );                                             # number of units
    my @designation_data =
      $proc->get_packs( 'L', 4, $block_offset + $OFFSETS[$ver]{designation_off},
        256 );

    my @occupation_data =
      $proc->get_packs( 'L', 4, $block_offset + $OFFSETS[$ver]{occupancy_off},
        256 );

    my ( $rx, $ry, $tile, $desig, $desig_below, $occup );

    my $bx_scaled  = $bx * 16;
    my $by_scaled  = $by * 16;
    my $tile_index = 0;

    for my $x ( 0 .. 15 ) {

        # this calculates the real x and y values
        # of this tile on the overall map_base
        $rx          = $bx_scaled + $x;
        $tile        = $tiles[$bz][type][$rx] ||= [];
        $desig       = $tiles[$bz][desig][$rx] ||= [];
        $desig_below = $tiles[ $bz - 1 ][desig][$rx] ||= [];
        $occup       = $tiles[$bz][occup][$rx] ||= [];

        # cycle through 16 x and 16 y values,
        # which generate a total of 256 tile indexes
        for my $y ( 0 .. 15 ) {

            $ry = $by_scaled + $y;

            if (
                ( $designation_data[$tile_index] & 512 ) == 512
                && ( !defined $desig_below->[$ry]
                    || ( $desig_below->[$ry] & 512 ) == 512 )
              )
            {
                ++$tile_index;
                next
                  ; # skip tile if it is hidden, but only if the tile directly below it is not loaded yet or also hidden
            }

            if ( !defined $tile->[$ry]
                || $tile->[$ry] != $type_data[$tile_index] )
            {
                $changed = 1;
                $tile->[$ry] = $type_data[$tile_index];
            }

            if ( !defined $desig->[$ry]
                || $desig->[$ry] != $designation_data[$tile_index] )
            {
                $changed = 1;
                $desig->[$ry] = $designation_data[$tile_index];
            }

            if ( !defined $occup->[$ry]
                || $occup->[$ry] != $occupation_data[$tile_index] )
            {
                $changed = 1;
                $occup->[$ry] = $occupation_data[$tile_index];
            }
            ++$tile_index;
        }
    }

    return $changed;
}

sub ask {
    print "$_[0]";
    return;
}

sub connect_to_DF {
    $ver = init_process_connection();

    refresh_datastore() unless $ver;

    return;
}

sub init_process_connection {
    ### get dwarf process id #######################################################
    my %list = Win32::Process::List->new()->GetProcesses();
    for my $key ( keys %list ) {
        $dwarf_pid = $key if ( $list{$key} =~ /dwarfort.exe/ );
    }
    croak 'Could not find process ID, make sure DF is running and'
      . ' a savegame is loaded.'
      unless ($dwarf_pid);

    ### lower priority of dwarf fortress ###########################################
    Win32::Process::Open( my $dwarf_process, $dwarf_pid, 1 );
    $dwarf_process->SetPriorityClass(IDLE_PRIORITY_CLASS);
    croak 'Could not lower DF process priority, this is really odd and'
      . ' should not happen, try running as administrator or poke Mithaldu/Xenofur.'
      unless ($dwarf_process);

    Win32::Process::Open( my $self_process, $PROCESS_ID, 1 );
    $self_process->SetPriorityClass(IDLE_PRIORITY_CLASS);
    croak 'Could not lower own process priority, this is really odd and'
      . ' should not happen, try running as administrator or poke Mithaldu/Xenofur.'
      unless ($self_process);

    ### actually read stuff from memory ############################################
    $proc = Win32::Process::Memory->new(
        { pid => $dwarf_pid, access => 'read/write/query' } )
      ;    # open process with read access
    croak 'Could not open memory access to Dwarf Fortress, this is really odd'
      . ' and should not happen, try running as'
      . ' administrator or poke Mithaldu/Xenofur.'
      unless ($proc);

    ### Let's Pla... erm, figure out what version this is ##########################

    for my $i ( 0 .. $#OFFSETS ) {
        $pe_timestamp = $proc->get_u32( $OFFSETS[$i]{pe_timestamp_offset} );
        return $i if ( $OFFSETS[$i]{PE} == $pe_timestamp );
    }
    return;
}

################################################################################

sub refresh_datastore {
    say 'Could not find DF version in local data store.'
      . " Checking for new memory address data...\n";
    import_remote_xml();

    $ver = init_process_connection();

    croak 'Version could not be correctly identified.'
      . ' Please contact Xenofur/Mithaldu or Jifodus'
      . " for updated memory addresses.\n"
      unless $ver;
    return;
}

sub import_remote_xml {
    say '  Remotely...';
    my $source = 'http://www.geocities.com/jifodus/tables/dwarvis/';
    my @xml_list;

    my $list = get($source);
    croak 'Could not download the index of the online offset stores!'
      unless defined $list;

    while ( $list =~ m/<A HREF="(.+?\.xml)">/gi ) {
        push @xml_list, $1;
    }

    say '    Found ' . ( $#xml_list + 1 ) . ' memory data files...';

    for my $file (@xml_list) {
        my $known = 0;
        for my $i ( 0 .. $#OFFSETS ) {
            $known = 1 if $file =~ m/$OFFSETS[$i]{version}/;
        }

        if ($known) {
            say "    One file ($file) discarded,"
              . ' memory data inside already known.';
            next;
        }

        my $xml = get( $source . $file );
        croak 'Could not get it!' unless defined $xml;

        my $msg_file = $file;
        $msg_file =~ s/core\.xml/messages.txt/;
        my $message = get( $source . $msg_file );

        process_xml( $xml, $message );
    }
    return;
}

sub process_xml {
    my ( $xml, $message ) = @_;
    my ( @data_store, @new_data_store );

    my %config_hash;

    if ( $xml =~ m/<version name="(.+?)" \/>/i ) {
        $config_hash{version} = $1;
    }
    else { return 0; }

    if ( $xml =~ m/<pe timestamp_offset="0x(.+?)" timestamp="0x(.+?)" \/>/i ) {
        $config_hash{pe_timestamp_offset} = hex $1;
        $config_hash{PE}                  = hex $2;
    }
    else { return 0; }

    if ( $xml =~ m/<address name="map_data" value="0x(.+?)" \/>/i ) {
        $config_hash{map_loc} = hex $1;
    }
    else { return 0; }

    if ( $xml =~ m/<address name="map_x_count" value="0x(.+?)" \/>/i ) {
        $config_hash{x_count} = hex $1;
    }
    else { return 0; }

    if ( $xml =~ m/<address name="map_y_count" value="0x(.+?)" \/>/i ) {
        $config_hash{y_count} = hex $1;
    }
    else { return 0; }

    if ( $xml =~ m/<address name="map_z_count" value="0x(.+?)" \/>/i ) {
        $config_hash{z_count} = hex $1;
    }
    else { return 0; }

    if ( $xml =~ m/<offset name="map_data_type_offset" value="0x(.+?)" \/>/i ) {
        $config_hash{type_off} = hex $1;
    }
    else { return 0; }

    if ( $xml =~
        m/<offset name="map_data_designation_offset" value="0x(.+?)" \/>/i )
    {
        $config_hash{designation_off} = hex $1;
    }
    else { return 0; }

    if ( $xml =~
        m/<offset name="map_data_occupancy_offset" value="0x(.+?)" \/>/i )
    {
        $config_hash{occupancy_off} = hex $1;
    }
    else { return 0; }

    if ( $xml =~ m/<address name="mouse_x" value="0x(.+?)" \/>/i ) {
        $config_hash{mouse_x} = hex $1;
    }
    else { return 0; }

    if ( $xml =~ m/<address name="mouse_y" value="0x(.+?)" \/>/i ) {
        $config_hash{mouse_y} = hex $1;
    }
    else { return 0; }

    if ( $xml =~ m/<address name="mouse_z" value="0x(.+?)" \/>/i ) {
        $config_hash{mouse_z} = hex $1;
    }
    else { return 0; }

    for my $i ( 0 .. $#OFFSETS ) {
        return 0 if $OFFSETS[$i]{version} eq $config_hash{version};
    }

    say "    Recognized new memory address data for DF $config_hash{version},"
      . ' inserting into data store.';
    say "--- -- -\n$message\n--- -- -" if defined $message;
    push @OFFSETS, \%config_hash;

    open my $HANDLE, '<', 'Lifevis/df_offsets.pm'
      or croak("horribly: $OS_ERROR");
    @data_store = <$HANDLE>;
    close $HANDLE or croak("horribly: $OS_ERROR");

    for my $line (@data_store) {
        if ( $line =~ m/OFFSETS\ END\ HERE/ ) {
            push @new_data_store, "        {\n";
            push @new_data_store,
              "            version => \"$config_hash{version}\",\n";
            push @new_data_store, '            PE => '
              . sprintf( '0x%08x', $config_hash{PE} ) . ",\n";
            push @new_data_store, '            map_loc => '
              . sprintf( '0x%08x', $config_hash{map_loc} ) . ",\n";
            push @new_data_store, '            x_count => '
              . sprintf( '0x%08x', $config_hash{x_count} ) . ",\n";
            push @new_data_store, '            y_count => '
              . sprintf( '0x%08x', $config_hash{y_count} ) . ",\n";
            push @new_data_store, '            z_count => '
              . sprintf( '0x%08x', $config_hash{z_count} ) . ",\n";
            push @new_data_store, '            pe_timestamp_offset => '
              . sprintf( '0x%08x', $config_hash{pe_timestamp_offset} ) . ",\n";
            push @new_data_store, '            type_off        => '
              . sprintf( '0x%08x', $config_hash{type_off} ) . ",\n";
            push @new_data_store, '            designation_off => '
              . sprintf( '0x%08x', $config_hash{designation_off} ) . ",\n";
            push @new_data_store, '            occupancy_off   => '
              . sprintf( '0x%08x', $config_hash{occupancy_off} ) . ",\n";
            push @new_data_store, '            mouse_x   => '
              . sprintf( '0x%08x', $config_hash{mouse_x} ) . ",\n";
            push @new_data_store, '            mouse_y   => '
              . sprintf( '0x%08x', $config_hash{mouse_y} ) . ",\n";
            push @new_data_store, '            mouse_z   => '
              . sprintf( '0x%08x', $config_hash{mouse_z} ) . ",\n";
            push @new_data_store, "        },\n";
        }
        push @new_data_store, $line;
    }

    open $HANDLE, '>', 'df_offsets.pl' or croak("horribly: $OS_ERROR");
    for my $line (@new_data_store) {
        print {$HANDLE} $line;
    }
    close $HANDLE or croak("horribly: $OS_ERROR");
    return;
}

################################################################################

################################################################################
## Rendering Functions #########################################################
################################################################################

# ------
# Does everything needed before losing control to the main
# OpenGL event loop.

sub initialize_opengl {
    my ( $width, $height ) = @_;

    build_textures();

    glClearColor( 0.7, 0.7, 0.7, 0.0 );    # Color to clear color buffer to.

    glClearDepth(1.0);    # Depth to clear depth buffer to; type of test.
    glDepthFunc(GL_LESS);
    glHint( GL_PERSPECTIVE_CORRECTION_HINT, GL_NICEST );
    glCullFace(GL_BACK);
    glEnable(GL_CULL_FACE);

    # Enables Smooth Color Shading; try GL_FLAT for (lack of) fun.
    glShadeModel(GL_SMOOTH);

    # Load up the correct perspective matrix; using a callback directly.
    resize_scene( $width, $height );

    glLightfv_p( GL_LIGHT1, GL_AMBIENT, @light_ambient );
    glLightfv_p( GL_LIGHT1, GL_DIFFUSE, @light_diffuse );

    #    glLightfv_p( GL_LIGHT1, GL_SPECULAR, @light_specular );

    glEnable(GL_LIGHT1);

    # A handy trick -- have surface material mirror the color.
    glColorMaterial( GL_FRONT, GL_AMBIENT_AND_DIFFUSE );

    #glMaterialfv_p( GL_FRONT_AND_BACK, GL_SPECULAR, 1, 1, 1, 1);
    #glMaterialfv_p(GL_FRONT_AND_BACK, GL_SHININESS, 127);
    glEnable(GL_COLOR_MATERIAL);
    return;
}

# ------
# Routine which draws all cubes in the map

# ------
# Barebone menu creation functions

sub create_menu {

    $submenid = glutCreateMenu( \&menu );
    glutAddMenuEntry( 'Teapot', 2 );
    glutAddMenuEntry( 'Cube',   3 );
    glutAddMenuEntry( 'Torus',  4 );

    $menid = glutCreateMenu( \&menu );
    glutAddMenuEntry( 'Clear', 1 );
    glutAddSubMenu( 'Draw', $submenid );
    glutAddMenuEntry( 'Quit', 0 );

    glutAttachMenu(GLUT_RIGHT_BUTTON);
    return;
}

sub menu {
    my ($in) = @_;

    if ( $in == 0 && defined $in ) {
        glutDestroyWindow($window_ID);
        exit 0;
    }

    glutPostRedisplay();
    return;
}

# ------
# Routine which handles background stuff when the app is idle

sub idle_tasks {
    cede();

    return;
}

# ------
# Routine which actually does the drawing

sub render_scene {

    while ( time < $next_cede_time ) {
        cede();
    }
    my $buf;    # For our strings.

    # Enables, disables or otherwise adjusts
    # as appropriate for our current settings.

    glEnable(GL_TEXTURE_2D);

    glEnable(GL_LIGHTING);

    glBlendFunc( GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA );

    glEnable(GL_DEPTH_TEST);

    # Need to manipulate the ModelView matrix to move our model around.
    glMatrixMode(GL_MODELVIEW);

    gluLookAt(
        $x_pos + $x_off,
        $y_pos + $y_off,
        $z_pos + $z_off,
        $x_pos, $y_pos, $z_pos, 0, 1, 0
    );

    # Set up a light, turn it on.
    glLightfv_p( GL_LIGHT1,
        GL_POSITION,
        (
            $light_position[0], $light_position[1],
            $light_position[2], $light_position[3]
        )
    );

    # Clear the color and depth buffers.
    glClear( GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT );

    glColor3f( 1, 1, 1 );    # Basic polygon color

    # cycle through cells in range around cursor to render
    for my $bx ( $min_x_range .. $max_x_range ) {
        for my $by ( $min_y_range .. $max_y_range ) {

            #next unless $cells[$bx][$by][cache_ptr];

            my $cache_ptr = $cells[$bx][$by][cache_ptr];

            next if !defined $cache_ptr;

            next if !defined $cache[$cache_ptr];

            my $slices = $cache[$cache_ptr];
            for my $slice ( 2 .. ( @{$slices} - 1 ) ) {
                glCallList( $slices->[$slice] ) if $slices->[$slice];
            }

            next if !defined $cells[$bx][$by][creature_list];
            my @creature_list = @{ $cells[$bx][$by][creature_list] };
            for my $entry (@creature_list) {
                last if !defined $entry;
                next unless $creatures_present{$entry};
                my $x = $creatures{$entry}[c_x];
                my $z = $creatures{$entry}[c_z];
                my $y = $creatures{$entry}[c_y];
                glTranslatef( $x, $z, $y );
                glCallList( $creature_display_lists[0] );
                glTranslatef( -$x, -$z, -$y );
            }
        }
    }

    # draw visible cursor
    glDisable(GL_LIGHTING);
    glLineWidth(2);
    glBindTexture( GL_TEXTURE_2D, $texture_ID[cursor] );
    glPolygonMode( GL_FRONT, GL_LINE );
    glBegin(GL_QUADS);
    $DRAW_MODEL{Cursor}->( $x_pos, $y_pos, $z_pos, 1, 1000 );
    glEnd();
    glPolygonMode( GL_FRONT, GL_FILL );
    glBindTexture( GL_TEXTURE_2D, $texture_ID[grass] );

=cut    glBindTexture( GL_TEXTURE_2D, $texture_ID[test] );
    glEnable(GL_POINT_SPRITE);
    glTexEnvi(GL_POINT_SPRITE, GL_COORD_REPLACE, GL_TRUE);
	glPointSize(50.0);
    glBegin(GL_POINTS);
    glVertex3f($x_pos, $y_pos, $z_pos);
=cut    glEnd();

    glLoadIdentity();    # Move back to the origin (for the text, below).

    # We need to change the projection matrix for the text rendering.
    glMatrixMode(GL_PROJECTION);

    glPushMatrix();      # But we like our current view too; so we save it here.

    glLoadIdentity();    # Now we set up a new projection for the text.

    gluOrtho2D( 0, $c{window_width}, $c{window_height}, 0 );

    glDisable(GL_TEXTURE_2D);    # Lit or textured text looks awful.
    glDisable(GL_LIGHTING);

    glDisable(GL_DEPTH_TEST);    # We don't want depth-testing either.

    # But, for fun, let's make the text partially transparent too.
    glColor4f( 0.6, 1.0, 0.6, .75 );

    $buf = sprintf 'x_rot: %d', $x_rot;
    glRasterPos2i( 2, 14 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'y_rot: %d', $y_rot;
    glRasterPos2i( 2, 26 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'z_pos: %f', $z_pos;
    glRasterPos2i( 2, 38 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'y_pos: %f', $y_pos;
    glRasterPos2i( 2, 50 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'x_pos: %f', $x_pos;
    glRasterPos2i( 2, 62 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'z_off: %f', $z_off;
    glRasterPos2i( 2, 74 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'y_off: %f', $y_off;
    glRasterPos2i( 2, 86 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'x_off: %f', $x_off;
    glRasterPos2i( 2, 98 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Mem: %f', ( ( $memory_use / $c{memory_limit} ) * 100 );
    glRasterPos2i( 2, 110 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Caches: %d', ( ( $#cache + 1 ) - ( $#cache_bucket + 1 ) );
    glRasterPos2i( 2, 122 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    if ( $tiles[$zmouse][type][$xmouse][$ymouse] ) {
        $buf = sprintf 'Type: %d', $tiles[$zmouse][type][$xmouse][$ymouse];
        glRasterPos2i( 2, 134 );
        print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );
    }

    if ( $tiles[$zmouse][desig][$xmouse][$ymouse] ) {
        $buf = sprintf 'Desigs: 0b%059b',
          $tiles[$zmouse][desig][$xmouse][$ymouse];
        glRasterPos2i( 2, $c{window_height} - 14 );
        print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );
    }

    $buf = sprintf 'Desigs: 0b%059b', 512;
    glRasterPos2i( 2, $c{window_height} - 2 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Mouse: %d %d', $xmouse, $ymouse;
    glRasterPos2i( 2, 158 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Working threads: %d', Coro::nready;
    glRasterPos2i( 2, 146 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Tasks: $current_data_proc_task / $max_data_proc_tasks";
    glRasterPos2i( 2, 172 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Creature-Tasks: $current_creat_proc_task / $max_creat_proc_tasks";
    glRasterPos2i( 2, 186 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, $buf );

    #$buf = "X";
    #glRasterPos2i(146,144); print_opengl_string(GLUT_BITMAP_HELVETICA_12,$buf);

# Now we want to render the calulated FPS at the top. To ease, simply translate up.  Note we're working in screen pixels in this projection.

    #    glTranslatef(6.0,$c{window_height} - 14,0.0);
    #
    glColor4f( 0.2, 0.2, 0.2, 0.75 )
      ; # Make sure we can read the FPS section by first placing a dark, mostly opaque backdrop rectangle.

    #
    glBegin(GL_QUADS);
    glVertex3f( $c{window_width} - 42, $c{window_height} - 20,   0.0 );
    glVertex3f( $c{window_width} - 42, $c{window_height},        0.0 );
    glVertex3f( $c{window_width} - 22, $c{window_height},        0.0 );
    glVertex3f( $c{window_width} - 22, $c{window_height} - 20.0, 0.0 );
    glEnd();

    glBegin(GL_QUADS);
    glVertex3f( $c{window_width} - 20, $c{window_height} - 20,   0.0 );
    glVertex3f( $c{window_width} - 20, $c{window_height},        0.0 );
    glVertex3f( $c{window_width},      $c{window_height},        0.0 );
    glVertex3f( $c{window_width},      $c{window_height} - 20.0, 0.0 );
    glEnd();

    glColor4f( 1, 1, 0.2, 0.75 )
      ; # Make sure we can read the FPS section by first placing a dark, mostly opaque backdrop rectangle.
    glRasterPos2i( $c{window_width} - 36, $c{window_height} - 6 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, "-" );
    glRasterPos2i( $c{window_width} - 14, $c{window_height} - 6 );
    print_opengl_string( GLUT_BITMAP_HELVETICA_12, "+" );

    #
    #    glColor4f(0.9,0.2,0.2,.75);
    #    $buf = sprintf 'FPS: %f F: %2d", $FrameRate, $FrameCount;
    #    glRasterPos2i(6,0);
    #    print_opengl_string(GLUT_BITMAP_HELVETICA_12,$buf);

    glPopMatrix();   # Done with this special projection matrix.  Throw it away.

    glutSwapBuffers();    # All done drawing.  Let's show it.

    $next_cede_time = time + $c{redraw_delay};
    cede();
    return;
}

################################################################################
## 3D Maintenance ##############################################################
################################################################################

# ------
# Callback routine executed whenever our window is resized.  Lets us
# request the newly appropriate perspective projection matrix for
# our needs.  Try removing the gluPerspective() call to see what happens.

sub resize_scene {
    my ( $width, $height ) = @_;

    $height = 1 if ( $height == 0 );    # Let's not core dump, no matter what.

    glViewport( 0, 0, $width, $height );

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    gluPerspective( 45.0, $width / $height, 0.1, 1300.0 );

    glMatrixMode(GL_MODELVIEW);

    $c{window_width}  = $width;
    $c{window_height} = $height;
    return;
}

################################################################################
## Texture Stuff ###############################################################
################################################################################

# ------
# Function to build a simple full-color texture with alpha channel,
# and then create mipmaps.  This could instead load textures from
# graphics files from disk, or render textures based on external
# input.

sub build_textures {

    print 'loading textures..';

    # Generate a texture index, then bind it for future operations.
    @texture_ID = glGenTextures_p(23);

    create_texture( 'grass',                      grass );
    create_texture( 'stone',                      stone );
    create_texture( 'cursor',                     cursor );
    create_texture( 'obsidian',                   obsidian );
    create_texture( 'unknown',                    unknown );
    create_texture( 'minstone',                   minstone );
    create_texture( 'pool',                       pool );
    create_texture( 'water',                      water );
    create_texture( 'soil',                       soil );
    create_texture( 'tree',                       tree );
    create_texture( 'shrub',                      shrub );
    create_texture( 'sapling',                    sapling );
    create_texture( 'creature',                   creature );
    create_texture( 'grassb',                     grassb );
    create_texture( 'boulder',                    boulder );
    create_texture( 'shrub_dead',                 shrub_dead );
    create_texture( 'tree_dead',                  tree_dead );
    create_texture( 'sapling_dead',               sapling_dead );
    create_texture( 'constructed_floor_detailed', constructed_floor_detailed );
    create_texture( 'constructed_wall',           constructed_wall );
    create_texture( 'grass_dry',                  grass_dry );
    create_texture( 'lava',                       lava );
    create_texture( 'curses3_960x300',            test );

#glBindTexture(GL_TEXTURE_2D, $texture_ID[grass]);       # select mipmapped texture
#glTexParameterf(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,GL_REPEAT);    # Some pretty standard settings for wrapping and filtering.
#glTexParameterf(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,GL_REPEAT);

    say "   textures loaded.\n";
    return;
}

sub create_texture {
    my ( $name, $id ) = @_;
    glBindTexture( GL_TEXTURE_2D, $texture_ID[$id] );
    my $tex =
      new OpenGL::Image( engine => 'Magick', source => "textures/$name.png" );
    my ( $ifmt, $fmt, $type ) =
      $tex->Get( 'gl_internalformat', 'gl_format', 'gl_type' );
    my ( $w, $h ) = $tex->Get( 'width', 'height' );
    glTexParameteri( GL_TEXTURE_2D, GL_GENERATE_MIPMAP, GL_TRUE );
    glTexParameterf( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    glTexParameterf( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER,
        GL_LINEAR_MIPMAP_NEAREST );
    glTexImage2D_c( GL_TEXTURE_2D, 0, $ifmt, $w, $h, 0, $fmt, $type,
        $tex->Ptr() );
    return;
}

################################################################################
## Input Stuff #################################################################
################################################################################

# Callback function called when a normal $key is pressed. ######################

sub process_key_press {
    my $key = shift;

    my $scan = VkKeyScan($key);
    $scan &= 0xff;

    if ( $scan == VK_F ) {
        $proc->set_u32( $OFFSETS[$ver]{mouse_z}, $zmouse + 1 )
          ;    # BE CAREFUL, MAY DAMAGE YOUR SYSTEM
        print "moo";
    }

    PostMessage( $DF_window, WM_KEYDOWN, $scan, 0 );

    glutPostRedisplay();
    return;
}

# Callback Function called when a special $key is pressed. #####################

sub process_special_key_press {
    my $key = shift;

    if ( $key >= GLUT_KEY_F1 && $key <= GLUT_KEY_F12 ) {
        PostMessage( $DF_window, WM_KEYDOWN, $key + 111, 0 );
    }
    elsif ( $key >= GLUT_KEY_LEFT && $key <= GLUT_KEY_DOWN ) {
        PostMessage( $DF_window, WM_KEYDOWN, $key - 63, 0 );
    }
    elsif ( $key >= GLUT_KEY_PAGE_UP && $key <= GLUT_KEY_PAGE_DOWN ) {
        PostMessage( $DF_window, WM_KEYDOWN, $key - 71, 0 );
    }
    elsif ( $key == GLUT_KEY_HOME ) {
        PostMessage( $DF_window, WM_KEYDOWN, VK_HOME, 0 );
    }
    elsif ( $key == GLUT_KEY_END ) {
        PostMessage( $DF_window, WM_KEYDOWN, VK_END, 0 );
    }
    elsif ( $key == GLUT_KEY_INSERT ) {
        PostMessage( $DF_window, WM_KEYDOWN, VK_INSERT, 0 );
    }
    else {
        printf "SKP: No action for %d.\n", $key;
    }

    glutPostRedisplay();
    return;
}

sub process_mouse_click {
    my ( $button, $state, $x, $y ) = @_;
    if ( $button == GLUT_MIDDLE_BUTTON && $state == GLUT_DOWN ) {
        $middle_mouse = 1;
        $last_mouse_x = $x;
        $last_mouse_y = $y;
    }

    if ( $button == GLUT_LEFT_BUTTON && $state == GLUT_DOWN ) {
        $last_mouse_x = $x;
        $last_mouse_y = $y;

        if (   $x > $c{window_width} - 42
            && $x < $c{window_width} - 22
            && $y > $c{window_height} - 20
            && $y < $c{window_height} )
        {
            --$c{view_range} if $c{view_range} > 0;
            glutPostRedisplay();
        }

        if (   $x > $c{window_width} - 20
            && $x < $c{window_width}
            && $y > $c{window_height} - 20
            && $y < $c{window_height} )
        {
            my $size = ( $xcount > $ycount ) ? $xcount : $ycount;
            ++$c{view_range} if ( $c{view_range} < $size / 2 );
            glutPostRedisplay();
        }
    }

    $middle_mouse = 0 if $button == GLUT_MIDDLE_BUTTON && $state == GLUT_UP;
    return;
}

sub process_active_mouse_motion {
    my ( $x, $y ) = @_;

    if (   $x > $c{window_width} - 42
        && $x < $c{window_width} - 22
        && $y > $c{window_height} - 20
        && $y < $c{window_height} )
    {
        return;
    }

    if (   $x > $c{window_width} - 20
        && $x < $c{window_width}
        && $y > $c{window_height} - 20
        && $y < $c{window_height} )
    {
        return;
    }

    my ( $new_x, $new_y ) = ( 0, 0 );
    $new_x = $x - $last_mouse_x if ($last_mouse_x);
    $new_y = $y - $last_mouse_y if ($last_mouse_y);

    if ( $middle_mouse == 0 ) {

        $y_rot -= ( 180 * $new_x / 300 ) * -1 * $c{sensitivity};
        $y_rot -= 360 if ( $y_rot > 360 );
        $y_rot += 360 if ( $y_rot < 0 );

        my $diff = ( 180 * $new_y / 300 ) * -0.75 * $c{sensitivity};
        $x_rot += $diff
          if ( ( $x_rot + $diff ) > -89 and ( $x_rot + $diff ) < 89 );
    }
    else {

        $mouse_dist += $new_y * 0.2;
        $mouse_dist = 1 if $mouse_dist < 1;

    }

    $last_mouse_x = $x;
    $last_mouse_y = $y;
    reposition_camera();

    glutPostRedisplay();
    return;
}

sub reposition_camera {
    my $radial_x_rotation = $x_rot * PIOVER180;
    my $radial_y_rotation = $y_rot * PIOVER180;
    my $cos_y             = $cos_cache{$y_rot} ||= cos $radial_y_rotation;
    my $sin_y             = $sin_cache{$y_rot} ||= sin $radial_y_rotation;
    my $sin_x             = $sin_cache{$x_rot} ||= sin $radial_x_rotation;
    my $cos_x             = $cos_cache{$x_rot} ||= cos $radial_x_rotation;

    $x_off = ( $sin_y * $cos_x ) * $mouse_dist;
    $y_off = ( -$sin_x ) * $mouse_dist;
    $z_off = ( -$cos_y * $cos_x ) * $mouse_dist;
    return;
}

################################################################################
## Map Stuff ###################################################################
################################################################################

################################################################################
## Helper Stuff ################################################################
################################################################################

# ------
# String rendering routine; leverages on GLUT routine.

sub print_opengl_string {
    my ( $font, $str ) = @_;
    my @c = split //, $str;

    for (@c) {
        glutBitmapCharacter( $font, ord $_ );
    }
    return;
}

__END__