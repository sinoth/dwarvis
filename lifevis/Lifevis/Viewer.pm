# $Id$
# $Revision$
# $HeadURL$
# $Date$
# $Source$

# Lifevis
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

package Lifevis::Viewer;

use 5.010;
use strict;
use warnings;

our ($VERSION) = '$Revision$' =~ m{ \$Revision: \s+ (\S+) }x;    # define minor version
$VERSION = 0 + $VERSION / 1000;                                        # define major version

#use warnings::unused;
#use diagnostics;

=cut
use criticism (
    -exclude => [
        'ProhibitCallsToUndeclaredSubs',
        'ProhibitConstantPragma',
        'RequireExtendedFormatting',
        'ProhibitComplexRegexes',
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

=cut

use Carp;
use utf8;
use English qw(-no_match_vars);
$OUTPUT_AUTOFLUSH = 1;

my $detached;

use threads;
use threads::shared;

use Config::Simple;
use LWP::Simple;
use Win32;

use Benchmark qw/:hireswallclock timesum timestr timediff/;

use Time::HiRes qw ( time sleep );
use Coro qw[ cede schedule ];

use OpenGL::Image;
use Math::Trig;
use Win32;
use Win32::Process::List;
use Win32::Process;
use Win32::Process::Memory;
use Image::Magick;
use Win32::GUI::Constants qw ( :window :accelerator );
use Win32::GuiTest qw( :FUNC );
use Math::Vec qw(:terse);

=cut
use Devel::AutoProfiler 
                ( 
                -pkg_exception => [ 'OpenGL', 'constants', 'df_internals' ],
                -sub_exception => [ 'GL_', '[a-z]st$', 'GLUT_' ],
                );
=cut

use lib '.';
use lib '..';
use Lifevis::constants;
use Lifevis::df_internals;
use Lifevis::ProcessConnection;
use Lifevis::Vtables;

my $memory_use;
$memory_use = 0;

my %building_visuals = get_df_building_visuals();
my @TILE_TYPES       = get_df_tile_type_data();
my %DRAW_MODEL;
my %model_display_lists;
my @ramps   = get_ramp_bitmasks();
my %vtables = get_vtables();

my $config_loaded;
my %c;
tie %c, 'Config::Simple', 'lifevis.cfg';
$c{redraw_delay} = 0.5 / $c{fps_limit};

my $memory_limit;
$memory_limit  = $c{memory_limit};
$config_loaded = 1;
my $time_slice = $c{time_slice};

my ( $xcount, $ycount, $zcount );    # dimensions of the map data we're dealing with, counts in cells
my ( $x_max, $y_max );               # dimensions of the map data we're dealing with, counts in tiles

my @cells;
my @cell_strings;

my %creatures_present;
my $current_creat_proc_task = 0;
my $max_creat_proc_tasks    = 0;
my %creatures;

my %building_present;
my %buildings;
my $current_buil_proc_task = 0;
my $max_buil_proc_tasks    = 0;

my @item_present;
my $current_item_proc_task = 0;
my $max_item_proc_tasks    = 0;
my %items;
my $gap = 65535;
my %bucket_strings;

my ( $mouse_cursor_x, $mouse_cursor_y );

# cursor coordinates at last refresh, in tiles
my ( $xmouse_old, $ymouse_old, $zmouse_old ) = ( 0, 0, 15 );

# current cursor coordinates, in tiles
my ( $xmouse, $ymouse, $zmouse ) = ( 0, 0, 15 );

# Camera position and rotation variables.
my ( $x_pos, $y_pos, $z_pos, $x_off, $y_off, $z_off, $x_rot, $y_rot );

my $min_x_range = 0;
my $max_x_range = 0;
my $min_y_range = 3;
my $max_y_range = 3;

my $current_data_proc_task = 0;
my $max_data_proc_tasks    = 0;
my @cache;
my @cache_bucket;

my @texture_ID;
my @tiles;

# Settings for our light.  Try playing with these (or add more lights).
my @light_ambient = ( 0.7, 0.7, 0.7, 1.0 );
my @light_diffuse = ( 0.9, 0.9, 0.9, 1.0 );

#my @light_specular  = ( 0.9,  0, 0, 1.0 );
my @light_position = ( -0.8, 1.5, 1.0, 0.0 );

my ( $submenid, $menid );
my $window_ID;
my $DF_window;
my $next_render_time = 0;

my $middle_mouse = 0;
my $last_mouse_x;
my $last_mouse_y;
my $mouse_dist = 100;
my $cam_angle  = 45;

my $rotating = 0;
my $changing_ceiling;
my $ceiling_slice;
my $ceiling_locked = 0;
my $view_range_changed;

my $memory_needs_clears = 0;
my $memory_full_checks  = 0;
my $memory_clears       = 0;
my $memory_loop;
my $all_protected;

my $render_loop;
my $redraw_needed;

my $next_creature_time  = 0;
my $next_landscape_time = 0;
my $next_building_time  = 0;
my $next_item_time      = 0;
my $next_cursor_time    = 0;

my $creature_delay_counter;
my $creature_loop;

my $location_delay_counter;
my $loc_loop;

my $landscape_delay_counter;
my $land_loop;

my $building_delay_counter;
my $buil_loop;

my $item_delay_counter;
my $item_loop;
my $force_rt = 0;
my $pixels   = '';

my %time = ( landscape => 0, creature => 0, building => 0, item => 0, cursor => 0 );

my @offsets;
my $df_proc_handle;
my $proc;

my $occlusion_supported = 1;

__PACKAGE__->run(@ARGV) unless caller();

BEGIN {
    share(%c);
    share($config_loaded);
    share($memory_use);
    share($memory_needs_clears);
    share($memory_limit);
    share($all_protected);
    my $thr = threads->create( { 'stack_size' => 64 }, \&update_memory_use );
    $thr->detach();

    sub update_memory_use {
        require Win32::OLE;
        import Win32::OLE qw(in);
        my @state_array;
        my $pid              = $PROCESS_ID;
        my $sleep_time       = 2;
        my $small_sleep_time = 0.1;

        sleep $small_sleep_time while ( !$config_loaded );

        while (1) {
            @state_array = in(
                Win32::OLE->GetObject("winmgmts:\\\\.\\root\\CIMV2")->ExecQuery(
                    'SELECT PrivatePageCount FROM Win32_Process' . " WHERE ProcessId = $pid",
                    'WQL', 0x10 | 0x20
                )
            );
            $memory_use = $state_array[0]->{PrivatePageCount};

            if ( $memory_use > $memory_limit && !$all_protected ) {
                $memory_needs_clears = 1;
                sleep $small_sleep_time;
            }
            else {
                $all_protected = 0;
                sleep $sleep_time;
            }
        }
        Win32::OLE->Uninitialize();
        return 1;
    }
}

sub check_for_new_version {
    my $source = 'http://code.google.com/p/dwarvis/wiki/LifevisVersionInfo';

    my $new_version = get($source);
    return if !defined $new_version;

    if ( $new_version =~ m/-----(\d+?.\d+?)-----/ ) {
        $new_version = $1;
    }
    else {
        notify_user(
            "Could not identify version info during online check. Please check internet connection or contact Mithaldu."
        );
    }

    notify_user(
        "New version $new_version available, please check the download section on [ http://dwarvis.googlecode.com ].")
      if ( $new_version + 0 ) > $VERSION;

    return;
}

sub run {
    check_for_new_version() if $c{update_checks};

    use OpenGL qw/ :all /;
    

    
    use Lifevis::models;
    %DRAW_MODEL = get_model_subs();

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

    # TODO: Split these and ramp-tops into seperate models. Fix texturing on ramp models where i fucked up diagonals.

    # ------
    # The main() function.  Inits OpenGL.  Calls our own init function,
    # then passes control onto OpenGL.

    Lifevis::ProcessConnection::initialize( $VERSION, $detached );
    my $offsets_ref;
    ( $proc, $df_proc_handle, $offsets_ref ) = connect_to_DF();
    @offsets = @{$offsets_ref};

    extract_base_memory_data();

    glutInit();

    print 'setting up OpenGL environment...   ';
    glutInitDisplayMode( GLUT_RGBA | GLUT_DOUBLE | GLUT_DEPTH );
    glutInitWindowSize( $c{window_width}, $c{window_height} );

    # clamp viewer window to bottom of df window, right side
    ($DF_window) = FindWindowLike( 0, '^Dwarf Fortress$' );
    my ( undef, undef, $right, $bottom ) = GetWindowRect($DF_window);
    ( $right, $bottom ) = ClientToScreen( $DF_window, $right, $bottom );

    # reset to 0,0 if outside of screen
    my ( $screen_width, $screen_height ) = GetScreenRes();
    ( $right, $bottom ) = ( $c{window_width}, 0 )
      if ( $right > $screen_width
        or $bottom + $c{window_height} > $screen_height );
    glutInitWindowPosition( $right - $c{window_width}, $bottom );

    $window_ID = glutCreateWindow( PROGRAM_TITLE . " v$VERSION" );    # Open a window
    glutSetOption( GLUT_ACTION_ON_WINDOW_CLOSE, GLUT_ACTION_CONTINUE_EXECUTION );
    glutIgnoreKeyRepeat(1);

    create_menu();

    # Set up Callback functions ####################################################

    # Register the callback function to do the drawing.
    glutDisplayFunc( sub { $redraw_needed = 1; } );

    glutIdleFunc( \&idle_tasks );                                     # If there's nothing to do, draw.

    # It's a good idea to know when our window's resized.
    glutReshapeFunc( \&resize_scene );

    glutKeyboardFunc( \&process_key_press );                          # And let's get some keyboard input.
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

    $loc_loop = new Coro \&location_update_loop;
    $loc_loop->ready;
    cede();

    generate_model_display_lists();
    $land_loop = new Coro \&landscape_update_loop;
    $land_loop->ready;

    $creature_loop = new Coro \&creature_update_loop;

    $buil_loop = new Coro \&building_update_loop;

    $item_loop = new Coro \&item_update_loop;

    $memory_loop = new Coro \&memory_control_loop;

    $render_loop = new Coro \&render_scene;
    $render_loop->prio(1);

    # Pass off control to OpenGL.
    # Above functions are called as appropriate.
    print "switching to main loop...\n";
    $ceiling_slice = $zcount;

    glutMainLoop();

    return;
}

################################################################################
## Rendering Functions #########################################################
################################################################################

sub extract_base_memory_data {
    my $buf = '';
    my $map_base;# offset of the address where the map blocks start
    $xcount = $proc->get_u32( $offsets[x_count] );    # map size in cells
    $ycount = $proc->get_u32( $offsets[y_count] );
    $zcount = $proc->get_u32( $offsets[z_count] );
    set_zcount_for_models($zcount);

    $x_max = ( $xcount * 16 ) - 1;
    $y_max = ( $ycount * 16 ) - 1;

    # checking whether the game has a map already
    $map_base = $proc->get_u32( $offsets[map_loc] );
    croak 'Map data is not yet available, make sure you have a game loaded.'
      unless ($map_base);

    # get the offsets of the address storages for each x-slice and cycle through
    _ReadMemory( $df_proc_handle, $map_base, $xcount * 4, $buf );
    my @xoffsets = unpack( 'L' x $xcount, $buf );
    for my $bx ( 0 .. $xcount - 1 ) {

        # get the offsets of the address storages
        # for each y-column in this x-slice and cycle through
        _ReadMemory( $df_proc_handle, $xoffsets[$bx], $ycount * 4, $buf );
        my @yoffsets = unpack( 'L' x $ycount, $buf );
        for my $by ( 0 .. $ycount - 1 ) {
            $cells[$bx][$by][offset] = $yoffsets[$by];
        }
    }

    return;
}

sub creature_update_loop {
    my $entry_time;
    my $full_crea_run;
    while (1) {
        $next_creature_time = time + $c{creature_update_delay} - $time{creature};
        schedule();
        $entry_time = time;
        my $buf = "";

        my $t0 = time;

        _ReadMemory( $df_proc_handle, $offsets[creature_vector] + 4, 4 * 2, $buf );
        my @creature_vector_offsets = unpack( 'L' x 2, $buf );

        my $creature_list_length = ( $creature_vector_offsets[1] - $creature_vector_offsets[0] ) / 4;

        _ReadMemory( $df_proc_handle, $creature_vector_offsets[0], 4 * $creature_list_length, $buf );
        my @creature_offsets = unpack( 'L' x $creature_list_length, $buf );

        for my $creature ( values %creatures_present ) {
            $creature = 0;
        }

        for my $creature (@creature_offsets) {
            $creatures_present{$creature} = 1;
        }

        $current_creat_proc_task = 0;
        $max_creat_proc_tasks    = $#creature_offsets;

        for my $creature (@creature_offsets) {

            #say $creature unless $full_crea_run;
            my $buf = "";

            $current_creat_proc_task++;

            if ( ( time - $entry_time ) > $time_slice ) {
                cede();
                $entry_time = time;
            }

            #say $proc->hexdump( $creature, 0x688 );

            _ReadMemory( $df_proc_handle, $creature, 232, $buf );

            next if ( defined $creatures{$creature}[string] and $creatures{$creature}[string] eq $buf );
            $creatures{$creature}[string] = $buf;

            my $flags = unpack( "L", substr( $buf, 228, 4 ) );
            $creatures{$creature}[flags] = $flags;
            next if $flags & 2;

            # extract coordinates of current creature and skip if out of bounds
            my $rx = unpack( "S", substr( $buf, 148, 2 ) );
            next if ( $rx > $xcount * 16 );
            my $rz = unpack( "S", substr( $buf, 152, 2 ) );
            next if ( $rz > $zcount + 1 );
            my $ry = unpack( "S", substr( $buf, 150, 2 ) );

            # get name and race, but only if we don't have them yet, since they're unlikely to change
            if ( !defined $creatures{$creature}[name] ) {
                my $name_length = unpack( "L", substr( $buf, 120, 4 ) );
                $creatures{$creature}[name] = substr( $buf, 4, $name_length );
            }
            if ( !defined $creatures{$creature}[race] ) {
                my $race = unpack( "L", substr( $buf, 140, 4 ) );
                $creatures{$creature}[race] = $race;
            }

            # update record of current creature
            $creatures{$creature}[c_x] = $rx;
            $creatures{$creature}[c_y] = $ry;

            # get old and new cell location and compare
            my $old_x = $creatures{$creature}[cell_x];
            my $old_y = $creatures{$creature}[cell_y];
            my $old_z = $creatures{$creature}[c_z];
            my $bx    = int $rx / 16;
            my $by    = int $ry / 16;
            if ( !defined $old_x or $bx != $old_x or $by != $old_y or $rz != $old_z ) {

                # creature moved to other cell or is new
                # get creature list of old cell then cycle through it and remove the old entry
                if ( defined $old_x ) {
                    $redraw_needed = 1;
                    my $creature_list = $cells[$old_x][$old_y][creature_list][$old_z];
                    for my $entry ( @{$creature_list} ) {
                        if ( $entry == $creature ) {
                            $entry = $creature_list->[$#$creature_list];
                            pop @{$creature_list};
                            last;
                        }
                    }
                }

                # add entry to new cell and update cell coordinates
                push @{ $cells[$bx][$by][creature_list][$rz] }, $creature;
                $creatures{$creature}[cell_x] = $bx;
                $creatures{$creature}[cell_y] = $by;
                $creatures{$creature}[c_z]    = $rz;
            }
        }

        my $t1 = time;
        $time{creature} = sprintf( "%.3f", $t1 - $t0 );
        $redraw_needed  = 1;
        $full_crea_run  = 1;
    }
}

sub building_update_loop {
    my $entry_time;
    my $full_buil_run;
    while (1) {
        $next_building_time = time + $c{building_update_delay} - $time{building};
        schedule();
        $entry_time = time;
        my $buf = "";

        my $t0 = time;

        _ReadMemory( $df_proc_handle, $offsets[building_vector] + 4, 4 * 2, $buf );
        my @building_vector_offsets = unpack( 'L' x 2, $buf );

        my $building_list_length = ( $building_vector_offsets[1] - $building_vector_offsets[0] ) / 4;

        _ReadMemory( $df_proc_handle, $building_vector_offsets[0], 4 * $building_list_length, $buf );
        my @building_offsets = unpack( 'L' x $building_list_length, $buf );

        for my $building ( values %building_present ) {
            $building = 0;
        }

        for my $building (@building_offsets) {
            $building_present{$building} = 1;
        }

        $current_buil_proc_task = 0;
        $max_buil_proc_tasks    = $#building_offsets;

        for my $building (@building_offsets) {

            #say $building unless $full_buil_run;
            my $buf = "";

            $current_buil_proc_task++;
            if ( ( time - $entry_time ) > $time_slice ) {
                cede();
                $entry_time = time;
            }

            #say $proc->hexdump( $building, 0xD8 );
            _ReadMemory( $df_proc_handle, $building, 30, $buf );

            next if ( defined $buildings{$building}[string] and $buildings{$building}[string] eq $buf );
            $buildings{$building}[string] = $buf;

            # extract coordinates of current creature and skip if out of bounds
            my $rx = unpack( "S", substr( $buf, 4, 2 ) );
            next if ( $rx > $xcount * 16 );
            my $rz = unpack( "S", substr( $buf, 28, 2 ) );
            next if ( $rz > $zcount + 1 );
            my $ry     = unpack( "S", substr( $buf, 8, 2 ) );
            my $vtable = unpack( "L", substr( $buf, 0, 4 ) );

            # update record of current creature
            $buildings{$building}[b_x]            = $rx;
            $buildings{$building}[b_y]            = $ry;
            $buildings{$building}[b_vtable_const] = $vtable;
            $buildings{$building}[b_vtable_id]    = $vtables{$vtable};
            warn sprintf "UNKNOWN BUILDING VTABLE: %x\n", $vtable unless $vtables{$vtable};

            # get old and new cell location and compare
            my $old_x = $buildings{$building}[b_cell_x];
            my $old_y = $buildings{$building}[b_cell_y];
            my $old_z = $buildings{$building}[b_z];
            my $bx    = int $rx / 16;
            my $by    = int $ry / 16;
            if ( !defined $old_x || $bx != $old_x || $by != $old_y or $rz != $old_z ) {

                # creature moved to other cell or is new
                # get creature list of old cell then cycle through it and remove the old entry
                if ( defined $old_x ) {
                    $redraw_needed = 1;
                    my $building_list = $cells[$old_x][$old_y][building_list][$old_z];
                    for my $entry ( @{$building_list} ) {
                        if ( $entry == $building ) {
                            $entry = $building_list->[$#$building_list];
                            pop @{$building_list};
                            last;
                        }
                    }
                }

                # add entry to new cell and update cell coordinates
                push @{ $cells[$bx][$by][building_list][$rz] }, $building;
                $buildings{$building}[b_cell_x] = $bx;
                $buildings{$building}[b_cell_y] = $by;
                $buildings{$building}[b_z]      = $rz;
            }
        }

        my $t1 = time;
        $time{building} = sprintf( "%.3f", $t1 - $t0 );
        $redraw_needed  = 1;
        $full_buil_run  = 1;
    }
}

sub item_update_loop {
    my $full_loop_completed;
    my $largest_id = 0;
    my $entry_time;
    while (1) {
        $next_item_time = time + $c{item_update_delay} - $time{item};
        schedule();
        $entry_time = time;
        my $buf = "";

        my $t0 = time;

        _ReadMemory( $df_proc_handle, $offsets[item_vector] + 4, 4 * 2, $buf );
        my @item_vector_offsets = unpack( 'L' x 2, $buf );

        my $item_list_length = ( $item_vector_offsets[1] - $item_vector_offsets[0] ) / 4;

        _ReadMemory( $df_proc_handle, $item_vector_offsets[0], 4 * $item_list_length, $buf );
        my @item_offsets = unpack( 'L' x $item_list_length, $buf );

        $current_item_proc_task = 0;
        $max_item_proc_tasks    = $#item_offsets;

        my @sort = sort { $a <=> $b } @item_offsets;
        my @buckets;
        my $start = shift @sort;
        push @buckets, [ $start, $start ];
        push @{ $buckets[$#buckets][2] }, $start;
        for my $item (@sort) {
            if ( $item < $buckets[$#buckets][1] + $gap ) {
                $buckets[$#buckets][1] = $item;
                push @{ $buckets[$#buckets][2] }, $item;
            }
            else {
                push @buckets, [ $item, $item ];
                push @{ $buckets[$#buckets][2] }, $item;
            }
        }

        for my $bucket (@buckets) {
            if ( ( time - $entry_time ) > $time_slice ) {
                cede();
                $entry_time = time;
            }

            my $string = "";
            _ReadMemory( $df_proc_handle, $bucket->[0], $bucket->[1] - $bucket->[0] + 24, $string );

            next if ( $string eq "" );

            # cycle through items in bucket
            for my $item_address ( @{ $bucket->[2] } ) {

                $current_item_proc_task++;
                if ( ( time - $entry_time ) > $time_slice ) {
                    cede();
                    $entry_time = time;
                }

                my $new_offset = $item_address - $bucket->[0];
                my $buf = substr( $string, $new_offset, 24 );

                # extract DF item id
                my $id = unpack( "L", substr( $buf, 20, 4 ) );

                if ( $id > $largest_id ) {
                    #say $largest_id;
                    $largest_id = $id;
                }

                next if ( defined $items{$id}[string] and $items{$id}[string] eq $buf );
                $items{$id}[string] = $buf;

                # extract state of current item and skip applicable items
                my $state = unpack( "L", substr( $buf, 12, 4 ) );
                if (
                    !( $state & 0x1 )    # is not lying on the ground
                    || ( $state & 0x1000000 )    # is hidden
                  )
                {
                    $items{$id}[invisible] = 1;
                    next;
                }

                # extract coordinates of current creature and skip if out of bounds
                my $rx = unpack( "S", substr( $buf, 4, 2 ) );
                if ( $rx > $xcount * 16 ) {
                    $items{$id}[invisible] = 1;
                    next;
                }
                my $rz = unpack( "S", substr( $buf, 8, 2 ) );
                next if ( $rz > $zcount + 1 );
                my $ry   = unpack( "S", substr( $buf, 6, 2 ) );
                my $type = unpack( "L", substr( $buf, 0, 4 ) );
                my $vtable = $type;

                #say $proc->hexdump( $item, 0x88 ),"\n ";

                # update record of current creature
                $items{$id}[i_x]            = $rx;
                $items{$id}[i_y]            = $ry;
                $items{$id}[i_type]         = $type;
                $items{$id}[i_state]        = $state;
                $items{$id}[i_address]      = $item_address;
                $items{$id}[i_vtable_const] = $vtable;
                $items{$id}[i_vtable_id]    = $vtables{$vtable};
                warn sprintf "UNKNOWN ITEM VTABLE: %x\n", $vtable unless $items{$id}[i_vtable_id];

#say "X: $rx Y: $ry Z: $rz ST: $state T: $type" if ( !$full_loop_completed && $state & (1 << 0) && ( 0 || $state & (1 << 2) ));

                # get old and new cell location and compare
                my $old_x = $items{$id}[i_cell_x];
                my $old_y = $items{$id}[i_cell_y];
                my $old_z = $items{$id}[i_z];
                my $bx    = int $rx / 16;
                my $by    = int $ry / 16;

                # if creature moved to other cell or is newly added
                if ( !defined $old_x || $bx != $old_x || $by != $old_y || $rz != $old_z ) {

                    # if creature moved: get creature list of old cell then cycle through it and remove the old entry
                    if ( defined $old_x ) {
                        $redraw_needed = 1;
                        my $item_list = $cells[$old_x][$old_y][item_list][$old_z];

                        for my $entry ( 0 .. @{$item_list} - 1 ) {
                            if ( $item_list->[$entry] == $id ) {
                                splice @{$item_list}, $entry, 1;
                                last;
                            }
                        }
                    }

                    # add entry to new cell and update cell coordinates
                    push @{ $cells[$bx][$by][item_list][$rz] }, $id;
                    $items{$id}[i_cell_x] = $bx;
                    $items{$id}[i_cell_y] = $by;
                    $items{$id}[i_z]      = $rz;
                }
            }
        }

        $full_loop_completed = 1;

        my $t1 = time;
        $time{item} = sprintf( "%.3f", $t1 - $t0 );
        $redraw_needed = 1;
    }
}

sub location_update_loop {
    my $entry_time;
    while (1) {
        $next_cursor_time = time + $c{cursor_update_delay} - $time{cursor};
        schedule();
        $entry_time = time;

        my $t0 = time;

        my $old_ceiling_slice = $ceiling_slice;
        my $buf               = "";

        $xmouse_old = $xmouse;
        $ymouse_old = $ymouse;
        $zmouse_old = $zmouse;

        # get mouse data
        _ReadMemory( $df_proc_handle, $offsets[mouse_x], 4, $buf );
        $xmouse = unpack( "L", $buf );
        _ReadMemory( $df_proc_handle, $offsets[mouse_y], 4, $buf );
        $ymouse = unpack( "L", $buf );
        _ReadMemory( $df_proc_handle, $offsets[mouse_z], 4, $buf );
        $zmouse = unpack( "L", $buf );

        #say $proc->get_u32( $OFFSETS[$ver]{menu_state} );
        #say $proc->get_u32( $OFFSETS[$ver]{view_state} );

        # use viewport coords if out of bounds, i.e. cursor not in use
        if (   $xmouse > $xcount * 16
            || $ymouse > $ycount * 16
            || $zmouse > $zcount )
        {
            _ReadMemory( $df_proc_handle, $offsets[viewport_x], 4, $buf );
            my $viewport_x = unpack( "L", $buf );
            _ReadMemory( $df_proc_handle, $offsets[window_grid_x], 4, $buf );
            my $window_grid_x = unpack( "L", $buf );
            _ReadMemory( $df_proc_handle, $offsets[viewport_y], 4, $buf );
            my $viewport_y = unpack( "L", $buf );
            _ReadMemory( $df_proc_handle, $offsets[window_grid_y], 4, $buf );
            my $window_grid_y = unpack( "L", $buf );
            _ReadMemory( $df_proc_handle, $offsets[viewport_z], 4, $buf );
            my $viewport_z = unpack( "L", $buf );

            $xmouse = $viewport_x + int( $window_grid_x / 6 );
            $ymouse = $viewport_y + int( $window_grid_y / 3 );
            $zmouse = $viewport_z;
        }

        $ceiling_slice = $zmouse if $ceiling_locked;

        if (   $xmouse != $xmouse_old
            || $ymouse != $ymouse_old
            || $zmouse != $zmouse_old
            || $ceiling_slice != $old_ceiling_slice
            || $view_range_changed )
        {
            $view_range_changed = 0;
            $redraw_needed      = 1;

            # update camera system with mouse data
            ( $x_pos, $z_pos, $y_pos ) = ( $xmouse, $ymouse, $zmouse );
            reposition_camera();    # sets up initial camera position offsets

            # calculate cell coords from mouse coords
            my $xcell = int $xmouse / 16;
            my $ycell = int $ymouse / 16;
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
        }

        my $t1 = time;
        $time{cursor} = sprintf( "%.3f", $t1 - $t0 );
    }
}

sub landscape_update_loop {
    my $full_land_run;
    my $entry_time;
    while (1) {
        $next_landscape_time = time + $c{landscape_update_delay} - $time{landscape};
        schedule();
        $entry_time = time;
        my $buf = "";
        my $t0  = time;

        #TODO: When at the edge, only grab at inner edge.
        # cycle through cells in range around cursor to grab data
        for my $bx ( $min_x_range - 1 .. $max_x_range + 1 ) {
            next if ( $bx < 0 || $bx > $xcount - 1 );    # skip if block is outside the map
            next
              if ( $bx < $min_x_range - 1 || $bx > $max_x_range + 1 ); # skip if block is outside the current view range
            for my $by ( $min_y_range - 1 .. $max_y_range + 1 ) {
                next if ( $by < 0 || $by > $ycount - 1 );              # skip if block is outside the map
                next
                  if ( $by < $min_y_range - 1 || $by > $max_y_range + 1 )
                  ;                                                    # skip if block is outside the current view range

                # cycle through slices in cell
                _ReadMemory( $df_proc_handle, $cells[$bx][$by][offset], 4 * $zcount, $buf );
                my @zoffsets = unpack( 'L' x $zcount, $buf );
                $cells[$bx][$by][changed] = 0
                  if !defined $cells[$bx][$by][changed];
                for my $bz ( 0 .. $#zoffsets ) {

                    # go to the next block if this one is not allocated
                    next if ( $zoffsets[$bz] == 0 );

                    #say $zoffsets[$bz] unless $full_land_run;

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

                    if ( ( time - $entry_time ) > $time_slice ) {
                        cede();
                        $entry_time = time;
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
                                generate_display_list( $cache_id, $slice, $by, $bx );
                                @{$slices}[$slice] = 0;
                            }
                            $redraw_needed = 1;
                            if ( ( time - $entry_time ) > $time_slice ) {
                                cede();
                                $entry_time = time;
                            }
                            $current_data_proc_task++;
                        }
                        $cells[$bx][$by][changed] = 0;
                    }

                    $cache[$cache_id][use_counter]++;

                }
                else {

                    my $slices = $cells[$bx][$by][z];

                    next if !defined $slices;

                    # cell is not in cache

                    # get fresh cache id either from end of cache or out of bucket
                    $cache_id = $#cache + 1;
                    $cache_id = pop @cache_bucket if ( $#cache_bucket > -1 );

                    # set up link to cell and back-link to cache id
                    $cache[$cache_id][cell_ptr]    = \$cells[$bx][$by][cache_ptr];
                    $cells[$bx][$by][cache_ptr]    = $cache_id;
                    $cache[$cache_id][use_counter] = 0;

                    # cycle through slices and
                    # create displaylists as necessary,
                    # storing the ids in the cache entry
                    for my $slice ( 0 .. ( @{$slices} - 1 ) ) {
                        if ( defined @{$slices}[$slice] ) {
                            generate_display_list( $cache_id, $slice, $by, $bx );
                            @{$slices}[$slice] = 0;
                        }
                        $redraw_needed = 1;
                        if ( ( time - $entry_time ) > $time_slice ) {
                            cede();
                            $entry_time = time;
                        }
                        $current_data_proc_task++;
                    }
                    $cells[$bx][$by][changed] = 0;
                }
            }
        }

        $max_data_proc_tasks    = $current_data_proc_task;
        $current_data_proc_task = 0;

        my $t1 = time;
        $time{landscape} = sprintf( "%.3f", $t1 - $t0 );
        $redraw_needed   = 1;
        $full_land_run   = 1;
    }
    return;
}

sub memory_control_loop {

    while (1) {
        schedule();

        $memory_full_checks++;

        my @protected_caches;

        # cycle through cells in range around cursor to generate display lists
        for my $bx ( $min_x_range .. $max_x_range ) {
            for my $by ( $min_y_range .. $max_y_range ) {
                if (   defined $cells[$bx][$by]
                    && defined $cells[$bx][$by][cache_ptr] )
                {
                    $protected_caches[ $cells[$bx][$by][cache_ptr] ] = 1;
                }
            }
        }

        # TODO: Limit cache deletions so $c{view_range} is never undercut
        # check that we're not using too much memory and destroy cache entries if necessary

        my $delete;
        my $use;

        for my $id ( 0 .. $#cache ) {

            # skip empty caches
            next if !defined $cache[$id][use_counter];

            # skip caches we're currently looking at
            next if $protected_caches[$id];

            if ( !defined $use || $cache[$id][use_counter] < $use ) {
                $delete = $id;
                $use    = $cache[$id][use_counter];
            }
        }

        if ( defined $delete ) {
            $memory_clears++;

            # delete landscape display lists
            my $slices = $cache[$delete][display_lists];
            for my $slice ( 0 .. @{$slices} - 1 ) {
                glDeleteLists( $cache[$delete][display_lists][$slice], 1 )
                  if ( $cache[$delete][display_lists][$slice] );
            }

            # delete landscape masks
            $slices = $cache[$delete][mask_lists];
            for my $slice ( 0 .. @{$slices} - 1 ) {
                glDeleteLists( $cache[$delete][mask_lists][$slice], 1 )
                  if ( $cache[$delete][mask_lists][$slice] );
            }

            undef ${ $cache[$delete][cell_ptr] };

            undef $cache[$delete];
            push @cache_bucket, $delete;
        }
        else {
            $all_protected = 1;
        }

        $memory_needs_clears = 0;
    }
}

# TODO : comment this better
sub generate_model_display_lists {
    for my $model ( keys %DRAW_MODEL ) {
        for my $part ( 0 .. $#{ $DRAW_MODEL{$model} } ) {
            next if !defined $DRAW_MODEL{$model}[$part];
            my $dl = $DRAW_MODEL{$model}[$part]->( 0, 0, 0, 1, 0, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY );
            $model_display_lists{$model}[$part] = $dl;
        }
    }
}

sub generate_display_list {
    my ( $id, $z, $y, $x ) = @_;
    my $dl;
    my $type;
    my $type_below;
    my $type_above;
    my $brightness_mod;

    if ( $cache[$id][display_lists][$z] ) {
        $dl = $cache[$id][display_lists][$z];
    }
    else {
        $dl = glGenLists(1);
        $cache[$id][display_lists][$z] = $dl;
    }

    glNewList( $dl, GL_COMPILE );

    for my $texture ( 0 .. $#texture_ID ) {    # cycle through textures

        glBindTexture( GL_TEXTURE_2D, $texture_ID[$texture] );    # set texture
        my $tile       = $tiles[$z][type];                        # get pointers to current layer
        my $tile_below = $tiles[ $z - 1 ][type];                  # as well as to layer above and below
        my $tile_above = $tiles[ $z + 1 ][type];

        #my $occup      = $tiles[$z][occup];                       # get pointers to current layer
        for my $rx ( ( $x * 16 ) .. ( $x * 16 ) + 15 ) {          # cycle through tiles in current slice on layer
            for my $ry ( ( $y * 16 ) .. ( $y * 16 ) + 15 ) {

                next if !defined $tile->[$rx][$ry];               # skip tile if undefined
                $type = $tile->[$rx][$ry];                        # store type of current tile
                next if $type == 32;                              # skip if tile is air
                next
                  if !defined $TILE_TYPES[$type][base_texture];    # skip if tile type doesn't have associated texture
                next
                  if $TILE_TYPES[$type][base_texture] !=
                      $texture;    # skip if tile type texture doesn't match current texture
                $type_below     = $tile_below->[$rx][$ry];
                $type_above     = $tile_above->[$rx][$ry];
                $brightness_mod = $TILE_TYPES[$type][brightness_mod];

                my ( $above, $below, $north, $south, $west, $east ) = ( EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY );
                my ( $northeast, $southeast, $southwest, $northwest ) = ( EMPTY, EMPTY, EMPTY, EMPTY );
                my $x_mod = $rx % 16;
                my $y_mod = $ry % 16;

                $below = $TILE_TYPES[$type_below][base_visual] if $type_below;
                $above = $TILE_TYPES[$type_above][base_visual] if $type_above;

                $north = $TILE_TYPES[ $tile->[$rx][ $ry - 1 ] ][base_visual]
                  if $tile->[$rx][ $ry - 1 ] && $y_mod != 0;
                $west = $TILE_TYPES[ $tile->[ $rx - 1 ][$ry] ][base_visual]
                  if $tile->[ $rx - 1 ][$ry] && $x_mod != 0;
                $south = $TILE_TYPES[ $tile->[$rx][ $ry + 1 ] ][base_visual]
                  if $tile->[$rx][ $ry + 1 ] && $y_mod != 15;
                $east = $TILE_TYPES[ $tile->[ $rx + 1 ][$ry] ][base_visual]
                  if $tile->[ $rx + 1 ][$ry] && $x_mod != 15;

                given ( $TILE_TYPES[$type][base_visual] ) {
                    when ( [ FLOOR, TREE, SHRUB, BOULDER, SAPLING, STAIR, STAIR_UP, STAIR_DOWN, PILLAR, FORTIF ] ) {
                        $brightness_mod *= 0.75 if ( defined $type_above && $above != EMPTY );
                    }
                }

                my @const_model_map;
                $const_model_map[WALL]       = "Wall";
                $const_model_map[PILLAR]     = "Pillar";
                $const_model_map[FORTIF]     = "Fortif";
                $const_model_map[TREE]       = "Tree";
                $const_model_map[SHRUB]      = "Shrub";
                $const_model_map[BOULDER]    = "Boulder";
                $const_model_map[SAPLING]    = "Sapling";
                $const_model_map[STAIR]      = "Stairs";
                $const_model_map[STAIR_UP]   = "Stair_Up";
                $const_model_map[STAIR_DOWN] = "Stair_Down";
                $const_model_map[FLOOR]      = "Floor";

                my $base_visual = $TILE_TYPES[$type][base_visual];

                my $brightness = ( ( ( $z / ( $zcount - 1 ) ) * 0.6 ) + 0.3 + $brightness_mod );

                given ($base_visual) {
                    when ( [ WALL, PILLAR, FORTIF, TREE, SHRUB, BOULDER, SAPLING, STAIR, STAIR_UP, STAIR_DOWN, FLOOR ] )
                    {
                        glColor3f( $brightness, $brightness, $brightness );
                        glTranslatef( $rx, $z, $ry );

                        for my $part ( 0 .. $#{ $DRAW_MODEL{ $const_model_map[$base_visual] } } ) {
                            next if ( ( $base_visual == WALL ) && ( $part == east )  && ( $east == WALL ) );
                            next if ( ( $base_visual == WALL ) && ( $part == west )  && ( $west == WALL ) );
                            next if ( ( $base_visual == WALL ) && ( $part == north ) && ( $north == WALL ) );
                            next if ( ( $base_visual == WALL ) && ( $part == south ) && ( $south == WALL ) );

                            next
                              if ( ( $base_visual != STAIR )
                                && ( $base_visual != STAIR_DOWN )
                                && ( $part == bottom )
                                && ( $below == WALL ) );

                            next
                              if ( ( $base_visual != WALL )
                                && ( $part == east )
                                && ( $east != EMPTY )
                                && ( $east != RAMP_TOP ) );
                            next
                              if ( ( $base_visual != WALL )
                                && ( $part == west )
                                && ( $west != EMPTY )
                                && ( $west != RAMP_TOP ) );
                            next
                              if ( ( $base_visual != WALL )
                                && ( $part == north )
                                && ( $north != EMPTY )
                                && ( $north != RAMP_TOP ) );
                            next
                              if ( ( $base_visual != WALL )
                                && ( $part == south )
                                && ( $south != EMPTY )
                                && ( $south != RAMP_TOP ) );

                            next if !defined $model_display_lists{ $const_model_map[$base_visual] }[$part];
                            glCallList( $model_display_lists{ $const_model_map[$base_visual] }[$part] );
                        }

                        glTranslatef( -$rx, -$z, -$ry );
                    }

                    when (RAMP) {
                        next
                          if ( defined $type_below
                            && $TILE_TYPES[$type_below][base_visual] == RAMP );
                        $northeast = $TILE_TYPES[ $tile->[ $rx + 1 ][ $ry - 1 ] ][base_visual]
                          if $tile->[ $rx + 1 ][ $ry - 1 ]
                              && ( $ry != 0 || $rx != $x_max );
                        $southeast = $TILE_TYPES[ $tile->[ $rx + 1 ][ $ry + 1 ] ][base_visual]
                          if $tile->[ $rx + 1 ][ $ry + 1 ]
                              && ( $ry != $y_max || $rx != $x_max );
                        $southwest = $TILE_TYPES[ $tile->[ $rx - 1 ][ $ry + 1 ] ][base_visual]
                          if $tile->[ $rx - 1 ][ $ry + 1 ]
                              && ( $ry != $y_max || $ry != 0 );
                        $northwest = $TILE_TYPES[ $tile->[ $rx - 1 ][ $ry - 1 ] ][base_visual]
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
                                  if !defined $DRAW_MODEL{$func}[main];

                                glColor3f( $brightness, $brightness, $brightness );
                                glTranslatef( $rx, $z, $ry );
                                
                                # TODO : remove unneeded checks for definedness
                                for my $part ( 0 .. $#{ $DRAW_MODEL{$func} } ) {
                                    next if !defined $model_display_lists{$func}[$part];
                                    glCallList( $model_display_lists{$func}[$part] );
                                }
                                glTranslatef( -$rx, -$z, -$ry );
                                last;
                            }
                        }
                    }
                }
            }
        }
    }
    glEndList();

    if ( $cache[$id][mask_lists][$z] ) {
        $dl = $cache[$id][mask_lists][$z];
    }
    else {
        $dl = glGenLists(1);
        $cache[$id][mask_lists][$z] = $dl;
    }

    draw_quadrangle( ( $x * 16 ), $z, ( $y * 16 ), 16, 16, $dl );

    return;
}

sub draw_quadrangle {
    my ( $x, $y, $z, $width, $length, $dl ) = @_;

    my $x_west   = $x + -0.4;
    my $x_east   = $x + $width - 0.4;
    my $y_top    = $y + 0.4;
    my $y_bottom = $y + -0.4;
    my $z_north  = $z + -0.4;
    my $z_south  = $z + $length - 0.4;

    my @verts = (
        $x_west,   $y_bottom, $z_south,  $x_east,   $y_bottom, $z_south,  $x_west,   $y_top,    $z_south,  $x_west,
        $y_top,    $z_south,  $x_east,   $y_bottom, $z_south,  $x_east,   $y_top,    $z_south,  $x_west,   $y_bottom,
        $z_north,  $x_east,   $y_top,    $z_north,  $x_east,   $y_bottom, $z_north,  $x_west,   $y_top,    $z_north,
        $x_east,   $y_top,    $z_north,  $x_west,   $y_bottom, $z_north,  $x_west,   $y_top,    $z_south,  $x_east,
        $y_top,    $z_north,  $x_west,   $y_top,    $z_north,  $x_east,   $y_top,    $z_south,  $x_east,   $y_top,
        $z_north,  $x_west,   $y_top,    $z_south,  $x_west,   $y_top,    $z_south,  $x_west,   $y_bottom, $z_north,
        $x_west,   $y_bottom, $z_south,  $x_west,   $y_top,    $z_north,  $x_west,   $y_bottom, $z_north,  $x_west,
        $y_top,    $z_south,  $x_east,   $y_bottom, $z_south,  $x_east,   $y_top,    $z_north,  $x_east,   $y_top,
        $z_south,  $x_east,   $y_bottom, $z_north,  $x_east,   $y_top,    $z_north,  $x_east,   $y_bottom, $z_south,
        $x_west,   $y_bottom, $z_south,  $x_west,   $y_bottom, $z_north,  $x_east,   $y_bottom, $z_south,  $x_east,
        $y_bottom, $z_south,  $x_west,   $y_bottom, $z_north,  $x_east,   $y_bottom, $z_north,
    );
    my $verts = OpenGL::Array->new_list( GL_FLOAT, @verts );

    my @texcoords = (
        0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0,
        1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1,
    );
    my $texcoords = OpenGL::Array->new_list( GL_FLOAT, @texcoords );

    my @norms = (
        0,  0,  1, 0,  0,  1, 0,  0,  1, 0,  0,  1, 0,  0,  1, 0,  0,  1, 0,  0,  -1, 0,
        0,  -1, 0, 0,  -1, 0, 0,  -1, 0, 0,  -1, 0, 0,  -1, 0, 1,  0,  0, 1,  0,  0,  1,
        0,  0,  1, 0,  0,  1, 0,  0,  1, 0,  -1, 0, 0,  -1, 0, 0,  -1, 0, 0,  -1, 0,  0,
        -1, 0,  0, -1, 0,  0, 1,  0,  0, 1,  0,  0, 1,  0,  0, 1,  0,  0, 1,  0,  0,  1,
        0,  0,  0, -1, 0,  0, -1, 0,  0, -1, 0,  0, -1, 0,  0, -1, 0,  0, -1, 0,
    );
    my $norms = OpenGL::Array->new_list( GL_FLOAT, @norms );

    my @indices = ( 0 .. 36 );
    my $indices = OpenGL::Array->new_list( GL_UNSIGNED_INT, @indices );

    glVertexPointer_p( 3, $verts );
    glNormalPointer_p($norms);
    glTexCoordPointer_p( 2, $texcoords );

    glNewList( $dl, GL_COMPILE );
    glDrawArrays( GL_TRIANGLES, 0, 36 );
    glEndList();
}

sub new_process_block {
    my ( $block_offset, $bx, $by, $bz ) = @_;
    my $changed = 0;
    my $buf     = "";

    my ( $type_changed, $desig_changed, $occup_changed ) = ( 0, 0, 0 );

    my $cell_string = $cell_strings[$bx][$by][$bz] ||= [ '', '', '' ];

    _ReadMemory( $df_proc_handle, $block_offset + $offsets[type_off], 2 * 256, $buf );
    if ( $cell_string->[type] ne $buf ) {
        $cell_string->[type] = $buf;
        $type_changed        = 1;
        $changed             = 1;
    }

    _ReadMemory( $df_proc_handle, $block_offset + $offsets[designation_off], 4 * 256, $buf );
    if ( $cell_string->[desig] ne $buf ) {
        $cell_string->[desig] = $buf;
        $desig_changed        = 1;
        $changed              = 1;
    }

    _ReadMemory( $df_proc_handle, $block_offset + $offsets[occupancy_off], 4 * 256, $buf );
    if ( $cell_string->[occup] ne $buf ) {
        $cell_string->[occup] = $buf;
        $occup_changed        = 1;
        $changed              = 1;
    }

    if ($changed) {
        my @type_data        = unpack( 'S' x 256, $cell_string->[type] )  if $type_changed;
        my @designation_data = unpack( 'L' x 256, $cell_string->[desig] ) if $desig_changed;
        my @occupation_data  = unpack( 'L' x 256, $cell_string->[occup] ) if $occup_changed;

        my ( $rx, $ry, $tile, $desig, $desig_below, $occup );

        my $bx_scaled  = $bx * 16;
        my $by_scaled  = $by * 16;
        my $tile_index = 0;

        for my $rx ( $bx_scaled .. $bx_scaled + 15 ) {

            # this calculates the real x and y values
            # of this tile on the overall map_base
            $tile        = $tiles[$bz][type][$rx]        ||= [];
            $desig       = $tiles[$bz][desig][$rx]       ||= [];
            $desig_below = $tiles[ $bz - 1 ][desig][$rx] ||= [];
            $occup       = $tiles[$bz][occup][$rx]       ||= [];

            # cycle through 16 x and 16 y values,
            # which generate a total of 256 tile indexes
            for my $ry ( $by_scaled .. $by_scaled + 15 ) {
                my $hideflag = 0;

                # skip tile if it is hidden, but only if the tile directly below it is not loaded yet or also hidden
                $hideflag = $designation_data[$tile_index] & 512 if $desig_changed;
                $hideflag = $desig->[$ry] & 512 if !$desig_changed;
                if (
                    $hideflag == 512
                    and ( !defined $desig_below->[$ry]
                        or ( $desig_below->[$ry] & 512 ) == 512 )
                  )
                {
                    $desig->[$ry] = 512;
                    ++$tile_index;
                    next;
                }

                $tile->[$ry]  = $type_data[$tile_index]        if $type_changed;
                $desig->[$ry] = $designation_data[$tile_index] if $desig_changed;
                $occup->[$ry] = $occupation_data[$tile_index]  if $occup_changed;

                ++$tile_index;
            }
        }
    }

    return $changed;
}

sub ask {
    print "$_[0]";
    return;
}

################################################################################

################################################################################

################################################################################
## Rendering Functions #########################################################
################################################################################

# ------
# Does everything needed before losing control to the main
# OpenGL event loop.

sub initialize_opengl {
    my ( $width, $height ) = @_;
    
    eval 'glDeleteQueries([0])';
    $occlusion_supported = 0 if $@ =~ /is not supported by this renderer/;

    build_textures();

    glClearColor( 0.7, 0.7, 0.7, 0.0 );    # Color to clear color buffer to.

    glClearDepth(1.0);                     # Depth to clear depth buffer to; type of test.
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

    glEnableClientState(GL_VERTEX_ARRAY);
    glEnableClientState(GL_NORMAL_ARRAY);
    glEnableClientState(GL_TEXTURE_COORD_ARRAY);
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

    $redraw_needed = 1;
    return;
}

# ------
# Routine which handles background stuff when the app is idle

sub idle_tasks {
    my $time = time;

    if ( $time > $next_cursor_time ) {
        $loc_loop->ready;
    }

    if ( $time > $next_creature_time ) {
        $creature_loop->ready;
    }

    if ( $time > $next_landscape_time ) {
        $land_loop->ready;
    }

    if ( $time > $next_item_time ) {
        $item_loop->ready;
    }

    if ( $time > $next_building_time ) {
        $buil_loop->ready;
    }

    $render_loop->ready if $force_rt or ( $redraw_needed and $time > $next_render_time );
    $memory_loop->ready if $memory_needs_clears;
    cede();

    return;
}

# ------
# Routine which actually does the drawing

sub render_scene {

    while (1) {
        my $t0 = time;
        my $buf;    # For our strings.

        # Enables, disables or otherwise adjusts
        # as appropriate for our current settings.

        glEnable(GL_TEXTURE_2D);

        glEnable(GL_LIGHTING);

        glBlendFunc( GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA );

        glEnable(GL_DEPTH_TEST);

        # Need to manipulate the ModelView matrix to move our model around.
        glMatrixMode(GL_MODELVIEW);

        gluLookAt( $x_pos + $x_off, $y_pos + $y_off, $z_pos + $z_off, $x_pos, $y_pos, $z_pos, 0, 1, 0 );

        # Set up a light, turn it on.
        glLightfv_p( GL_LIGHT1, GL_POSITION,
            ( $light_position[0], $light_position[1], $light_position[2], $light_position[3] ) );

        # Clear the color and depth buffers.
        glClear( GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT );

        glColor3f( 0.75, 0.75, 0.75 );    # Basic polygon color

        render_models();

        ## get pixels of cursor
        #my @array = glGenQueries_p(1);
        #
        #glDepthMask(GL_FALSE);
        #glColorMask(GL_FALSE,GL_FALSE,GL_FALSE,GL_FALSE);
        #
        #glBeginQuery(GL_SAMPLES_PASSED, $array[0]);
        #
        #glLineWidth(2);
        #glPolygonMode( GL_FRONT, GL_LINE );
        #glColor3f( 1, 1, 1 );
        #glTranslatef( $x_pos, $y_pos, $z_pos );
        #for my $part ( 0 .. $#{ $DRAW_MODEL{Cursor} } ) {
        #    next if !defined $model_display_lists{Cursor}[$part];
        #    glCallList( $model_display_lists{Cursor}[$part] );
        #}
        #glTranslatef( -$x_pos, -$y_pos, -$z_pos );
        #glPolygonMode( GL_FRONT, GL_FILL );
        #glEndQuery(GL_SAMPLES_PASSED);
        #
        #glDepthMask(GL_TRUE);
        #glColorMask(GL_TRUE,GL_TRUE,GL_TRUE,GL_TRUE);
        #
        #while (!glGetQueryObjectiv($array[0], GL_QUERY_RESULT_AVAILABLE)) {}
        #
        #$pixels = glGetQueryObjectuiv($array[0], GL_QUERY_RESULT);

        # draw visible cursor
        glDisable(GL_LIGHTING);
        glLineWidth(2);
        glBindTexture( GL_TEXTURE_2D, $texture_ID[cursor] );
        glPolygonMode( GL_FRONT, GL_LINE );
        glColor3f( 1, 1, 1 );
        glTranslatef( $x_pos, $y_pos, $z_pos );
        
        # TODO : remove unneeded checks for definedness
        for my $part ( 0 .. $#{ $DRAW_MODEL{Cursor} } ) {
            next if !defined $model_display_lists{Cursor}[$part];
            glCallList( $model_display_lists{Cursor}[$part] );
        }
        glTranslatef( -$x_pos, -$y_pos, -$z_pos );
        glPolygonMode( GL_FRONT, GL_FILL );
        glBindTexture( GL_TEXTURE_2D, $texture_ID[grass] );

=cut        glBindTexture( GL_TEXTURE_2D, $texture_ID[test] );
        glEnable(GL_POINT_SPRITE);
        glTexEnvi(GL_POINT_SPRITE, GL_COORD_REPLACE, GL_TRUE);
        glPointSize(50.0);
        glBegin(GL_POINTS);
        glVertex3f($x_pos, $y_pos, $z_pos);
=cut        glEnd();

        glLoadIdentity();    # Move back to the origin (for the text, below).

        # We need to change the projection matrix for the text rendering.
        glMatrixMode(GL_PROJECTION);

        glPushMatrix();      # But we like our current view too; so we save it here.

        render_ui();

        glPopMatrix();        # Done with this special projection matrix.  Throw it away.
        glutSwapBuffers();    # All done drawing.  Let's show it.

        my $t1 = time;
        $time{render} = $t1 - $t0;

        $next_render_time = time + $c{redraw_delay} - $time{render};
        $redraw_needed    = 0;
        schedule();
    }
    return;
}

sub render_models {
    my @query_cells;

    for my $z ( 0 .. $ceiling_slice ) {

        # cycle through cells in range around cursor to render
        for my $bx ( $min_x_range .. $max_x_range ) {
            for my $by ( $min_y_range .. $max_y_range ) {

                my $cache_ptr = $cells[$bx][$by][cache_ptr];
                next if !defined $cache_ptr;
                next if !defined $cache[$cache_ptr];

                # draw landscape
                my $slices = $cache[$cache_ptr][display_lists];
                if ($slices->[$z]) {
                    glCallList( $slices->[$z] );
                    push @query_cells, [ $bx, $by, $z ];
                }

            }
        }
    }
    
    my @cells_to_draw;
    
    if ($occlusion_supported) {
        my @queries;
        glDepthMask(GL_FALSE);
        glColorMask( GL_FALSE, GL_FALSE, GL_FALSE, GL_FALSE );
        glDisable(GL_CULL_FACE);
         
        @queries = glGenQueries_p( scalar @query_cells );
        my $id = 0;
        
        for my $cell ( @query_cells ) {
            my $bx         = $cell->[0];
            my $by         = $cell->[1];
            my $z          = $cell->[2];
            my $cache_ptr = $cells[$bx][$by][cache_ptr];
            my $slices = $cache[$cache_ptr][mask_lists];
            $cell->[3] = $queries[$id];
            glBeginQuery( GL_SAMPLES_PASSED, $cell->[3] );
            glCallList( $slices->[$z] );
            glEndQuery(GL_SAMPLES_PASSED);
            $id++;
        }
        
        glEnable(GL_CULL_FACE);
        glDepthMask(GL_TRUE);
        glColorMask( GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE );
    
        for my $cell ( @query_cells ) {
            while ( !glGetQueryObjectiv( $cell->[3], GL_QUERY_RESULT_AVAILABLE ) ) { }
            my $pixel = glGetQueryObjectuiv( $cell->[3], GL_QUERY_RESULT );
            push @cells_to_draw, $cell if $pixel > 0;
        }
        glDeleteQueries(@queries);
    }
    else {
        @cells_to_draw = @query_cells;
    }

    $pixels = $#cells_to_draw . "/" . $#query_cells;

    for my $cell (@cells_to_draw) {
        my $bx         = $cell->[0];
        my $by         = $cell->[1];
        my $z          = $cell->[2];
        my $brightness = ( ( ( $z / ( $zcount - 1 ) ) * 0.6 ) + 0.3 );

        my $cache_ptr = $cells[$bx][$by][cache_ptr];
        next if !defined $cache_ptr;
        next if !defined $cache[$cache_ptr];

        # draw creatures
        if ( defined $cells[$bx][$by][creature_list][$z] ) {
            my $creature_list_size = @{ $cells[$bx][$by][creature_list][$z] };
            for my $entry ( 0 .. $creature_list_size ) {
                my $creature_id = $cells[$bx][$by][creature_list][$z][$entry];
                next if !defined $creature_id;
                next unless $creatures_present{$creature_id};

                next if $creatures{$creature_id}[flags] & 2;    # dead, i think
                my $x = $creatures{$creature_id}[c_x];
                my $y = $creatures{$creature_id}[c_y];
                glColor3f( $brightness, $brightness, $brightness );
                glTranslatef( $x, $z, $y );
                my $model_name;
                given ( $creatures{$creature_id}[race] ) {
                    when (166) {
                        $model_name = "Creature";
                    }
                    default {
                        $model_name = "Creature2";
                    }
                }

                glBindTexture( GL_TEXTURE_2D, $texture_ID[creature] );
                
                # TODO : remove unneeded checks for definedness
                for my $part ( 0 .. $#{ $DRAW_MODEL{$model_name} } ) {
                    next if !defined $model_display_lists{$model_name}[$part];
                    glCallList( $model_display_lists{$model_name}[$part] );
                }
                glTranslatef( -$x, -$z, -$y );
            }
        }

        # draw buildings
        if ( defined $cells[$bx][$by][building_list][$z] ) {
            my $building_list_size = @{ $cells[$bx][$by][building_list][$z] };
            for my $entry ( 0 .. $building_list_size ) {
                my $building_id = $cells[$bx][$by][building_list][$z][$entry];
                next if !defined $building_id;
                next unless $building_present{$building_id};

                my $x = $buildings{$building_id}[b_x];
                my $y = $buildings{$building_id}[b_y];
                glColor3f( $brightness, $brightness, $brightness );
                glTranslatef( $x, $z, $y );

                my $vtable_id = $buildings{$building_id}[b_vtable_id];
                $vtable_id = 'default' if !defined $building_visuals{$vtable_id}[0];
                my $model_name = $building_visuals{$vtable_id}[0];

                glBindTexture( GL_TEXTURE_2D, $texture_ID[ $building_visuals{$vtable_id}[1] ] );
                
                # TODO : remove unneeded checks for definedness
                for my $part ( 0 .. $#{ $DRAW_MODEL{$model_name} } ) {
                    next if !defined $model_display_lists{$model_name}[$part];
                    glCallList( $model_display_lists{$model_name}[$part] );
                }
                glTranslatef( -$x, -$z, -$y );
            }
        }

        # draw items
        if ( defined $cells[$bx][$by][item_list][$z] ) {
            my $item_list_size = @{ $cells[$bx][$by][item_list][$z] };
            for my $entry ( 0 .. $item_list_size ) {
                my $item_id = $cells[$bx][$by][item_list][$z][$entry];
                next if !defined $item_id;
                next if $items{$item_id}[invisible];

                my $x = $items{$item_id}[i_x];
                my $y = $items{$item_id}[i_y];

                glColor3f( $brightness, $brightness, $brightness );
                glTranslatef( $x, $z, $y );
                my $model_name;
                given ($item_id) {
                    default {
                        $model_name = "Items";
                    }
                }

                glBindTexture( GL_TEXTURE_2D, $texture_ID[items] );
                
                # TODO : remove unneeded checks for definedness
                for my $part ( 0 .. $#{ $DRAW_MODEL{$model_name} } ) {
                    next if !defined $model_display_lists{$model_name}[$part];
                    glCallList( $model_display_lists{$model_name}[$part] );
                }

                glTranslatef( -$x, -$z, -$y );
            }
        }

    }

    return;
}

sub render_ui {
    my $buf;

    glLoadIdentity();    # Now we set up a new projection for the text.

    gluOrtho2D( 0, $c{window_width}, $c{window_height}, 0 );

    glDisable(GL_TEXTURE_2D);    # Lit or textured text looks awful.
    glDisable(GL_LIGHTING);

    glDisable(GL_DEPTH_TEST);    # We don't want depth-testing either.

    # But, for fun, let's make the text partially transparent too.
    glColor4f( 0.6, 1.0, 0.6, .75 );

    $buf = sprintf 'X: %d', $x_pos;
    glRasterPos2i( 2, 14 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Y: %d', $z_pos;
    glRasterPos2i( 2, 26 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Z: %d', $y_pos;
    glRasterPos2i( 2, 38 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'H-Angle: %.2f', $y_rot;
    glRasterPos2i( 2, 50 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'V-Angle: %.2f', $x_rot;
    glRasterPos2i( 2, 62 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Cam-X: %.2f', $x_off;
    glRasterPos2i( 2, 74 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Cam-Y: %.2f', $z_off;
    glRasterPos2i( 2, 86 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Cam-Z: %.2f', $y_off;
    glRasterPos2i( 2, 98 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Mem: %.2f %%', ( ( $memory_use / $c{memory_limit} ) * 100 );
    glRasterPos2i( 2, 110 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Caches: %d', ( ( $#cache + 1 ) - ( $#cache_bucket + 1 ) );
    glRasterPos2i( 2, 122 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    if ( $tiles[$zmouse][type][$xmouse][$ymouse] ) {
        $buf = sprintf 'Type: %d', $tiles[$zmouse][type][$xmouse][$ymouse];
        glRasterPos2i( 2, 134 );
        glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );
    }

    if ( $tiles[$zmouse][desig][$xmouse][$ymouse] ) {
        $buf = sprintf 'Desigs: 0b%059b', $tiles[$zmouse][desig][$xmouse][$ymouse];
        glRasterPos2i( 2, $c{window_height} - 14 );
        glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );
    }

    if ( $tiles[$zmouse][occup][$xmouse][$ymouse] ) {
        $buf = sprintf 'Occup: 0b%059b', ( $tiles[$zmouse][occup][$xmouse][$ymouse] & 7 );
        glRasterPos2i( 2, $c{window_height} - 26 );
        glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );
    }

    if ( $tiles[$zmouse][occup][$xmouse][$ymouse] ) {
        $buf = sprintf 'Occup: 0b%059b', $tiles[$zmouse][occup][$xmouse][$ymouse];
        glRasterPos2i( 2, $c{window_height} - 2 );
        glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );
    }

    $buf = sprintf 'Mouse: %d %d', $xmouse, $ymouse;
    glRasterPos2i( 2, 158 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = sprintf 'Working threads: %d', Coro::nready;
    glRasterPos2i( 2, 146 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Tasks: $current_data_proc_task / $max_data_proc_tasks : $time{landscape} secs";
    glRasterPos2i( 2, 172 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Creature-Tasks: $current_creat_proc_task / $max_creat_proc_tasks : $time{creature} secs";
    glRasterPos2i( 2, 186 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Ceiling: $ceiling_slice";
    glRasterPos2i( 2, 198 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Mem-Act: $memory_clears / $memory_full_checks";
    glRasterPos2i( 2, 210 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Building-Tasks: $current_buil_proc_task / $max_buil_proc_tasks : $time{building} secs";
    glRasterPos2i( 2, 224 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Item-Tasks: $current_item_proc_task / $max_item_proc_tasks : $time{item} secs";
    glRasterPos2i( 2, 236 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    $buf = "Pixels: $pixels";
    glRasterPos2i( 2, 250 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    my $timesum = $time{landscape} + $time{creature} + $time{building} + $time{item};
    $buf = "Time: $timesum secs";
    glRasterPos2i( 2, 262 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    #$buf = "Crea: $creature_length";
    #glRasterPos2i( 2, 222 );
    #glutBitmapString( GLUT_BITMAP_HELVETICA_12, $buf );

    glColor4f( 0.2, 0.2, 0.2, 0.75 );

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

    glColor4f( 0.2, 0.2, 0.2, 0.75 );
    glColor4f( 1, 1, 0.2, 0.75 ) if ( $c{view_range} > 0 );
    glRasterPos2i( $c{window_width} - 36, $c{window_height} - 6 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, "-" );

    glColor4f( 0.2, 0.2, 0.2, 0.75 );
    my $size = ( $xcount > $ycount ) ? $xcount : $ycount;
    glColor4f( 1, 1, 0.2, 0.75 ) if ( $c{view_range} < $size / 2 );
    glRasterPos2i( $c{window_width} - 14, $c{window_height} - 6 );
    glutBitmapString( GLUT_BITMAP_HELVETICA_12, "+" );

    my $height_mod = ( $c{window_height} - 22 ) / ( $zcount + 2 );

    for my $slice ( 0 .. $zcount ) {

        my $part   = ( 0.6 / $zcount );
        my $bright = ( $part * $slice ) + 0.2;

        glColor4f( $bright, $bright, $bright, 1 );

        glBegin(GL_QUADS);
        glVertex3f( $c{window_width} - 20, $c{window_height} - 22 - $height_mod * ( $slice + 1 ), 0.0 );
        glVertex3f( $c{window_width} - 20, $c{window_height} - 22 - $height_mod * $slice, 0.0 );
        glVertex3f( $c{window_width} - 0,  $c{window_height} - 22 - $height_mod * $slice, 0.0 );
        glVertex3f( $c{window_width} - 0, $c{window_height} - 22 - $height_mod * ( $slice + 1 ), 0.0 );
        glEnd();
    }

    for my $slice ( 0 .. $zcount ) {
        if ( $slice == $ceiling_slice ) {
            glColor4f( 1, 1, 0, 1 );
            my $height = ( $height_mod * $slice ) - ( $height_mod * ( $slice + 1 ) );
            glRasterPos2i( $c{window_width} - 17,
                $c{window_height} - 22 - ( $height / 2 ) - $height_mod * ( $slice + 1 ) );
            glutBitmapString( GLUT_BITMAP_HELVETICA_12, $slice );
        }
    }

    glEnable(GL_TEXTURE_2D);
    glBindTexture( GL_TEXTURE_2D, $texture_ID[ui] );
    glColor4f( 1, 1, 1, 1 );

    if ($ceiling_locked) {
        glBegin(GL_QUADS);
        OpenGL::glTexCoord2f( 0, 1 );
        glVertex3f( $c{window_width} - 42, 0, 0.0 );
        OpenGL::glTexCoord2f( 0, 0.84375 );
        glVertex3f( $c{window_width} - 42, 20, 0.0 );
        OpenGL::glTexCoord2f( 0.15625, 0.84375 );
        glVertex3f( $c{window_width} - 22, 20, 0.0 );
        OpenGL::glTexCoord2f( 0.15625, 1 );
        glVertex3f( $c{window_width} - 22, 0, 0.0 );
        glEnd();
    }
    else {
        glBegin(GL_QUADS);
        OpenGL::glTexCoord2f( 0.15625, 1 );
        glVertex3f( $c{window_width} - 42, 0, 0.0 );
        OpenGL::glTexCoord2f( 0.15625, 0.84375 );
        glVertex3f( $c{window_width} - 42, 20, 0.0 );
        OpenGL::glTexCoord2f( 0.3125, 0.84375 );
        glVertex3f( $c{window_width} - 22, 20, 0.0 );
        OpenGL::glTexCoord2f( 0.3125, 1 );
        glVertex3f( $c{window_width} - 22, 0, 0.0 );
        glEnd();
    }

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

    my $cam_target = V( $x_pos, $y_pos, $z_pos );
    my $cam_off    = V( $x_off, $y_off, $z_off );
    my $cam_pos    = $cam_target + $cam_off;
    my $cam_normal = $cam_off * -1;

    my @x = ( $min_x_range * 16, ( $max_x_range * 16 ) + 15 );
    my @y = ( $min_y_range * 16, ( $max_y_range * 16 ) + 15 );
    my @z = ( 0, $zcount );

    my $dist_min = 999999;
    my $dist_max = -999999;

    for my $x (@x) {
        for my $y (@y) {
            for my $z (@z) {
                my $target = V( $x, $z, $y );
                my $dist = ( $cam_normal * ( $target - $cam_pos ) ) / abs($cam_normal);
                $dist_min = $dist if $dist < $dist_min;
                $dist_max = $dist if $dist > $dist_max;
            }
        }
    }

    $dist_min -= .75;
    $dist_min = 1 if $dist_min < 1;

    gluPerspective( $cam_angle, $width / $height, $dist_min, $dist_max );

    #say "$dist_min, $dist_max";

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
    @texture_ID = glGenTextures_p(30);

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
    create_texture( 'metal',                      metal );
    create_texture( 'stone_detailed',             stone_detailed );
    create_texture( 'minstone_detailed',          minstone_detailed );
    create_texture( 'ui',                         ui );
    create_texture( 'items',                      items );
    create_texture( 'wood',                       wood );
    create_texture( 'red',                        red );

#glBindTexture(GL_TEXTURE_2D, $texture_ID[grass]);       # select mipmapped texture
#glTexParameterf(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,GL_REPEAT);    # Some pretty standard settings for wrapping and filtering.
#glTexParameterf(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,GL_REPEAT);

    say "   textures loaded.\n";
    return;
}

sub create_texture {
    my ( $name, $id ) = @_;
    glBindTexture( GL_TEXTURE_2D, $texture_ID[$id] );
    my $tex = new OpenGL::Image( engine => 'Magick', source => "textures/$name.png" );
    my ( $ifmt, $fmt, $type ) = $tex->Get( 'gl_internalformat', 'gl_format', 'gl_type' );
    my ( $w, $h ) = $tex->Get( 'width', 'height' );
    glTexParameteri( GL_TEXTURE_2D, GL_GENERATE_MIPMAP, GL_TRUE );
    glTexParameterf( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    glTexParameterf( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_NEAREST );
    glTexImage2D_c( GL_TEXTURE_2D, 0, $ifmt, $w, $h, 0, $fmt, $type, $tex->Ptr() );
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

    #if ( $scan == VK_F ) {
    #    $proc->set_u32( $OFFSETS[$ver]{mouse_z}, $zmouse + 1 );    # BE CAREFUL, MAY DAMAGE YOUR SYSTEM
    #    print "moo";
    #}

    PostMessage( $DF_window, WM_KEYDOWN, $scan, 0 );

    $redraw_needed = 1;
    return;
}

# Callback Function called when a special $key is pressed. #####################

sub process_special_key_press {
    my $key = shift;

    if ( $key == GLUT_KEY_F12 ) {

        $force_rt = 1;
        open my $OUT, ">>", 'export.txt' or die( "horribly: " . $! );
        print $OUT "\n\n--------------------------------\n";
        print $OUT "X: $xmouse Y: $ymouse Z: $zmouse\n\n";
        say "\n\n--------------------------------";
        say "X: $xmouse Y: $ymouse Z: $zmouse\n";
        for my $item ( values %items ) {
            next if !defined $item->[i_x];
            next if !defined $item->[i_y];
            next if !defined $item->[i_z];
            if (   $item->[i_x] == $xmouse
                && $item->[i_y] == $ymouse
                && $item->[i_z] == $zmouse )
            {
                my $hex_dump = $proc->hexdump( $item->[i_address], 0x88 );
                print $OUT "Item:\n$hex_dump\n\n";
                say "Item:\n$hex_dump\n";
            }
        }
        for my $building ( keys %buildings ) {
            next if !defined $buildings{$building}[b_x];
            next if !defined $buildings{$building}[b_y];
            next if !defined $buildings{$building}[b_z];
            if (   $buildings{$building}[b_x] == $xmouse
                && $buildings{$building}[b_y] == $ymouse
                && $buildings{$building}[b_z] == $zmouse )
            {
                my $hex_dump = $proc->hexdump( $building, 0xD8 );
                print $OUT "Building:\n$hex_dump\n\n";
                say "Building:\n$hex_dump\n";
            }
        }
        for my $creature ( keys %creatures ) {
            next if !defined $creatures{$creature}[c_x];
            next if !defined $creatures{$creature}[c_y];
            next if !defined $creatures{$creature}[c_z];
            if (   $creatures{$creature}[c_x] == $xmouse
                && $creatures{$creature}[c_y] == $ymouse
                && $creatures{$creature}[c_z] == $zmouse )
            {
                my $hex_dump = $proc->hexdump( $creature, 0x688 );
                print $OUT "Creature:\n$hex_dump\n\n";
                say "Creature:\n$hex_dump\n";
            }
        }
        close $OUT;
    }

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

    $redraw_needed = 1;
    return;
}

sub process_mouse_click {
    my ( $button, $state, $x, $y ) = @_;
    if ( $button == GLUT_MIDDLE_BUTTON && $state == GLUT_DOWN ) {
        glutSetCursor(GLUT_CURSOR_NONE);
        $middle_mouse   = 1;
        $last_mouse_x   = $x;
        $last_mouse_y   = $y;
        $mouse_cursor_x = $x;
        $mouse_cursor_y = $y;
    }

    if ( $button == GLUT_LEFT_BUTTON && $state == GLUT_DOWN ) {
        $last_mouse_x = $x;
        $last_mouse_y = $y;

        if (   $x > $c{window_width} - 42
            && $x < $c{window_width} - 22
            && $y > $c{window_height} - 20
            && $y < $c{window_height} )
        {
            if ( $c{view_range} > 0 ) {
                --$c{view_range};
                resize_scene( $c{window_width}, $c{window_height} );
                $redraw_needed      = 1;
                $view_range_changed = 1;
            }
        }
        elsif ($x > $c{window_width} - 42
            && $x < $c{window_width} - 20
            && $y > 0
            && $y < 20 )
        {
            if ( $ceiling_locked == 1 ) {
                $ceiling_locked = 0;
                $ceiling_slice  = $zcount;
                $redraw_needed  = 1;
            }
            else {
                $ceiling_locked = 1;
                $redraw_needed  = 1;
            }
        }
        elsif ($x > $c{window_width} - 20
            && $x < $c{window_width}
            && $y > $c{window_height} - 20
            && $y < $c{window_height} )
        {
            my $size = ( $xcount > $ycount ) ? $xcount : $ycount;

            if ( $c{view_range} < $size / 2 ) {
                ++$c{view_range};
                resize_scene( $c{window_width}, $c{window_height} );
                $redraw_needed      = 1;
                $view_range_changed = 1;
            }
        }
        elsif ($x > $c{window_width} - 20
            && $x < $c{window_width}
            && $y > 0
            && $y < $c{window_height} - 22 )
        {
            $ceiling_slice = int( ( ( $y / ( ( $c{window_height} - 22 ) / ( $zcount + 2 ) ) ) - ($zcount) ) * -1 ) + 2;
            $ceiling_slice = 0       if $ceiling_slice < 0;
            $ceiling_slice = $zcount if $ceiling_slice > $zcount;
            $changing_ceiling = 1;
            $redraw_needed    = 1;
        }
        else {
            $mouse_cursor_x = $x;
            $mouse_cursor_y = $y;
            glutSetCursor(GLUT_CURSOR_NONE);
            $rotating = 1;
        }
    }

    glutWarpPointer( $mouse_cursor_x, $mouse_cursor_y )
      if $button == GLUT_MIDDLE_BUTTON && $state == GLUT_UP && $middle_mouse == 1;
    glutWarpPointer( $mouse_cursor_x, $mouse_cursor_y )
      if $button == GLUT_LEFT_BUTTON && $state == GLUT_UP && $rotating == 1;
    glutSetCursor(GLUT_CURSOR_INHERIT) if $button == GLUT_LEFT_BUTTON   && $state == GLUT_UP;
    glutSetCursor(GLUT_CURSOR_INHERIT) if $button == GLUT_MIDDLE_BUTTON && $state == GLUT_UP;
    $changing_ceiling = 0 if $button == GLUT_LEFT_BUTTON   && $state == GLUT_UP;
    $rotating         = 0 if $button == GLUT_LEFT_BUTTON   && $state == GLUT_UP;
    $middle_mouse     = 0 if $button == GLUT_MIDDLE_BUTTON && $state == GLUT_UP;
    return;
}

sub process_active_mouse_motion {
    my ( $x, $y ) = @_;

    if ($changing_ceiling) {
        $ceiling_slice = int( ( ( $y / ( ( $c{window_height} - 22 ) / ( $zcount + 2 ) ) ) - ($zcount) ) * -1 ) + 2;
        $ceiling_slice = 0       if $ceiling_slice < 0;
        $ceiling_slice = $zcount if $ceiling_slice > $zcount;
        $redraw_needed = 1;
        return;
    }

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
        my $zoom_by_fov = 0;
        if ($zoom_by_fov) {
            $cam_angle += $new_y * 0.2;
            $cam_angle = 1   if $cam_angle < 1;
            $cam_angle = 179 if $cam_angle > 179;
        }
        else {
            $mouse_dist += $new_y * 0.2;
            $mouse_dist = 0.2 if $mouse_dist < 0.2;
        }

    }

    resize_scene( $c{window_width}, $c{window_height} );

    $last_mouse_x = $x;
    $last_mouse_y = $y;
    reposition_camera();

    if ( ( $rotating == 1 || $middle_mouse == 1 ) && ( $new_x != 0 || $new_y != 0 ) ) {

        $last_mouse_x = $mouse_cursor_x;
        $last_mouse_y = $mouse_cursor_y;
        glutWarpPointer( $last_mouse_x, $last_mouse_y );
    }

    $redraw_needed = 1;
    return;
}

sub reposition_camera {
    my $radial_x_rotation = $x_rot * PIOVER180;
    my $radial_y_rotation = $y_rot * PIOVER180;
    my $cos_y             = cos $radial_y_rotation;
    my $sin_y             = sin $radial_y_rotation;
    my $sin_x             = sin $radial_x_rotation;
    my $cos_x             = cos $radial_x_rotation;

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

sub set_detached {
    ($detached) = $_[1];
}

sub fatal_error {
    my ($error) = @_;
    if ($detached) {
        Win32::MsgBox( $error, MB_ICONSTOP, "Lifevis - $VERSION" );
        exit;
    }
    else {
        croak $error;
    }
}

sub notify_user {
    my ($message) = @_;
    if ($detached) {
        Win32::MsgBox( $message, MB_ICONINFORMATION, "Lifevis - $VERSION" );
    }
    else {
        say $message;
    }
}

1;
__END__
