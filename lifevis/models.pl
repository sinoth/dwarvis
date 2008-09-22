#!/usr/bin/perl -w
use 5.010;
use strict;

BEGIN {
	eval "use constant base_visual => 0"    unless(defined &base_visual);
	eval "use constant EMPTY => 0"          unless(defined &EMPTY);
	eval "use constant FLOOR => 1"          unless(defined &FLOOR);
	eval "use constant WALL => 2"           unless(defined &WALL);
	eval "use constant RAMP => 3"           unless(defined &RAMP);
	eval "use constant STAIR => 4"          unless(defined &STAIR);
	eval "use constant FORTIF => 5"         unless(defined &FORTIF);
	eval "use constant PILLAR => 6"         unless(defined &PILLAR);
}

our $zcount;

sub drawWall {
    my ($x, $y, $z, $s, $below, $north, $south, $west, $east) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + $s;
    my $zs = $z + $s;

    if ($below != WALL) {
        glNormal3f( 0,-1, 0); # Bottom Face.
        glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
        glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
        glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
        glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);
    }

    glNormal3f( 0, 1, 0); # Top face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);

    if ($north != WALL) {    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    }

    if ($east != WALL) {    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    }

    if ($south != WALL) {    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
    }

    if ($west != WALL) {    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
    }
}

sub drawFloor {
    my ($x, $y, $z, $s, $below, $north, $south, $west, $east) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;
    my $tex_y3 =0.1;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $zs = $z + $s;

    if ($below != WALL) {
        glNormal3f( 0,-1, 0); # Bottom Face.
        glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
        glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
        glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
        glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);
    }

    glNormal3f( 0, 1, 0); # Top face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);

    if ($north == EMPTY) {    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y3); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y3); glVertex3f(  $x, $ys, $z);
    }

    if ($east == EMPTY) {    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y3); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y3); glVertex3f( $xs, $ys,  $z);
    }

    if ($south == EMPTY) {    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y3); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y3); glVertex3f( $xs, $ys, $zs);
    }

    if ($west == EMPTY) {    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y3); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y3); glVertex3f( $x, $ys,  $z);
    }
}

sub ourDrawCube {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + $s;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 0, 1, 0); # Top face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}

sub ourDrawFloor {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;# $tex_num_x*$tex_const;
    my $tex_x2 =1;# $tex_num_x*$tex_const + $tex_const;
    my $tex_y1 =1;# $tex_num_y*$tex_const;
    my $tex_y2 =0;# $tex_num_y*$tex_const + $tex_const;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 0, 1, 0); # Top face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}

#sub drawSingleNorthRamp {
#    my ($x, $y, $z, $s) = @_;
#    my $brightness = $y/($zcount-15);
#    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
#    my $tex_x1 =0;
#    my $tex_x2 =1;
#    my $tex_y1 =1;
#    my $tex_y2 =0;
#
#    my $xs = $x + $s;
#    my $ys = $y + 0.1*$s;
#    my $ys2 = $y + $s+0.1;
#    my $zs = $z + $s;
#
#    glNormal3f( 0,-1, 0); # Bottom Face.
#    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
#    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
#    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
#    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);
#
#    glNormal3f( 0, 1, 1); # Top face.
#    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2,  $z);
#    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
#    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
#    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
#    
#    glNormal3f( 0, 0,-1); # Far face.
#    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $z);
#    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
#    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
#    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys2, $z);
#    
#    glNormal3f( 1, 0, 0); # Right face.
#    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
#    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
#    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
#    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
#    
#    glNormal3f( 0, 0, 1); # Front face.
#    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
#    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
#    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
#    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
#    
#    glNormal3f(-1, 0, 0); # Left Face.
#    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
#    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
#    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
#    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys2,  $z);
#}

sub drawSingleNorthRamp {
    glEnd();
    glBegin(GL_TRIANGLES);
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness);
    




    glNormal3f( -0.0004897960441668,0.000548003221476199,0.0001249813615748);
    glTexCoord2f(-0.085311502,1.05485195); glVertex3f(0.49013028+$x,0.31448611+$y,0.30755096+$z);
    glTexCoord2f(-0.13358794,1.04511636); glVertex3f(0.4684979+$x,0.29833853+$y,0.29357665+$z);
    glTexCoord2f(-0.08694026,1.013209); glVertex3f(0.47951976+$x,0.30078833+$y,0.32602921+$z);


    glNormal3f( -0.0006919435585516,0.000589164424043298,0.000390345306977401);
    glTexCoord2f(-0.17809861,0.3285038); glVertex3f(0.49013028+$x,0.31448611+$y,0.30755096+$z);
    glTexCoord2f(-0.33731306,0.1363279); glVertex3f(0.40528709+$x,0.26919905+$y,0.22550777+$z);
    glTexCoord2f(-0.20323544,0.27323554); glVertex3f(0.4684979+$x,0.29833853+$y,0.29357665+$z);


    glNormal3f( -0.0030586941512722,0.0038061028761448,0.00106508053462);
    glTexCoord2f(-0.08694026,1.013209); glVertex3f(0.47951976+$x,0.30078833+$y,0.32602921+$z);
    glTexCoord2f(0.23945416,1.04239178); glVertex3f(0.62247392+$x,0.38495707+$y,0.43578445+$z);
    glTexCoord2f(-0.085311502,1.05485195); glVertex3f(0.49013028+$x,0.31448611+$y,0.30755096+$z);


    glNormal3f( -0.001602205939299,0.0046474164600432,-0.000900437076937802);
    glTexCoord2f(-0.08694026,1.013209); glVertex3f(0.47951976+$x,0.30078833+$y,0.32602921+$z);
    glTexCoord2f(-0.088264428,0.97135806); glVertex3f(0.46257918+$x,0.29857151+$y,0.34473103+$z);
    glTexCoord2f(0.23918441,0.99898814); glVertex3f(0.6118634+$x,0.3712593+$y,0.45426269+$z);


    glNormal3f( -9.26695056059999e-005,0.0001784811071916,-6.27861184224001e-005);
    glTexCoord2f(-0.08694026,1.013209); glVertex3f(0.47951976+$x,0.30078833+$y,0.32602921+$z);
    glTexCoord2f(-0.10179278,0.97000246); glVertex3f(0.4565586+$x,0.29407741+$y,0.34084183+$z);
    glTexCoord2f(-0.088264428,0.97135806); glVertex3f(0.46257918+$x,0.29857151+$y,0.34473103+$z);


    glNormal3f( -0.0030586922120324,0.00380610144660321,0.00106507910507839);
    glTexCoord2f(0.23918441,0.99898814); glVertex3f(0.6118634+$x,0.3712593+$y,0.45426269+$z);
    glTexCoord2f(0.23945416,1.04239178); glVertex3f(0.62247392+$x,0.38495707+$y,0.43578445+$z);
    glTexCoord2f(-0.08694026,1.013209); glVertex3f(0.47951976+$x,0.30078833+$y,0.32602921+$z);


    glNormal3f( -0.0004205973668255,0.000584849924152403,0.0001920303542387);
    glTexCoord2f(0.23918441,0.99898814); glVertex3f(0.6118634+$x,0.3712593+$y,0.45426269+$z);
    glTexCoord2f(0.29310666,1.04299267); glVertex3f(0.64023247+$x,0.38978456+$y,0.45997772+$z);
    glTexCoord2f(0.23945416,1.04239178); glVertex3f(0.62247392+$x,0.38495707+$y,0.43578445+$z);


    glNormal3f( -0.000245348424731199,0.000341162398777001,0.000112017696498801);
    glTexCoord2f(0.23918441,0.99898814); glVertex3f(0.6118634+$x,0.3712593+$y,0.45426269+$z);
    glTexCoord2f(0.27443061,0.99272353); glVertex3f(0.62222256+$x,0.37407534+$y,0.46837543+$z);
    glTexCoord2f(0.29310666,1.04299267); glVertex3f(0.64023247+$x,0.38978456+$y,0.45997772+$z);


    glNormal3f( -0.0020457448632915,0.0017418785972313,0.0011540625211788);
    glTexCoord2f(0.071791846,0.6338303); glVertex3f(0.62247392+$x,0.38495707+$y,0.43578445+$z);
    glTexCoord2f(-0.35096775,0.16435506); glVertex3f(0.41429417+$x,0.28282474+$y,0.22090828+$z);
    glTexCoord2f(-0.17809861,0.3285038); glVertex3f(0.49013028+$x,0.31448611+$y,0.30755096+$z);


    glNormal3f( -0.0016022066661769,0.00464741795288539,-0.000900437076937798);
    glTexCoord2f(-0.088264428,0.97135806); glVertex3f(0.46257918+$x,0.29857151+$y,0.34473103+$z);
    glTexCoord2f(0.23631314,0.9551481); glVertex3f(0.59492282+$x,0.36904248+$y,0.47296452+$z);
    glTexCoord2f(0.23918441,0.99898814); glVertex3f(0.6118634+$x,0.3712593+$y,0.45426269+$z);


    glNormal3f( 0.000283585632232904,0.0042434683163125,-0.0026246816119269);
    glTexCoord2f(-0.088264428,0.97135806); glVertex3f(0.46257918+$x,0.29857151+$y,0.34473103+$z);
    glTexCoord2f(-0.089795086,0.93005151); glVertex3f(0.44384773+$x,0.30842962+$y,0.35864533+$z);
    glTexCoord2f(0.23631314,0.9551481); glVertex3f(0.59492282+$x,0.36904248+$y,0.47296452+$z);


    glNormal3f( -1.44879999426998e-005,9.37932827855003e-005,-8.59551501324002e-005);
    glTexCoord2f(-0.088264428,0.97135806); glVertex3f(0.46257918+$x,0.29857151+$y,0.34473103+$z);
    glTexCoord2f(-0.097860479,0.92968259); glVertex3f(0.44024229+$x,0.3057383+$y,0.3563163+$z);
    glTexCoord2f(-0.089795086,0.93005151); glVertex3f(0.44384773+$x,0.30842962+$y,0.35864533+$z);


    glNormal3f( -4.00527967475998e-005,0.000206498118924301,-1.18035747053996e-005);
    glTexCoord2f(0.23631314,0.9551481); glVertex3f(0.59492282+$x,0.36904248+$y,0.47296452+$z);
    glTexCoord2f(0.25145721,0.94994462); glVertex3f(0.59986523+$x,0.370386+$y,0.47969782+$z);
    glTexCoord2f(0.23918441,0.99898814); glVertex3f(0.6118634+$x,0.3712593+$y,0.45426269+$z);


    glNormal3f( 0.000283585095169598,0.00424346794875349,-0.00262468070730459);
    glTexCoord2f(-0.089795086,0.93005151); glVertex3f(0.44384773+$x,0.30842962+$y,0.35864533+$z);
    glTexCoord2f(0.23234741,0.91350768); glVertex3f(0.57619136+$x,0.37890058+$y,0.48687881+$z);
    glTexCoord2f(0.23631314,0.9551481); glVertex3f(0.59492282+$x,0.36904248+$y,0.47296452+$z);


    glNormal3f( 0.0074439466999832,0.0217526331650803,-0.0196367428340348);
    glTexCoord2f(-0.089795086,0.93005151); glVertex3f(0.44384773+$x,0.30842962+$y,0.35864533+$z);
    glTexCoord2f(-0.10117832,0.68123918); glVertex3f(0.336635+$x,0.39971742+$y,0.41912706+$z);
    glTexCoord2f(0.23234741,0.91350768); glVertex3f(0.57619136+$x,0.37890058+$y,0.48687881+$z);


    glNormal3f( 4.98372481284005e-005,0.000467765380473102,-0.000617675537257602);
    glTexCoord2f(0.709593,0.12622949); glVertex3f(0.44384773+$x,0.30842962+$y,0.35864533+$z);
    glTexCoord2f(0.9377108,0.31652768); glVertex3f(0.33302957+$x,0.3970261+$y,0.41679802+$z);
    glTexCoord2f(0.93117772,0.32385289); glVertex3f(0.336635+$x,0.39971742+$y,0.41912706+$z);


    glNormal3f( 4.76834178292e-005,0.0001948946656569,-7.38888631602002e-005);
    glTexCoord2f(0.23234741,0.91350768); glVertex3f(0.57619136+$x,0.37890058+$y,0.48687881+$z);
    glTexCoord2f(0.25145721,0.94994462); glVertex3f(0.59986523+$x,0.370386+$y,0.47969782+$z);
    glTexCoord2f(0.23631314,0.9551481); glVertex3f(0.59492282+$x,0.36904248+$y,0.47296452+$z);


    glNormal3f( 0.0003194352604958,0.000611318685770201,-0.000356445074920801);
    glTexCoord2f(0.23234741,0.91350768); glVertex3f(0.57619136+$x,0.37890058+$y,0.48687881+$z);
    glTexCoord2f(0.21793725,0.66554789); glVertex3f(0.46897864+$x,0.47018838+$y,0.54736054+$z);
    glTexCoord2f(0.2401844,0.91286269); glVertex3f(0.5791511+$x,0.37970512+$y,0.49091106+$z);


    glNormal3f( 0.0074439466999832,0.0217526324875628,-0.0196367430422032);
    glTexCoord2f(0.23234741,0.91350768); glVertex3f(0.57619136+$x,0.37890058+$y,0.48687881+$z);
    glTexCoord2f(-0.10117832,0.68123918); glVertex3f(0.336635+$x,0.39971742+$y,0.41912706+$z);
    glTexCoord2f(0.21793725,0.66554789); glVertex3f(0.46897864+$x,0.47018838+$y,0.54736054+$z);


    glNormal3f( -0.000285713982525601,0.000319668284608,7.29056860786001e-005);
    glTexCoord2f(-0.13358794,1.04511636); glVertex3f(0.4684979+$x,0.29833853+$y,0.29357665+$z);
    glTexCoord2f(-0.11543037,1.00805273); glVertex3f(0.46690088+$x,0.29136892+$y,0.31787753+$z);
    glTexCoord2f(-0.08694026,1.013209); glVertex3f(0.47951976+$x,0.30078833+$y,0.32602921+$z);


    glNormal3f( -0.000562423186687601,0.000478984983400001,0.0001004135427421);
    glTexCoord2f(-0.20323544,0.27323554); glVertex3f(0.4684979+$x,0.29833853+$y,0.29357665+$z);
    glTexCoord2f(-0.19895205,0.21511838); glVertex3f(0.44878801+$x,0.27519749+$y,0.29356581+$z);
    glTexCoord2f(-0.15396116,0.26407478); glVertex3f(0.46690088+$x,0.29136892+$y,0.31787753+$z);


    glNormal3f( -0.0010073764084296,0.000857745284779599,0.000568289100219);
    glTexCoord2f(-0.20323544,0.27323554); glVertex3f(0.4684979+$x,0.29833853+$y,0.29357665+$z);
    glTexCoord2f(-0.27949455,0.050242985); glVertex3f(0.37933458+$x,0.22248611+$y,0.25000909+$z);
    glTexCoord2f(-0.19895205,0.21511838); glVertex3f(0.44878801+$x,0.27519749+$y,0.29356581+$z);


    glNormal3f( -0.0001942314132998,0.0003740907030144,-0.000131596285946001);
    glTexCoord2f(-0.11543037,1.00805273); glVertex3f(0.46690088+$x,0.29136892+$y,0.31787753+$z);
    glTexCoord2f(-0.10179278,0.97000246); glVertex3f(0.4565586+$x,0.29407741+$y,0.34084183+$z);
    glTexCoord2f(-0.08694026,1.013209); glVertex3f(0.47951976+$x,0.30078833+$y,0.32602921+$z);


    glNormal3f( -0.000309977103640999,0.000264095817756001,-0.0001707507252944);
    glTexCoord2f(-0.15396116,0.26407478); glVertex3f(0.46690088+$x,0.29136892+$y,0.31787753+$z);
    glTexCoord2f(-0.15060514,0.22932791); glVertex3f(0.45540344+$x,0.27786996+$y,0.31787123+$z);
    glTexCoord2f(-0.10610308,0.26048739); glVertex3f(0.4565586+$x,0.29407741+$y,0.34084183+$z);


    glNormal3f( -0.000328081055802199,0.000279408430915801,5.85748614759989e-005);
    glTexCoord2f(-0.15396116,0.26407478); glVertex3f(0.46690088+$x,0.29136892+$y,0.31787753+$z);
    glTexCoord2f(-0.19895205,0.21511838); glVertex3f(0.44878801+$x,0.27519749+$y,0.29356581+$z);
    glTexCoord2f(-0.15060514,0.22932791); glVertex3f(0.45540344+$x,0.27786996+$y,0.31787123+$z);


    glNormal3f( -2.41922822389999e-005,0.000156622677444599,-0.0001435324498872);
    glTexCoord2f(-0.10179278,0.97000246); glVertex3f(0.4565586+$x,0.29407741+$y,0.34084183+$z);
    glTexCoord2f(-0.097860479,0.92968259); glVertex3f(0.44024229+$x,0.3057383+$y,0.3563163+$z);
    glTexCoord2f(-0.088264428,0.97135806); glVertex3f(0.46257918+$x,0.29857151+$y,0.34473103+$z);


    glNormal3f( -0.000361092112354801,0.0002311670237715,7.28640912099005e-005);
    glTexCoord2f(-0.15060514,0.22932791); glVertex3f(0.45540344+$x,0.27786996+$y,0.31787123+$z);
    glTexCoord2f(-0.16659349,0.16494389); glVertex3f(0.43628191+$x,0.25126367+$y,0.30752132+$z);
    glTexCoord2f(-0.13179454,0.19858321); glVertex3f(0.44810823+$x,0.2639086+$y,0.32601191+$z);


    glNormal3f( -0.000147891365153,0.0001260015080108,-8.14660893332995e-005);
    glTexCoord2f(-0.15060514,0.22932791); glVertex3f(0.45540344+$x,0.27786996+$y,0.31787123+$z);
    glTexCoord2f(-0.10436443,0.24444826); glVertex3f(0.45107311+$x,0.28763699+$y,0.34083881+$z);
    glTexCoord2f(-0.10610308,0.26048739); glVertex3f(0.4565586+$x,0.29407741+$y,0.34084183+$z);


    glNormal3f( -0.000619017229114101,0.0003962877125813,0.000124910333775599);
    glTexCoord2f(-0.19895205,0.21511838); glVertex3f(0.44878801+$x,0.27519749+$y,0.29356581+$z);
    glTexCoord2f(-0.16659349,0.16494389); glVertex3f(0.43628191+$x,0.25126367+$y,0.30752132+$z);
    glTexCoord2f(-0.15060514,0.22932791); glVertex3f(0.45540344+$x,0.27786996+$y,0.31787123+$z);


    glNormal3f( -0.0017780928869742,0.0015139827328913,0.0010030721025846);
    glTexCoord2f(-0.19895205,0.21511838); glVertex3f(0.44878801+$x,0.27519749+$y,0.29356581+$z);
    glTexCoord2f(-0.27949455,0.050242985); glVertex3f(0.37933458+$x,0.22248611+$y,0.25000909+$z);
    glTexCoord2f(-0.16659349,0.16494389); glVertex3f(0.43628191+$x,0.25126367+$y,0.30752132+$z);


    glNormal3f( -0.0004001689184892,0.0001323014884674,-0.0001317098309751);
    glTexCoord2f(-0.13179454,0.19858321); glVertex3f(0.44810823+$x,0.2639086+$y,0.32601191+$z);
    glTexCoord2f(-0.10436443,0.24444826); glVertex3f(0.45107311+$x,0.28763699+$y,0.34083881+$z);
    glTexCoord2f(-0.15060514,0.22932791); glVertex3f(0.45540344+$x,0.27786996+$y,0.31787123+$z);


    glNormal3f( -0.0048427359900066,0.000842766801184201,-0.000902220600281399);
    glTexCoord2f(-0.13179454,0.19858321); glVertex3f(0.44810823+$x,0.2639086+$y,0.32601191+$z);
    glTexCoord2f(0.11061356,-0.062185449); glVertex3f(0.39953487+$x,0.12196798+$y,0.45414589+$z);
    glTexCoord2f(-0.09575802,0.23096525); glVertex3f(0.4475925+$x,0.28097593+$y,0.34472277+$z);


    glNormal3f( -0.0042448110164872,0.002413503535036,0.0010644284560536);
    glTexCoord2f(-0.16659349,0.16494389); glVertex3f(0.43628191+$x,0.25126367+$y,0.30752132+$z);
    glTexCoord2f(0.11061356,-0.062185449); glVertex3f(0.39953487+$x,0.12196798+$y,0.45414589+$z);
    glTexCoord2f(-0.13179454,0.19858321); glVertex3f(0.44810823+$x,0.2639086+$y,0.32601191+$z);


    glNormal3f( -0.0121458672540712,0.0103417701358439,0.0068518265318351);
    glTexCoord2f(-0.16659349,0.16494389); glVertex3f(0.43628191+$x,0.25126367+$y,0.30752132+$z);
    glTexCoord2f(-0.26804602,0.036231297); glVertex3f(0.37515838+$x,0.21371046+$y,0.25585165+$z);
    glTexCoord2f(0.077525062,-0.093088169); glVertex3f(0.38770856+$x,0.10932305+$y,0.4356553+$z);


    glNormal3f( -0.0001909229881384,6.31221317337999e-005,-6.28400279450998e-005);
    glTexCoord2f(-0.09575802,0.23096525); glVertex3f(0.4475925+$x,0.28097593+$y,0.34472277+$z);
    glTexCoord2f(-0.10436443,0.24444826); glVertex3f(0.45107311+$x,0.28763699+$y,0.34083881+$z);
    glTexCoord2f(-0.13179454,0.19858321); glVertex3f(0.44810823+$x,0.2639086+$y,0.32601191+$z);


    glNormal3f( -0.0001584095012408,-9.60318324000451e-007,-0.0001436056066718);
    glTexCoord2f(-0.09575802,0.23096525); glVertex3f(0.4475925+$x,0.28097593+$y,0.34472277+$z);
    glTexCoord2f(-0.065216712,0.26988929); glVertex3f(0.43695733+$x,0.30188149+$y,0.35631449+$z);
    glTexCoord2f(-0.10436443,0.24444826); glVertex3f(0.45107311+$x,0.28763699+$y,0.34083881+$z);


    glNormal3f( -0.0041430643351128,-0.000953778436026199,-0.0026271131046174);
    glTexCoord2f(-0.09575802,0.23096525); glVertex3f(0.4475925+$x,0.28097593+$y,0.34472277+$z);
    glTexCoord2f(0.14259279,-0.032184403); glVertex3f(0.39901914+$x,0.13903531+$y,0.47285675+$z);
    glTexCoord2f(-0.059605702,0.26246179); glVertex3f(0.43487297+$x,0.29789251+$y,0.35864039+$z);


    glNormal3f( -9.96268605955997e-005,8.49343175387999e-005,-0.0001690496141326);
    glTexCoord2f(0.68830378,0.076533924); glVertex3f(0.45107311+$x,0.28763699+$y,0.34083881+$z);
    glTexCoord2f(0.72265908,0.11157918); glVertex3f(0.43695733+$x,0.30188149+$y,0.35631449+$z);
    glTexCoord2f(0.67739447,0.088765967); glVertex3f(0.4565586+$x,0.29407741+$y,0.34084183+$z);


    glNormal3f( -9.48633812495994e-005,-5.75024403800592e-007,-8.59981934681988e-005);
    glTexCoord2f(-0.059605702,0.26246179); glVertex3f(0.43487297+$x,0.29789251+$y,0.35864039+$z);
    glTexCoord2f(-0.065216712,0.26988929); glVertex3f(0.43695733+$x,0.30188149+$y,0.35631449+$z);
    glTexCoord2f(-0.09575802,0.23096525); glVertex3f(0.4475925+$x,0.28097593+$y,0.34472277+$z);


    glNormal3f( -0.000453586705355398,-0.000123300366705202,-0.000617946034633592);
    glTexCoord2f(0.72919211,0.10425404); glVertex3f(0.43487297+$x,0.29789251+$y,0.35864039+$z);
    glTexCoord2f(0.94424379,0.30920258); glVertex3f(0.32974461+$x,0.39316929+$y,0.41679622+$z);
    glTexCoord2f(0.72265908,0.11157918); glVertex3f(0.43695733+$x,0.30188149+$y,0.35631449+$z);


    glNormal3f( -0.000453586123797098,-0.000123300366705199,-0.000617944983349999);
    glTexCoord2f(0.72919211,0.10425404); glVertex3f(0.43487297+$x,0.29789251+$y,0.35864039+$z);
    glTexCoord2f(0.95077682,0.30187744); glVertex3f(0.32766025+$x,0.38918032+$y,0.41912212+$z);
    glTexCoord2f(0.94424379,0.30920258); glVertex3f(0.32974461+$x,0.39316929+$y,0.41679622+$z);


    glNormal3f( -5.96609844298006e-005,5.08625474922998e-005,-0.000101234464785501);
    glTexCoord2f(0.72265908,0.11157918); glVertex3f(0.43695733+$x,0.30188149+$y,0.35631449+$z);
    glTexCoord2f(0.71612609,0.11890428); glVertex3f(0.44024229+$x,0.3057383+$y,0.3563163+$z);
    glTexCoord2f(0.67739447,0.088765967); glVertex3f(0.4565586+$x,0.29407741+$y,0.34084183+$z);


    glNormal3f( -0.000233101310163303,0.000198874118804,-0.000713375862111206);
    glTexCoord2f(0.72265908,0.11157918); glVertex3f(0.43695733+$x,0.30188149+$y,0.35631449+$z);
    glTexCoord2f(0.94424379,0.30920258); glVertex3f(0.32974461+$x,0.39316929+$y,0.41679622+$z);
    glTexCoord2f(0.71612609,0.11890428); glVertex3f(0.44024229+$x,0.3057383+$y,0.3563163+$z);


    glNormal3f( 4.98363621636013e-005,0.000467764853818402,-0.000617676423222401);
    glTexCoord2f(0.71612609,0.11890428); glVertex3f(0.44024229+$x,0.3057383+$y,0.3563163+$z);
    glTexCoord2f(0.9377108,0.31652768); glVertex3f(0.33302957+$x,0.3970261+$y,0.41679802+$z);
    glTexCoord2f(0.709593,0.12622949); glVertex3f(0.44384773+$x,0.30842962+$y,0.35864533+$z);


    glNormal3f( -0.0002331021844732,0.0001988730138272,-0.000713375862111199);
    glTexCoord2f(0.71612609,0.11890428); glVertex3f(0.44024229+$x,0.3057383+$y,0.3563163+$z);
    glTexCoord2f(0.94424379,0.30920258); glVertex3f(0.32974461+$x,0.39316929+$y,0.41679622+$z);
    glTexCoord2f(0.9377108,0.31652768); glVertex3f(0.33302957+$x,0.3970261+$y,0.41679802+$z);


    glNormal3f( 2.85555215104e-005,0.0001167128256501,-4.42475183790004e-005);
    glTexCoord2f(0.2401844,0.91286269); glVertex3f(0.5791511+$x,0.37970512+$y,0.49091106+$z);
    glTexCoord2f(0.25145721,0.94994462); glVertex3f(0.59986523+$x,0.370386+$y,0.47969782+$z);
    glTexCoord2f(0.23234741,0.91350768); glVertex3f(0.57619136+$x,0.37890058+$y,0.48687881+$z);


    glNormal3f( 5.79312538684002e-005,0.0001134790431366,1.27055786925007e-005);
    glTexCoord2f(0.2401844,0.91286269); glVertex3f(0.5791511+$x,0.37970512+$y,0.49091106+$z);
    glTexCoord2f(0.24788112,0.91209021); glVertex3f(0.58067216+$x,0.37840743+$y,0.495566+$z);
    glTexCoord2f(0.25145721,0.94994462); glVertex3f(0.59986523+$x,0.370386+$y,0.47969782+$z);


    glNormal3f( 0.0005034257679357,0.000591065119070598,2.74653548805112e-007);
    glTexCoord2f(0.2401844,0.91286269); glVertex3f(0.5791511+$x,0.37970512+$y,0.49091106+$z);
    glTexCoord2f(0.22640999,0.66492618); glVertex3f(0.47193838+$x,0.47099292+$y,0.55139279+$z);
    glTexCoord2f(0.24788112,0.91209021); glVertex3f(0.58067216+$x,0.37840743+$y,0.495566+$z);


    glNormal3f( 0.000319435260495798,0.000611318685770195,-0.000356445074920795);
    glTexCoord2f(0.2401844,0.91286269); glVertex3f(0.5791511+$x,0.37970512+$y,0.49091106+$z);
    glTexCoord2f(0.21793725,0.66554789); glVertex3f(0.46897864+$x,0.47018838+$y,0.54736054+$z);
    glTexCoord2f(0.22640999,0.66492618); glVertex3f(0.47193838+$x,0.47099292+$y,0.55139279+$z);


    glNormal3f( -8.39509993271993e-005,0.000432813634976599,-2.47406722187991e-005);
    glTexCoord2f(0.25145721,0.94994462); glVertex3f(0.59986523+$x,0.370386+$y,0.47969782+$z);
    glTexCoord2f(0.27443061,0.99272353); glVertex3f(0.62222256+$x,0.37407534+$y,0.46837543+$z);
    glTexCoord2f(0.23918441,0.99898814); glVertex3f(0.6118634+$x,0.3712593+$y,0.45426269+$z);


    glNormal3f( 9.67383670541995e-005,0.0001894961141968,2.12170794164996e-005);
    glTexCoord2f(0.24788112,0.91209021); glVertex3f(0.58067216+$x,0.37840743+$y,0.495566+$z);
    glTexCoord2f(0.26377122,0.94064381); glVertex3f(0.60240519+$x,0.36821901+$y,0.48747102+$z);
    glTexCoord2f(0.25145721,0.94994462); glVertex3f(0.59986523+$x,0.370386+$y,0.47969782+$z);


    glNormal3f( 0.000109829755367401,0.000141872503419101,0.000116303773080001);
    glTexCoord2f(0.24788112,0.91209021); glVertex3f(0.58067216+$x,0.37840743+$y,0.495566+$z);
    glTexCoord2f(0.27006631,0.92882801); glVertex3f(0.60186211+$x,0.36312213+$y,0.49420127+$z);
    glTexCoord2f(0.26377122,0.94064381); glVertex3f(0.60240519+$x,0.36821901+$y,0.48747102+$z);


    glNormal3f( 0.000552533535268497,0.0004124430678333,0.000356927760580494);
    glTexCoord2f(0.29063144,0.87670838); glVertex3f(0.58067216+$x,0.37840743+$y,0.495566+$z);
    glTexCoord2f(0.13717019,1.13088241); glVertex3f(0.47345943+$x,0.46969523+$y,0.55604773+$z);
    glTexCoord2f(0.28222896,0.87163527); glVertex3f(0.58034695+$x,0.37535518+$y,0.49959642+$z);


    glNormal3f( 0.000503425767935698,0.000591064560802701,2.75579403693745e-007);
    glTexCoord2f(0.24788112,0.91209021); glVertex3f(0.58067216+$x,0.37840743+$y,0.495566+$z);
    glTexCoord2f(0.22640999,0.66492618); glVertex3f(0.47193838+$x,0.47099292+$y,0.55139279+$z);
    glTexCoord2f(0.23492184,0.66432956); glVertex3f(0.47345943+$x,0.46969523+$y,0.55604773+$z);


    glNormal3f( -4.14217738209975e-006,0.000202546217935599,5.78187353557993e-005);
    glTexCoord2f(0.26377122,0.94064381); glVertex3f(0.60240519+$x,0.36821901+$y,0.48747102+$z);
    glTexCoord2f(0.30575932,0.96874291); glVertex3f(0.62754621+$x,0.36953336+$y,0.48466781+$z);
    glTexCoord2f(0.25145721,0.94994462); glVertex3f(0.59986523+$x,0.370386+$y,0.47969782+$z);


    glNormal3f( 6.57716759684996e-005,8.49605744356997e-005,6.96479573004991e-005);
    glTexCoord2f(0.25184944,0.90864643); glVertex3f(0.58034695+$x,0.37535518+$y,0.49959642+$z);
    glTexCoord2f(0.27006631,0.92882801); glVertex3f(0.60186211+$x,0.36312213+$y,0.49420127+$z);
    glTexCoord2f(0.24788112,0.91209021); glVertex3f(0.58067216+$x,0.37840743+$y,0.495566+$z);


    glNormal3f( 0.00233326026608049,0.0024947625179328,0.0036480752761956);
    glTexCoord2f(0.5323926,1.05278023); glVertex3f(0.58034695+$x,0.37535518+$y,0.49959642+$z);
    glTexCoord2f(0.50096819,0.64224089); glVertex3f(0.55328875+$x,0.22118152+$y,0.62233525+$z);
    glTexCoord2f(0.58361461,1.04214609); glVertex3f(0.60186211+$x,0.36312213+$y,0.49420127+$z);


    glNormal3f( 0.0202818833943166,0.0107997929568526,0.0196519965411006);
    glTexCoord2f(0.28222896,0.87163527); glVertex3f(0.58034695+$x,0.37535518+$y,0.49959642+$z);
    glTexCoord2f(0.12876771,1.1258093); glVertex3f(0.47313422+$x,0.46664298+$y,0.56007815+$z);
    glTexCoord2f(-0.044990658,0.67407168); glVertex3f(0.53177359+$x,0.23341456+$y,0.6277304+$z);


    glNormal3f( 0.00055253353526851,0.000412443067833309,0.000356927760580506);
    glTexCoord2f(0.28222896,0.87163527); glVertex3f(0.58034695+$x,0.37535518+$y,0.49959642+$z);
    glTexCoord2f(0.13717019,1.13088241); glVertex3f(0.47345943+$x,0.46969523+$y,0.55604773+$z);
    glTexCoord2f(0.12876771,1.1258093); glVertex3f(0.47313422+$x,0.46664298+$y,0.56007815+$z);


    glNormal3f( 5.44151135020037e-006,0.000167683122776802,0.000127427054092001);
    glTexCoord2f(0.27006631,0.92882801); glVertex3f(0.60186211+$x,0.36312213+$y,0.49420127+$z);
    glTexCoord2f(0.3183215,0.92625955); glVertex3f(0.62640795+$x,0.35885047+$y,0.49877423+$z);
    glTexCoord2f(0.26377122,0.94064381); glVertex3f(0.60240519+$x,0.36821901+$y,0.48747102+$z);


    glNormal3f( -0.000101743934898792,0.0033672802039888,0.00369154038154001);
    glTexCoord2f(0.58361461,1.04214609); glVertex3f(0.60186211+$x,0.36312213+$y,0.49420127+$z);
    glTexCoord2f(0.50096819,0.64224089); glVertex3f(0.55328875+$x,0.22118152+$y,0.62233525+$z);
    glTexCoord2f(0.63481439,1.0315657); glVertex3f(0.62640795+$x,0.35885047+$y,0.49877423+$z);


    glNormal3f( 1.14056109499005e-005,0.0003514590055338,0.0002670826791168);
    glTexCoord2f(0.3183215,0.92625955); glVertex3f(0.62640795+$x,0.35885047+$y,0.49877423+$z);
    glTexCoord2f(0.30575932,0.96874291); glVertex3f(0.62754621+$x,0.36953336+$y,0.48466781+$z);
    glTexCoord2f(0.26377122,0.94064381); glVertex3f(0.60240519+$x,0.36821901+$y,0.48747102+$z);


    glNormal3f( -0.0002104452518946,0.000311384117809798,0.000218832337750299);
    glTexCoord2f(0.3183215,0.92625955); glVertex3f(0.62640795+$x,0.35885047+$y,0.49877423+$z);
    glTexCoord2f(0.40323265,0.93370087); glVertex3f(0.64740742+$x,0.36368477+$y,0.51208997+$z);
    glTexCoord2f(0.30575932,0.96874291); glVertex3f(0.62754621+$x,0.36953336+$y,0.48466781+$z);


    glNormal3f( -0.00250948235771541,0.00333753590167699,0.00274585938722869);
    glTexCoord2f(0.3183215,0.92625955); glVertex3f(0.62640795+$x,0.35885047+$y,0.49877423+$z);
    glTexCoord2f(0.37545116,0.2402096); glVertex3f(0.57783459+$x,0.21690986+$y,0.62690821+$z);
    glTexCoord2f(0.40323265,0.93370087); glVertex3f(0.64740742+$x,0.36368477+$y,0.51208997+$z);


    glNormal3f( -8.68206029699966e-006,0.000424530557668899,0.0001211873006044);
    glTexCoord2f(0.30575932,0.96874291); glVertex3f(0.62754621+$x,0.36953336+$y,0.48466781+$z);
    glTexCoord2f(0.27443061,0.99272353); glVertex3f(0.62222256+$x,0.37407534+$y,0.46837543+$z);
    glTexCoord2f(0.25145721,0.94994462); glVertex3f(0.59986523+$x,0.370386+$y,0.47969782+$z);


    glNormal3f( -0.000360764294493901,0.000533803072683102,0.0003751422472303);
    glTexCoord2f(0.40323265,0.93370087); glVertex3f(0.64740742+$x,0.36368477+$y,0.51208997+$z);
    glTexCoord2f(0.35707571,1.01209926); glVertex3f(0.64935876+$x,0.38199834+$y,0.4879075+$z);
    glTexCoord2f(0.30575932,0.96874291); glVertex3f(0.62754621+$x,0.36953336+$y,0.48466781+$z);


    glNormal3f( -0.003638385409027,0.00309795543200901,0.002052515589885);
    glTexCoord2f(0.23079912,0.64240467); glVertex3f(0.64740742+$x,0.36368477+$y,0.51208997+$z);
    glTexCoord2f(0.46106664,0.92478693); glVertex3f(0.76667996+$x,0.43122319+$y,0.62157925+$z);
    glTexCoord2f(0.17962802,0.67228717); glVertex3f(0.64935876+$x,0.38199834+$y,0.4879075+$z);


    glNormal3f( -0.0002177987980386,0.0003381313777005,0.000165431356626);
    glTexCoord2f(0.35707571,1.01209926); glVertex3f(0.64935876+$x,0.38199834+$y,0.4879075+$z);
    glTexCoord2f(0.27443061,0.99272353); glVertex3f(0.62222256+$x,0.37407534+$y,0.46837543+$z);
    glTexCoord2f(0.30575932,0.96874291); glVertex3f(0.62754621+$x,0.36953336+$y,0.48466781+$z);


    glNormal3f( -0.0029188165428276,0.0024852679621279,0.0016465868810539);
    glTexCoord2f(0.17962802,0.67228717); glVertex3f(0.64935876+$x,0.38199834+$y,0.4879075+$z);
    glTexCoord2f(0.41739262,0.97171679); glVertex3f(0.77680271+$x,0.45369015+$y,0.60561289+$z);
    glTexCoord2f(0.12150574,0.6686286); glVertex3f(0.64023247+$x,0.38978456+$y,0.45997772+$z);


    glNormal3f( -0.000373368641015401,0.000579652760915702,0.000283596018834001);
    glTexCoord2f(0.29310666,1.04299267); glVertex3f(0.64023247+$x,0.38978456+$y,0.45997772+$z);
    glTexCoord2f(0.27443061,0.99272353); glVertex3f(0.62222256+$x,0.37407534+$y,0.46837543+$z);
    glTexCoord2f(0.35707571,1.01209926); glVertex3f(0.64935876+$x,0.38199834+$y,0.4879075+$z);


    glNormal3f( -0.000843032866556001,0.000717811242081295,0.000475579147396904);
    glTexCoord2f(0.12150574,0.6686286); glVertex3f(0.64023247+$x,0.38978456+$y,0.45997772+$z);
    glTexCoord2f(0.41739262,0.97171679); glVertex3f(0.77680271+$x,0.45369015+$y,0.60561289+$z);
    glTexCoord2f(0.071791846,0.6338303); glVertex3f(0.62247392+$x,0.38495707+$y,0.43578445+$z);


    glNormal3f( -0.0042448110164872,0.0024135020687903,0.0010644271630967);
    glTexCoord2f(0.077525062,-0.093088169); glVertex3f(0.38770856+$x,0.10932305+$y,0.4356553+$z);
    glTexCoord2f(0.11061356,-0.062185449); glVertex3f(0.39953487+$x,0.12196798+$y,0.45414589+$z);
    glTexCoord2f(-0.16659349,0.16494389); glVertex3f(0.43628191+$x,0.25126367+$y,0.30752132+$z);


    glNormal3f( -0.0003759082551661,0.0001878746012216,0.0001119459344417);
    glTexCoord2f(0.077525062,-0.093088169); glVertex3f(0.38770856+$x,0.10932305+$y,0.4356553+$z);
    glTexCoord2f(0.13922046,-0.07713524); glVertex3f(0.39839659+$x,0.11128507+$y,0.46825233+$z);
    glTexCoord2f(0.11061356,-0.062185449); glVertex3f(0.39953487+$x,0.12196798+$y,0.45414589+$z);


    glNormal3f( -0.00064441449346333,0.000322071072444299,0.00019190740852813);
    glTexCoord2f(0.077525062,-0.093088169); glVertex3f(0.38770856+$x,0.10932305+$y,0.4356553+$z);
    glTexCoord2f(0.12496866,-0.12125842); glVertex3f(0.38575721+$x,0.091009479+$y,0.45983776+$z);
    glTexCoord2f(0.13922046,-0.07713524); glVertex3f(0.39839659+$x,0.11128507+$y,0.46825233+$z);


    glNormal3f( -0.00188264575488893,0.0016030062058317,0.00106205353674262);
    glTexCoord2f(0.077525062,-0.093088169); glVertex3f(0.38770856+$x,0.10932305+$y,0.4356553+$z);
    glTexCoord2f(-0.024731059,-0.219187); glVertex3f(0.32531259+$x,0.067998075+$y,0.38742297+$z);
    glTexCoord2f(0.12496866,-0.12125842); glVertex3f(0.38575721+$x,0.091009479+$y,0.45983776+$z);


    glNormal3f( -0.0048427359900066,0.000842766801184201,-0.000902220600281399);
    glTexCoord2f(0.11061356,-0.062185449); glVertex3f(0.39953487+$x,0.12196798+$y,0.45414589+$z);
    glTexCoord2f(0.14259279,-0.032184403); glVertex3f(0.39901914+$x,0.13903531+$y,0.47285675+$z);
    glTexCoord2f(-0.09575802,0.23096525); glVertex3f(0.4475925+$x,0.28097593+$y,0.34472277+$z);


    glNormal3f( -0.0004406457000078,1.40230834196e-005,-2.49368975666998e-005);
    glTexCoord2f(0.11061356,-0.062185449); glVertex3f(0.39953487+$x,0.12196798+$y,0.45414589+$z);
    glTexCoord2f(0.13922046,-0.07713524); glVertex3f(0.39839659+$x,0.11128507+$y,0.46825233+$z);
    glTexCoord2f(0.14259279,-0.032184403); glVertex3f(0.39901914+$x,0.13903531+$y,0.47285675+$z);


    glNormal3f( -0.0041430654772764,-0.000953777293862597,-0.0026271118745837);
    glTexCoord2f(0.14259279,-0.032184403); glVertex3f(0.39901914+$x,0.13903531+$y,0.47285675+$z);
    glTexCoord2f(0.17514342,-0.0043357067); glVertex3f(0.38629962+$x,0.1559519+$y,0.48677437+$z);
    glTexCoord2f(-0.059605702,0.26246179); glVertex3f(0.43487297+$x,0.29789251+$y,0.35864039+$z);


    glNormal3f( -0.0001847903038788,-7.80480827388004e-005,-7.40167176581996e-005);
    glTexCoord2f(0.14259279,-0.032184403); glVertex3f(0.39901914+$x,0.13903531+$y,0.47285675+$z);
    glTexCoord2f(0.15311488,-0.039025929); glVertex3f(0.39847608+$x,0.13393842+$y,0.47958705+$z);
    glTexCoord2f(0.17514342,-0.0043357067); glVertex3f(0.38629962+$x,0.1559519+$y,0.48677437+$z);


    glNormal3f( -0.0202818840708391,-0.0107997922803301,-0.0196519936224227);
    glTexCoord2f(0.17514342,-0.0043357067); glVertex3f(0.38629962+$x,0.1559519+$y,0.48677437+$z);
    glTexCoord2f(0.15859616,0.44373297); glVertex3f(0.32766025+$x,0.38918032+$y,0.41912212+$z);
    glTexCoord2f(-0.059605702,0.26246179); glVertex3f(0.43487297+$x,0.29789251+$y,0.35864039+$z);


    glNormal3f( -0.0202818833943166,-0.0107997929568526,-0.0196519965411006);
    glTexCoord2f(0.17514342,-0.0043357067); glVertex3f(0.38629962+$x,0.1559519+$y,0.48677437+$z);
    glTexCoord2f(0.38809463,0.16698811); glVertex3f(0.27908689+$x,0.2472397+$y,0.5472561+$z);
    glTexCoord2f(0.15859616,0.44373297); glVertex3f(0.32766025+$x,0.38918032+$y,0.41912212+$z);


    glNormal3f( -0.000552533535268498,-0.0004124430678333,-0.000356927760580498);
    glTexCoord2f(0.17514342,-0.0043357067); glVertex3f(0.38629962+$x,0.1559519+$y,0.48677437+$z);
    glTexCoord2f(0.39387684,0.15989986); glVertex3f(0.27876168+$x,0.24418745+$y,0.55128652+$z);
    glTexCoord2f(0.38809463,0.16698811); glVertex3f(0.27908689+$x,0.2472397+$y,0.5472561+$z);


    glNormal3f( 0.0023332590386922,0.0024947625179328,0.0036480750056136);
    glTexCoord2f(0.44924371,0.65376491); glVertex3f(0.53177359+$x,0.23341456+$y,0.6277304+$z);
    glTexCoord2f(0.50096819,0.64224089); glVertex3f(0.55328875+$x,0.22118152+$y,0.62233525+$z);
    glTexCoord2f(0.5323926,1.05278023); glVertex3f(0.58034695+$x,0.37535518+$y,0.49959642+$z);


    glNormal3f( 8.34507754524006e-005,6.47867914531009e-005,0.0001858923986664);
    glTexCoord2f(0.44924371,0.65376491); glVertex3f(0.53177359+$x,0.23341456+$y,0.6277304+$z);
    glTexCoord2f(0.49570318,0.622916); glVertex3f(0.54980816+$x,0.21452044+$y,0.62621926+$z);
    glTexCoord2f(0.50096819,0.64224089); glVertex3f(0.55328875+$x,0.22118152+$y,0.62233525+$z);


    glNormal3f( 0.000453587036675193,0.000123301462091492,0.000617945023239698);
    glTexCoord2f(0.44924371,0.65376491); glVertex3f(0.53177359+$x,0.23341456+$y,0.6277304+$z);
    glTexCoord2f(0.12130322,0.78972115); glVertex3f(0.42456086+$x,0.32470237+$y,0.68821213+$z);
    glTexCoord2f(0.44488912,0.64318019); glVertex3f(0.52968923+$x,0.22942559+$y,0.63005631+$z);


    glNormal3f( 0.0202818840708391,0.0107997929568526,0.0196519959547069);
    glTexCoord2f(-0.044990658,0.67407168); glVertex3f(0.53177359+$x,0.23341456+$y,0.6277304+$z);
    glTexCoord2f(0.12876771,1.1258093); glVertex3f(0.47313422+$x,0.46664298+$y,0.56007815+$z);
    glTexCoord2f(-0.19845191,0.92824571); glVertex3f(0.42456086+$x,0.32470237+$y,0.68821213+$z);


    glNormal3f( -0.000101743934898796,0.0033672802039888,0.00369154038154);
    glTexCoord2f(0.50096819,0.64224089); glVertex3f(0.55328875+$x,0.22118152+$y,0.62233525+$z);
    glTexCoord2f(0.55242522,0.63305884); glVertex3f(0.57783459+$x,0.21690986+$y,0.62690821+$z);
    glTexCoord2f(0.63481439,1.0315657); glVertex3f(0.62640795+$x,0.35885047+$y,0.49877423+$z);


    glNormal3f( -1.38696822401995e-005,0.000111252886864801,0.0001783697009866);
    glTexCoord2f(0.50096819,0.64224089); glVertex3f(0.55328875+$x,0.22118152+$y,0.62233525+$z);
    glTexCoord2f(0.49570318,0.622916); glVertex3f(0.54980816+$x,0.21452044+$y,0.62621926+$z);
    glTexCoord2f(0.55242522,0.63305884); glVertex3f(0.57783459+$x,0.21690986+$y,0.62690821+$z);


    glNormal3f( -0.0025094823577154,0.00333753704985939,0.0027458608549778);
    glTexCoord2f(0.37545116,0.2402096); glVertex3f(0.57783459+$x,0.21690986+$y,0.62690821+$z);
    glTexCoord2f(0.46359699,0.24778148); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);
    glTexCoord2f(0.40323265,0.93370087); glVertex3f(0.64740742+$x,0.36368477+$y,0.51208997+$z);


    glNormal3f( -0.000225261006789001,0.000268092062751001,0.000257914809683);
    glTexCoord2f(0.37545116,0.2402096); glVertex3f(0.57783459+$x,0.21690986+$y,0.62690821+$z);
    glTexCoord2f(0.36502869,0.17891107); glVertex3f(0.57053936+$x,0.20294846+$y,0.63504892+$z);
    glTexCoord2f(0.46359699,0.24778148); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);


    glNormal3f( -0.000386161627864599,0.000459586319838299,0.000442139404365198);
    glTexCoord2f(0.46359699,0.24778148); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);
    glTexCoord2f(0.36502869,0.17891107); glVertex3f(0.57053936+$x,0.20294846+$y,0.63504892+$z);
    glTexCoord2f(0.44611671,0.14282189); glVertex3f(0.58632796+$x,0.19781034+$y,0.65417945+$z);


    glNormal3f( -0.0235113109828982,0.0200190397448644,0.0132633948907943);
    glTexCoord2f(0.52988056,0.34243862); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);
    glTexCoord2f(0.48474348,0.89188196); glVertex3f(0.7589951+$x,0.4167062+$y,0.62986785+$z);
    glTexCoord2f(0.23079912,0.64240467); glVertex3f(0.64740742+$x,0.36368477+$y,0.51208997+$z);


    glNormal3f( -0.000210235662525801,6.69042459019994e-006,-1.18969764648996e-005);
    glTexCoord2f(0.13922046,-0.07713524); glVertex3f(0.39839659+$x,0.11128507+$y,0.46825233+$z);
    glTexCoord2f(0.15311488,-0.039025929); glVertex3f(0.39847608+$x,0.13393842+$y,0.47958705+$z);
    glTexCoord2f(0.14259279,-0.032184403); glVertex3f(0.39901914+$x,0.13903531+$y,0.47285675+$z);


    glNormal3f( -0.00036855586814196,0.0001611289352649,0.00016534811392377);
    glTexCoord2f(0.12496866,-0.12125842); glVertex3f(0.38575721+$x,0.091009479+$y,0.45983776+$z);
    glTexCoord2f(0.17234886,-0.076605496); glVertex3f(0.40372026+$x,0.10674311+$y,0.48454469+$z);
    glTexCoord2f(0.13922046,-0.07713524); glVertex3f(0.39839659+$x,0.11128507+$y,0.46825233+$z);


    glNormal3f( -0.00063181047873744,0.0002762213590005,0.000283454005951049);
    glTexCoord2f(0.12496866,-0.12125842); glVertex3f(0.38575721+$x,0.091009479+$y,0.45983776+$z);
    glTexCoord2f(0.18277717,-0.12158945); glVertex3f(0.39488351+$x,0.083223264+$y,0.48776755+$z);
    glTexCoord2f(0.17234886,-0.076605496); glVertex3f(0.40372026+$x,0.10674311+$y,0.48454469+$z);


    glNormal3f( -0.00194495737964427,0.0016560617770233,0.00109720544203995);
    glTexCoord2f(0.12496866,-0.12125842); glVertex3f(0.38575721+$x,0.091009479+$y,0.45983776+$z);
    glTexCoord2f(0.054156923,-0.2888844); glVertex3f(0.31742004+$x,0.029087611+$y,0.43216159+$z);
    glTexCoord2f(0.18277717,-0.12158945); glVertex3f(0.39488351+$x,0.083223264+$y,0.48776755+$z);


    glNormal3f( -0.0004205584696936,-5.90472945145996e-005,0.0001209600118436);
    glTexCoord2f(0.17234886,-0.076605496); glVertex3f(0.40372026+$x,0.10674311+$y,0.48454469+$z);
    glTexCoord2f(0.16370339,-0.041803114); glVertex3f(0.40101603+$x,0.13177143+$y,0.48736023+$z);
    glTexCoord2f(0.13922046,-0.07713524); glVertex3f(0.39839659+$x,0.11128507+$y,0.46825233+$z);


    glNormal3f( -0.000164740368289,-3.21240012211998e-005,0.0001273339878341);
    glTexCoord2f(0.17234886,-0.076605496); glVertex3f(0.40372026+$x,0.10674311+$y,0.48454469+$z);
    glTexCoord2f(0.17347263,-0.034060158); glVertex3f(0.40595846+$x,0.13311498+$y,0.49409353+$z);
    glTexCoord2f(0.16370339,-0.041803114); glVertex3f(0.40101603+$x,0.13177143+$y,0.48736023+$z);


    glNormal3f( -0.00034100558005216,0.000158097022099,0.0002187611479559);
    glTexCoord2f(0.18277717,-0.12158945); glVertex3f(0.39488351+$x,0.083223264+$y,0.48776755+$z);
    glTexCoord2f(0.20162976,-0.058793277); glVertex3f(0.41407941+$x,0.10955913+$y,0.49865745+$z);
    glTexCoord2f(0.17234886,-0.076605496); glVertex3f(0.40372026+$x,0.10674311+$y,0.48454469+$z);


    glNormal3f( -0.00104128453136023,0.000886617078487298,0.00058741758170572);
    glTexCoord2f(0.18277717,-0.12158945); glVertex3f(0.39488351+$x,0.083223264+$y,0.48776755+$z);
    glTexCoord2f(0.054156923,-0.2888844); glVertex3f(0.31742004+$x,0.029087611+$y,0.43216159+$z);
    glTexCoord2f(0.23542603,-0.094044842); glVertex3f(0.41264205+$x,0.088050734+$y,0.51196086+$z);


    glNormal3f( -0.000584581104703459,0.000271023634682999,0.00037501889842264);
    glTexCoord2f(0.23542603,-0.094044842); glVertex3f(0.41264205+$x,0.088050734+$y,0.51196086+$z);
    glTexCoord2f(0.20162976,-0.058793277); glVertex3f(0.41407941+$x,0.10955913+$y,0.49865745+$z);
    glTexCoord2f(0.18277717,-0.12158945); glVertex3f(0.39488351+$x,0.083223264+$y,0.48776755+$z);


    glNormal3f( -0.00369560075735564,0.0019449392599647,0.00274520706305188);
    glTexCoord2f(0.23542603,-0.094044842); glVertex3f(0.41264205+$x,0.088050734+$y,0.51196086+$z);
    glTexCoord2f(0.49033065,0.19661055); glVertex3f(0.54642304+$x,0.18003009+$y,0.62689094+$z);
    glTexCoord2f(0.20162976,-0.058793277); glVertex3f(0.41407941+$x,0.10955913+$y,0.49865745+$z);


    glNormal3f( -0.0036955991479816,0.001944936772854,0.0027452071801595);
    glTexCoord2f(0.23542603,-0.094044842); glVertex3f(0.41264205+$x,0.088050734+$y,0.51196086+$z);
    glTexCoord2f(0.52332412,0.15976283); glVertex3f(0.54498569+$x,0.1585217+$y,0.64019434+$z);
    glTexCoord2f(0.49033065,0.19661055); glVertex3f(0.54642304+$x,0.18003009+$y,0.62689094+$z);


    glNormal3f( -0.00173719892442526,0.0014791622428336,0.000980003326271062);
    glTexCoord2f(0.23542603,-0.094044842); glVertex3f(0.41264205+$x,0.088050734+$y,0.51196086+$z);
    glTexCoord2f(0.65992368,0.24683425); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);
    glTexCoord2f(0.52332412,0.15976283); glVertex3f(0.54498569+$x,0.1585217+$y,0.64019434+$z);


    glNormal3f( -0.00394873430442526,0.0033622046614624,0.00222759344062099);
    glTexCoord2f(0.23542603,-0.094044842); glVertex3f(0.41264205+$x,0.088050734+$y,0.51196086+$z);
    glTexCoord2f(0.054156923,-0.2888844); glVertex3f(0.31742004+$x,0.029087611+$y,0.43216159+$z);
    glTexCoord2f(0.65992368,0.24683425); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);


    glNormal3f( -0.0003452901476444,-6.73306864539995e-005,0.000266887341146499);
    glTexCoord2f(0.20162976,-0.058793277); glVertex3f(0.41407941+$x,0.10955913+$y,0.49865745+$z);
    glTexCoord2f(0.17347263,-0.034060158); glVertex3f(0.40595846+$x,0.13311498+$y,0.49409353+$z);
    glTexCoord2f(0.17234886,-0.076605496); glVertex3f(0.40372026+$x,0.10674311+$y,0.48454469+$z);


    glNormal3f( -0.0033422726791797,-0.000437372020785896,0.0036897578393475);
    glTexCoord2f(0.2545386,0.26567596); glVertex3f(0.41407941+$x,0.10955913+$y,0.49865745+$z);
    glTexCoord2f(0.51049285,0.55550037); glVertex3f(0.54642304+$x,0.18003009+$y,0.62689094+$z);
    glTexCoord2f(0.21729709,0.29853891); glVertex3f(0.40595846+$x,0.13311498+$y,0.49409353+$z);


    glNormal3f( -0.0002006507920458,-2.81717319858001e-005,5.77106303676003e-005);
    glTexCoord2f(0.16370339,-0.041803114); glVertex3f(0.40101603+$x,0.13177143+$y,0.48736023+$z);
    glTexCoord2f(0.15311488,-0.039025929); glVertex3f(0.39847608+$x,0.13393842+$y,0.47958705+$z);
    glTexCoord2f(0.13922046,-0.07713524); glVertex3f(0.39839659+$x,0.11128507+$y,0.46825233+$z);


    glNormal3f( -0.000171697784214,-0.0001256702299236,2.10695822652001e-005);
    glTexCoord2f(0.16370339,-0.041803114); glVertex3f(0.40101603+$x,0.13177143+$y,0.48736023+$z);
    glTexCoord2f(0.18061014,-0.011198091); glVertex3f(0.38597441+$x,0.15289965+$y,0.49080479+$z);
    glTexCoord2f(0.15311488,-0.039025929); glVertex3f(0.39847608+$x,0.13393842+$y,0.47958705+$z);


    glNormal3f( -0.000122642595554,-0.0001310694992806,0.0001161764468095);
    glTexCoord2f(0.56384219,0.82871369); glVertex3f(0.40595846+$x,0.13311498+$y,0.49409353+$z);
    glTexCoord2f(0.60824494,0.80426531); glVertex3f(0.38749544+$x,0.15160193+$y,0.49545975+$z);
    glTexCoord2f(0.57519029,0.84053991); glVertex3f(0.40101603+$x,0.13177143+$y,0.48736023+$z);


    glNormal3f( -0.0020933893417916,-0.0027024836163968,0.0036456421541524);
    glTexCoord2f(0.21729709,0.29853891); glVertex3f(0.40595846+$x,0.13311498+$y,0.49409353+$z);
    glTexCoord2f(0.47429697,0.58961951); glVertex3f(0.5383021+$x,0.20358594+$y,0.62232701+$z);
    glTexCoord2f(0.17998306,0.3313833); glVertex3f(0.39045522+$x,0.15240653+$y,0.49949197+$z);


    glNormal3f( -0.0033422731483308,-0.000437369288165997,0.0036897573701964);
    glTexCoord2f(0.21729709,0.29853891); glVertex3f(0.40595846+$x,0.13311498+$y,0.49409353+$z);
    glTexCoord2f(0.51049285,0.55550037); glVertex3f(0.54642304+$x,0.18003009+$y,0.62689094+$z);
    glTexCoord2f(0.47429697,0.58961951); glVertex3f(0.5383021+$x,0.20358594+$y,0.62232701+$z);


    glNormal3f( -7.34441889170006e-005,-7.84906691360004e-005,6.95726507629997e-005);
    glTexCoord2f(0.60144913,0.7971832); glVertex3f(0.39045522+$x,0.15240653+$y,0.49949197+$z);
    glTexCoord2f(0.60824494,0.80426531); glVertex3f(0.38749544+$x,0.15160193+$y,0.49545975+$z);
    glTexCoord2f(0.56384219,0.82871369); glVertex3f(0.40595846+$x,0.13311498+$y,0.49409353+$z);


    glNormal3f( -0.00209338882999751,-0.0027024850948656,0.0036456421541524);
    glTexCoord2f(0.17998306,0.3313833); glVertex3f(0.39045522+$x,0.15240653+$y,0.49949197+$z);
    glTexCoord2f(0.47429697,0.58961951); glVertex3f(0.5383021+$x,0.20358594+$y,0.62232701+$z);
    glTexCoord2f(0.4357254,0.62228429); glVertex3f(0.52279886+$x,0.22287749+$y,0.62772546+$z);


    glNormal3f( -0.000319428892958001,-0.000611317928980002,0.000356455167242);
    glTexCoord2f(0.60144913,0.7971832); glVertex3f(0.39045522+$x,0.15240653+$y,0.49949197+$z);
    glTexCoord2f(0.81568094,0.59161198); glVertex3f(0.28324249+$x,0.24369433+$y,0.5599737+$z);
    glTexCoord2f(0.60824494,0.80426531); glVertex3f(0.38749544+$x,0.15160193+$y,0.49545975+$z);


    glNormal3f( -0.0001028210933744,-7.5257418532e-005,1.26168453602007e-005);
    glTexCoord2f(0.18548083,-0.015874424); glVertex3f(0.38749544+$x,0.15160193+$y,0.49545975+$z);
    glTexCoord2f(0.18061014,-0.011198091); glVertex3f(0.38597441+$x,0.15289965+$y,0.49080479+$z);
    glTexCoord2f(0.16370339,-0.041803114); glVertex3f(0.40101603+$x,0.13177143+$y,0.48736023+$z);


    glNormal3f( -0.000503429408143598,-0.000591065495422701,-2.80621541597775e-007);
    glTexCoord2f(0.60824494,0.80426531); glVertex3f(0.38749544+$x,0.15160193+$y,0.49545975+$z);
    glTexCoord2f(0.82247673,0.59869411); glVertex3f(0.28028271+$x,0.24288973+$y,0.55594148+$z);
    glTexCoord2f(0.6150407,0.81134737); glVertex3f(0.38597441+$x,0.15289965+$y,0.49080479+$z);


    glNormal3f( -0.000319428892958004,-0.000611317928980005,0.000356455167242001);
    glTexCoord2f(0.60824494,0.80426531); glVertex3f(0.38749544+$x,0.15160193+$y,0.49545975+$z);
    glTexCoord2f(0.81568094,0.59161198); glVertex3f(0.28324249+$x,0.24369433+$y,0.5599737+$z);
    glTexCoord2f(0.82247673,0.59869411); glVertex3f(0.28028271+$x,0.24288973+$y,0.55594148+$z);


    glNormal3f( -0.0001106610675316,-4.67388595759996e-005,-4.43246038658005e-005);
    glTexCoord2f(0.15311488,-0.039025929); glVertex3f(0.39847608+$x,0.13393842+$y,0.47958705+$z);
    glTexCoord2f(0.18061014,-0.011198091); glVertex3f(0.38597441+$x,0.15289965+$y,0.49080479+$z);
    glTexCoord2f(0.17514342,-0.0043357067); glVertex3f(0.38629962+$x,0.1559519+$y,0.48677437+$z);


    glNormal3f( -0.000552533535268499,-0.000412443067833296,-0.000356927760580503);
    glTexCoord2f(0.18061014,-0.011198091); glVertex3f(0.38597441+$x,0.15289965+$y,0.49080479+$z);
    glTexCoord2f(0.39387684,0.15989986); glVertex3f(0.27876168+$x,0.24418745+$y,0.55128652+$z);
    glTexCoord2f(0.17514342,-0.0043357067); glVertex3f(0.38629962+$x,0.1559519+$y,0.48677437+$z);


    glNormal3f( -0.000503429408143599,-0.000591065495422697,-2.80621541602139e-007);
    glTexCoord2f(0.6150407,0.81134737); glVertex3f(0.38597441+$x,0.15289965+$y,0.49080479+$z);
    glTexCoord2f(0.82247673,0.59869411); glVertex3f(0.28028271+$x,0.24288973+$y,0.55594148+$z);
    glTexCoord2f(0.82927248,0.6057762); glVertex3f(0.27876168+$x,0.24418745+$y,0.55128652+$z);


    glNormal3f( 4.99739147749985e-005,3.87970269382988e-005,0.0001113215066561);
    glTexCoord2f(0.44488912,0.64318019); glVertex3f(0.52968923+$x,0.22942559+$y,0.63005631+$z);
    glTexCoord2f(0.49570318,0.622916); glVertex3f(0.54980816+$x,0.21452044+$y,0.62621926+$z);
    glTexCoord2f(0.44924371,0.65376491); glVertex3f(0.53177359+$x,0.23341456+$y,0.6277304+$z);


    glNormal3f( 1.47720970225006e-005,-1.26408465829984e-005,0.0001265588148175);
    glTexCoord2f(0.44488912,0.64318019); glVertex3f(0.52968923+$x,0.22942559+$y,0.63005631+$z);
    glTexCoord2f(0.44036072,0.63265383); glVertex3f(0.52640425+$x,0.22556874+$y,0.63005451+$z);
    glTexCoord2f(0.49570318,0.622916); glVertex3f(0.54980816+$x,0.21452044+$y,0.62621926+$z);


    glNormal3f( 0.000233104603742007,-0.000198874223479593,0.000713382014944501);
    glTexCoord2f(0.44488912,0.64318019); glVertex3f(0.52968923+$x,0.22942559+$y,0.63005631+$z);
    glTexCoord2f(0.11790124,0.78053186); glVertex3f(0.4224765+$x,0.32071339+$y,0.69053803+$z);
    glTexCoord2f(0.44036072,0.63265383); glVertex3f(0.52640425+$x,0.22556874+$y,0.63005451+$z);


    glNormal3f( 0.000453586665465601,0.000123300410807799,0.000617946074523404);
    glTexCoord2f(0.44488912,0.64318019); glVertex3f(0.52968923+$x,0.22942559+$y,0.63005631+$z);
    glTexCoord2f(0.12130322,0.78972115); glVertex3f(0.42456086+$x,0.32470237+$y,0.68821213+$z);
    glTexCoord2f(0.11790124,0.78053186); glVertex3f(0.4224765+$x,0.32071339+$y,0.69053803+$z);


    glNormal3f( -2.90702818181989e-005,0.000233181087673801,0.000373856831335401);
    glTexCoord2f(0.49570318,0.622916); glVertex3f(0.54980816+$x,0.21452044+$y,0.62621926+$z);
    glTexCoord2f(0.54419838,0.60393294); glVertex3f(0.57053936+$x,0.20294846+$y,0.63504892+$z);
    glTexCoord2f(0.55242522,0.63305884); glVertex3f(0.57783459+$x,0.21690986+$y,0.62690821+$z);


    glNormal3f( 2.46671828084995e-005,-2.11092160748e-005,0.000211336804214299);
    glTexCoord2f(0.44036072,0.63265383); glVertex3f(0.52640425+$x,0.22556874+$y,0.63005451+$z);
    glTexCoord2f(0.4865583,0.60506702); glVertex3f(0.54432265+$x,0.20808001+$y,0.62621623+$z);
    glTexCoord2f(0.49570318,0.622916); glVertex3f(0.54980816+$x,0.21452044+$y,0.62621926+$z);


    glNormal3f( -5.07680194910004e-005,-9.27971563020004e-005,0.0001858183172895);
    glTexCoord2f(0.44036072,0.63265383); glVertex3f(0.52640425+$x,0.22556874+$y,0.63005451+$z);
    glTexCoord2f(0.47429697,0.58961951); glVertex3f(0.5383021+$x,0.20358594+$y,0.62232701+$z);
    glTexCoord2f(0.4865583,0.60506702); glVertex3f(0.54432265+$x,0.20808001+$y,0.62621623+$z);


    glNormal3f( -4.98424216400055e-005,-0.000467763997277309,0.000617664380854501);
    glTexCoord2f(0.44036072,0.63265383); glVertex3f(0.52640425+$x,0.22556874+$y,0.63005451+$z);
    glTexCoord2f(0.10958898,0.76263806); glVertex3f(0.41558613+$x,0.31416529+$y,0.68820718+$z);
    glTexCoord2f(0.4357254,0.62228429); glVertex3f(0.52279886+$x,0.22287749+$y,0.62772546+$z);


    glNormal3f( 0.000233104950353298,-0.0001988731842021,0.000713380975666997);
    glTexCoord2f(0.44036072,0.63265383); glVertex3f(0.52640425+$x,0.22556874+$y,0.63005451+$z);
    glTexCoord2f(0.11790124,0.78053186); glVertex3f(0.4224765+$x,0.32071339+$y,0.69053803+$z);
    glTexCoord2f(0.11396279,0.77144786); glVertex3f(0.41919152+$x,0.31685655+$y,0.69053624+$z);


    glNormal3f( -5.69018702531999e-005,4.83723726905992e-005,0.0001969960544258);
    glTexCoord2f(0.4865583,0.60506702); glVertex3f(0.54432265+$x,0.20808001+$y,0.62621623+$z);
    glTexCoord2f(0.54419838,0.60393294); glVertex3f(0.57053936+$x,0.20294846+$y,0.63504892+$z);
    glTexCoord2f(0.49570318,0.622916); glVertex3f(0.54980816+$x,0.21452044+$y,0.62621926+$z);


    glNormal3f( -3.04024059650014e-005,-5.55713387675009e-005,0.000111276656104501);
    glTexCoord2f(0.4357254,0.62228429); glVertex3f(0.52279886+$x,0.22287749+$y,0.62772546+$z);
    glTexCoord2f(0.47429697,0.58961951); glVertex3f(0.5383021+$x,0.20358594+$y,0.62232701+$z);
    glTexCoord2f(0.44036072,0.63265383); glVertex3f(0.52640425+$x,0.22556874+$y,0.63005451+$z);


    glNormal3f( -0.00744394761286119,-0.0217526348420249,0.0196367437469128);
    glTexCoord2f(0.33679998,0.52138456); glVertex3f(0.52279886+$x,0.22287749+$y,0.62772546+$z);
    glTexCoord2f(0.81568094,0.59161198); glVertex3f(0.28324249+$x,0.24369433+$y,0.5599737+$z);
    glTexCoord2f(0.60144913,0.7971832); glVertex3f(0.39045522+$x,0.15240653+$y,0.49949197+$z);


    glNormal3f( -0.000112124503832101,-4.10675350530006e-006,0.0001783152455433);
    glTexCoord2f(0.47429697,0.58961951); glVertex3f(0.5383021+$x,0.20358594+$y,0.62232701+$z);
    glTexCoord2f(0.51049285,0.55550037); glVertex3f(0.54642304+$x,0.18003009+$y,0.62689094+$z);
    glTexCoord2f(0.4865583,0.60506702); glVertex3f(0.54432265+$x,0.20808001+$y,0.62621623+$z);


    glNormal3f( -0.000235008520730398,-8.60754612449993e-006,0.000373743633069599);
    glTexCoord2f(0.51049285,0.55550037); glVertex3f(0.54642304+$x,0.18003009+$y,0.62689094+$z);
    glTexCoord2f(0.52820421,0.57700098); glVertex3f(0.55904194+$x,0.18944953+$y,0.63504259+$z);
    glTexCoord2f(0.4865583,0.60506702); glVertex3f(0.54432265+$x,0.20808001+$y,0.62621623+$z);


    glNormal3f( -0.0003006397539027,0.000179591418336,0.0002578732405086);
    glTexCoord2f(0.49033065,0.19661055); glVertex3f(0.54642304+$x,0.18003009+$y,0.62689094+$z);
    glTexCoord2f(0.5543614,0.21015848); glVertex3f(0.56661808+$x,0.1746693+$y,0.65416862+$z);
    glTexCoord2f(0.50852253,0.22507882); glVertex3f(0.55904194+$x,0.18944953+$y,0.63504259+$z);


    glNormal3f( -0.0001192643467332,0.000101387194885499,0.000412897118721301);
    glTexCoord2f(0.52820421,0.57700098); glVertex3f(0.55904194+$x,0.18944953+$y,0.63504259+$z);
    glTexCoord2f(0.54419838,0.60393294); glVertex3f(0.57053936+$x,0.20294846+$y,0.63504892+$z);
    glTexCoord2f(0.4865583,0.60506702); glVertex3f(0.54432265+$x,0.20808001+$y,0.62621623+$z);


    glNormal3f( -0.0005153822460492,0.000307870268484,0.000442068127892102);
    glTexCoord2f(0.52332412,0.15976283); glVertex3f(0.54498569+$x,0.1585217+$y,0.64019434+$z);
    glTexCoord2f(0.5543614,0.21015848); glVertex3f(0.56661808+$x,0.1746693+$y,0.65416862+$z);
    glTexCoord2f(0.49033065,0.19661055); glVertex3f(0.54642304+$x,0.18003009+$y,0.62689094+$z);


    glNormal3f( -0.000710624323720002,0.000605071112343104,0.000400883352883);
    glTexCoord2f(0.52332412,0.15976283); glVertex3f(0.54498569+$x,0.1585217+$y,0.64019434+$z);
    glTexCoord2f(0.65992368,0.24683425); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);
    glTexCoord2f(0.5543614,0.21015848); glVertex3f(0.56661808+$x,0.1746693+$y,0.65416862+$z);


    glNormal3f( -0.000442756295162101,0.000376889706580199,0.000466636318458001);
    glTexCoord2f(0.5598865,0.54263255); glVertex3f(0.56661808+$x,0.1746693+$y,0.65416862+$z);
    glTexCoord2f(0.59033352,0.58974061); glVertex3f(0.58632796+$x,0.19781034+$y,0.65417945+$z);
    glTexCoord2f(0.52820421,0.57700098); glVertex3f(0.55904194+$x,0.18944953+$y,0.63504259+$z);


    glNormal3f( -0.0011011986432702,0.000937631382628799,0.0006212173915128);
    glTexCoord2f(0.5543614,0.21015848); glVertex3f(0.56661808+$x,0.1746693+$y,0.65416862+$z);
    glTexCoord2f(0.65992368,0.24683425); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);
    glTexCoord2f(0.55514637,0.27808808); glVertex3f(0.58632796+$x,0.19781034+$y,0.65417945+$z);


    glNormal3f( -0.0002582742096325,0.000219851796394601,0.000272204329848399);
    glTexCoord2f(0.59033352,0.58974061); glVertex3f(0.58632796+$x,0.19781034+$y,0.65417945+$z);
    glTexCoord2f(0.54419838,0.60393294); glVertex3f(0.57053936+$x,0.20294846+$y,0.63504892+$z);
    glTexCoord2f(0.52820421,0.57700098); glVertex3f(0.55904194+$x,0.18944953+$y,0.63504259+$z);


    glNormal3f( -0.000855897518428799,0.000728766451197401,0.000482835910630201);
    glTexCoord2f(0.55514637,0.27808808); glVertex3f(0.58632796+$x,0.19781034+$y,0.65417945+$z);
    glTexCoord2f(0.61257294,0.37166365); glVertex3f(0.62038135+$x,0.2243727+$y,0.67445229+$z);
    glTexCoord2f(0.52988056,0.34243862); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);


    glNormal3f( -4.98427260787977e-005,-0.000467765105458499,0.000617665489035702);
    glTexCoord2f(0.11396279,0.77144786); glVertex3f(0.41919152+$x,0.31685655+$y,0.69053624+$z);
    glTexCoord2f(0.10958898,0.76263806); glVertex3f(0.41558613+$x,0.31416529+$y,0.68820718+$z);
    glTexCoord2f(0.44036072,0.63265383); glVertex3f(0.52640425+$x,0.22556874+$y,0.63005451+$z);


    glNormal3f( -6.08043548539987e-006,-1.1114339472e-005,2.22552955020999e-005);
    glTexCoord2f(0.11396279,0.77144786); glVertex3f(0.41919152+$x,0.31685655+$y,0.69053624+$z);
    glTexCoord2f(0.1061502,0.75915265); glVertex3f(0.41248548+$x,0.31802358+$y,0.68928688+$z);
    glTexCoord2f(0.10958898,0.76263806); glVertex3f(0.41558613+$x,0.31416529+$y,0.68820718+$z);


    glNormal3f( -5.26581869619979e-006,-9.62525261759952e-006,1.92737339494999e-005);
    glTexCoord2f(0.11396279,0.77144786); glVertex3f(0.41919152+$x,0.31685655+$y,0.69053624+$z);
    glTexCoord2f(0.10966522,0.77175621); glVertex3f(0.41560785+$x,0.32035429+$y,0.6913039+$z);
    glTexCoord2f(0.1061502,0.75915265); glVertex3f(0.41248548+$x,0.31802358+$y,0.68928688+$z);


    glNormal3f( -0.00744394740469279,-0.0217526324464612,0.0196367437469128);
    glTexCoord2f(0.55103185,0.31581341); glVertex3f(0.41558613+$x,0.31416529+$y,0.68820718+$z);
    glTexCoord2f(0.81568094,0.59161198); glVertex3f(0.28324249+$x,0.24369433+$y,0.5599737+$z);
    glTexCoord2f(0.33679998,0.52138456); glVertex3f(0.52279886+$x,0.22287749+$y,0.62772546+$z);


    glNormal3f( -0.000418674458037201,-0.000540497285535201,0.000729125220190001);
    glTexCoord2f(0.10958898,0.76263806); glVertex3f(0.41558613+$x,0.31416529+$y,0.68820718+$z);
    glTexCoord2f(0.30455363,0.63232386); glVertex3f(0.28014185+$x,0.24755262+$y,0.5610534+$z);
    glTexCoord2f(0.30778761,0.63742023); glVertex3f(0.28324249+$x,0.24369433+$y,0.5599737+$z);


    glNormal3f( -0.000418674458037197,-0.000540498557073,0.000729125886316697);
    glTexCoord2f(0.10958898,0.76263806); glVertex3f(0.41558613+$x,0.31416529+$y,0.68820718+$z);
    glTexCoord2f(0.1061502,0.75915265); glVertex3f(0.41248548+$x,0.31802358+$y,0.68928688+$z);
    glTexCoord2f(0.30455363,0.63232386); glVertex3f(0.28014185+$x,0.24755262+$y,0.5610534+$z);


    glNormal3f( 2.95448083979977e-006,-2.52816251609983e-006,2.53116477479997e-005);
    glTexCoord2f(0.11790124,0.78053186); glVertex3f(0.4224765+$x,0.32071339+$y,0.69053803+$z);
    glTexCoord2f(0.10966522,0.77175621); glVertex3f(0.41560785+$x,0.32035429+$y,0.6913039+$z);
    glTexCoord2f(0.11396279,0.77144786); glVertex3f(0.41919152+$x,0.31685655+$y,0.69053624+$z);


    glNormal3f( 2.55865430939983e-006,-2.18944699439996e-006,2.19205224209999e-005);
    glTexCoord2f(0.11790124,0.78053186); glVertex3f(0.4224765+$x,0.32071339+$y,0.69053803+$z);
    glTexCoord2f(0.11528938,0.78359007); glVertex3f(0.41845272+$x,0.32369441+$y,0.69130545+$z);
    glTexCoord2f(0.10966522,0.77175621); glVertex3f(0.41560785+$x,0.32035429+$y,0.6913039+$z);


    glNormal3f( 9.99471288059967e-006,7.75937460880006e-006,2.22643148316e-005);
    glTexCoord2f(0.12130322,0.78972115); glVertex3f(0.42456086+$x,0.32470237+$y,0.68821213+$z);
    glTexCoord2f(0.12281594,0.79411589); glVertex3f(0.42025782+$x,0.32714896+$y,0.68929115+$z);
    glTexCoord2f(0.11790124,0.78053186); glVertex3f(0.4224765+$x,0.32071339+$y,0.69053803+$z);


    glNormal3f( 0.000466648071130386,0.000498954014392001,0.000729615219296796);
    glTexCoord2f(0.33082104,0.68336502); glVertex3f(0.47313422+$x,0.46664298+$y,0.56007815+$z);
    glTexCoord2f(0.12281594,0.79411589); glVertex3f(0.42025782+$x,0.32714896+$y,0.68929115+$z);
    glTexCoord2f(0.12130322,0.78972115); glVertex3f(0.42456086+$x,0.32470237+$y,0.68821213+$z);


    glNormal3f( 1.31543087573001e-005,1.69921118341005e-005,1.39295870149003e-005);
    glTexCoord2f(0.23492184,0.66432956); glVertex3f(0.47345943+$x,0.46969523+$y,0.55604773+$z);
    glTexCoord2f(0.23223613,0.65143152); glVertex3f(0.46911283+$x,0.47173292+$y,0.55766672+$z);
    glTexCoord2f(0.25027106,0.65780542); glVertex3f(0.47313422+$x,0.46664298+$y,0.56007815+$z);


    glNormal3f( 1.15862718216998e-005,2.26957269435002e-005,2.54111097949986e-006);
    glTexCoord2f(0.22640999,0.66492618); glVertex3f(0.47193838+$x,0.47099292+$y,0.55139279+$z);
    glTexCoord2f(0.23223613,0.65143152); glVertex3f(0.46911283+$x,0.47173292+$y,0.55766672+$z);
    glTexCoord2f(0.23492184,0.66432956); glVertex3f(0.47345943+$x,0.46969523+$y,0.55604773+$z);


    glNormal3f( 5.71108656400006e-006,2.33425065334998e-005,-8.84947896419988e-006);
    glTexCoord2f(0.21793725,0.66554789); glVertex3f(0.46897864+$x,0.47018838+$y,0.54736054+$z);
    glTexCoord2f(0.22446055,0.65560867); glVertex3f(0.46779557+$x,0.47285674+$y,0.55363544+$z);
    glTexCoord2f(0.22640999,0.66492618); glVertex3f(0.47193838+$x,0.47099292+$y,0.55139279+$z);


    glNormal3f( 5.67096346239977e-005,0.000848698878443595,-0.000524931431199195);
    glTexCoord2f(-0.10117832,0.68123918); glVertex3f(0.336635+$x,0.39971742+$y,0.41912706+$z);
    glTexCoord2f(0.21739621,0.65756961); glVertex3f(0.46523234+$x,0.47215996+$y,0.55014343+$z);
    glTexCoord2f(0.21793725,0.66554789); glVertex3f(0.46897864+$x,0.47018838+$y,0.54736054+$z);


    glNormal3f( 7.48514939118811e-005,6.96897490220013e-006,0.000122166670742361);
    glTexCoord2f(0.493245,0.65974822); glVertex3f(0.55021628+$x,0.09096489+$y,0.75143285+$z);
    glTexCoord2f(0.49435222,0.65903012); glVertex3f(0.55363974+$x,0.088049932+$y,0.74950158+$z);
    glTexCoord2f(0.49318907,0.65609532); glVertex3f(0.5645251+$x,0.11446657+$y,0.74132519+$z);


    glNormal3f( 0.000105969410908621,-2.0684135623901e-005,0.000219065913144822);
    glTexCoord2f(0.493245,0.65974822); glVertex3f(0.55021628+$x,0.09096489+$y,0.75143285+$z);
    glTexCoord2f(0.48283397,0.63727509); glVertex3f(0.52530559+$x,0.04818586+$y,0.75944379+$z);
    glTexCoord2f(0.49435222,0.65903012); glVertex3f(0.55363974+$x,0.088049932+$y,0.74950158+$z);


    glNormal3f( -0.0064738780828765,0.00551227503174821,0.00365209827777264);
    glTexCoord2f(0.73384276,0.10372462); glVertex3f(0.5645251+$x,0.11446657+$y,0.74132519+$z);
    glTexCoord2f(0.25671489,-0.41140866); glVertex3f(0.31340047+$x,-0.042761798+$y,0.53348187+$z);
    glTexCoord2f(0.75126648,0.049134097); glVertex3f(0.55021628+$x,0.09096489+$y,0.75143285+$z);


    glNormal3f( 7.76703769504011e-005,1.85084360316992e-005,0.0001097468788328);
    glTexCoord2f(0.49318907,0.65609532); glVertex3f(0.5645251+$x,0.11446657+$y,0.74132519+$z);
    glTexCoord2f(0.4862511,0.64681012); glVertex3f(0.57981492+$x,0.13350505+$y,0.72729346+$z);
    glTexCoord2f(0.48815747,0.64579906); glVertex3f(0.57639145+$x,0.13642001+$y,0.72922473+$z);


    glNormal3f( 7.76703769503988e-005,1.85082957144018e-005,0.000109746688448001);
    glTexCoord2f(0.49318907,0.65609532); glVertex3f(0.5645251+$x,0.11446657+$y,0.74132519+$z);
    glTexCoord2f(0.4920786,0.65665706); glVertex3f(0.56794856+$x,0.11155161+$y,0.73939392+$z);
    glTexCoord2f(0.4862511,0.64681012); glVertex3f(0.57981492+$x,0.13350505+$y,0.72729346+$z);


    glNormal3f( -0.00706888958291886,0.00601890488090081,0.00398776156165085);
    glTexCoord2f(0.71173287,0.153326); glVertex3f(0.57639145+$x,0.13642001+$y,0.72922473+$z);
    glTexCoord2f(0.17104309,-0.36612654); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);
    glTexCoord2f(0.73384276,0.10372462); glVertex3f(0.5645251+$x,0.11446657+$y,0.74132519+$z);


    glNormal3f( 0.000161927043404101,5.42603254560985e-005,0.000205142573017299);
    glTexCoord2f(0.48815747,0.64579906); glVertex3f(0.57639145+$x,0.13642001+$y,0.72922473+$z);
    glTexCoord2f(0.47525634,0.62440408); glVertex3f(0.60041007+$x,0.17589144+$y,0.69982568+$z);
    glTexCoord2f(0.47578951,0.62407913); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);


    glNormal3f( 0.000161927043404102,5.42603254560985e-005,0.0002051425730173);
    glTexCoord2f(0.48815747,0.64579906); glVertex3f(0.57639145+$x,0.13642001+$y,0.72922473+$z);
    glTexCoord2f(0.4862511,0.64681012); glVertex3f(0.57981492+$x,0.13350505+$y,0.72729346+$z);
    glTexCoord2f(0.47525634,0.62440408); glVertex3f(0.60041007+$x,0.17589144+$y,0.69982568+$z);


    glNormal3f( -0.0016490345178896,0.0014040942593874,0.000930267213147003);
    glTexCoord2f(0.65992368,0.24683425); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);
    glTexCoord2f(0.61257294,0.37166365); glVertex3f(0.62038135+$x,0.2243727+$y,0.67445229+$z);
    glTexCoord2f(0.55514637,0.27808808); glVertex3f(0.58632796+$x,0.19781034+$y,0.65417945+$z);


    glNormal3f( -0.0155396168292688,0.0132314296439408,0.00876633632584506);
    glTexCoord2f(0.65992368,0.24683425); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);
    glTexCoord2f(0.054156923,-0.2888844); glVertex3f(0.31742004+$x,0.029087611+$y,0.43216159+$z);
    glTexCoord2f(0.71173287,0.153326); glVertex3f(0.57639145+$x,0.13642001+$y,0.72922473+$z);


    glNormal3f( 0.000167592819914598,4.82951055377015e-005,0.000224189621521);
    glTexCoord2f(0.47578951,0.62407913); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);
    glTexCoord2f(0.48019194,0.63377785); glVertex3f(0.62380482+$x,0.22145774+$y,0.67252102+$z);
    glTexCoord2f(0.47945103,0.63422472); glVertex3f(0.62038135+$x,0.2243727+$y,0.67445229+$z);


    glNormal3f( 0.000167592819914602,4.82951055376985e-005,0.000224189621520999);
    glTexCoord2f(0.47578951,0.62407913); glVertex3f(0.5969866+$x,0.1788064+$y,0.70175695+$z);
    glTexCoord2f(0.47525634,0.62440408); glVertex3f(0.60041007+$x,0.17589144+$y,0.69982568+$z);
    glTexCoord2f(0.48019194,0.63377785); glVertex3f(0.62380482+$x,0.22145774+$y,0.67252102+$z);


    glNormal3f( -0.0017182635430948,0.001463039859944,0.000969320945257602);
    glTexCoord2f(0.61257294,0.37166365); glVertex3f(0.62038135+$x,0.2243727+$y,0.67445229+$z);
    glTexCoord2f(0.56916472,0.50633895); glVertex3f(0.65325807+$x,0.27336908+$y,0.65877865+$z);
    glTexCoord2f(0.52988056,0.34243862); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);


    glNormal3f( 0.000140313272456997,-9.8355867035981e-006,0.0002635719607698);
    glTexCoord2f(0.47945103,0.63422472); glVertex3f(0.62038135+$x,0.2243727+$y,0.67445229+$z);
    glTexCoord2f(0.48019194,0.63377785); glVertex3f(0.62380482+$x,0.22145774+$y,0.67252102+$z);
    glTexCoord2f(0.48642789,0.64237535); glVertex3f(0.65325807+$x,0.27336908+$y,0.65877865+$z);


    glNormal3f( -0.000318063830252601,0.000270819907620999,0.000179428922716404);
    glTexCoord2f(0.56916472,0.50633895); glVertex3f(0.65325807+$x,0.27336908+$y,0.65877865+$z);
    glTexCoord2f(0.56337574,0.54020003); glVertex3f(0.6627339+$x,0.28565443+$y,0.65703312+$z);
    glTexCoord2f(0.52988056,0.34243862); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);


    glNormal3f( 2.88144780233006e-005,-1.23246166150004e-005,6.96801925813e-005);
    glTexCoord2f(0.48642789,0.64237535); glVertex3f(0.65325807+$x,0.27336908+$y,0.65877865+$z);
    glTexCoord2f(0.4818343,0.63792349); glVertex3f(0.66615737+$x,0.28273947+$y,0.65510185+$z);
    glTexCoord2f(0.48525176,0.6356137); glVertex3f(0.6627339+$x,0.28565443+$y,0.65703312+$z);


    glNormal3f( 0.000140313272457002,-9.83572412730204e-006,0.000263571441656395);
    glTexCoord2f(0.48642789,0.64237535); glVertex3f(0.65325807+$x,0.27336908+$y,0.65877865+$z);
    glTexCoord2f(0.48019194,0.63377785); glVertex3f(0.62380482+$x,0.22145774+$y,0.67252102+$z);
    glTexCoord2f(0.48657266,0.64216045); glVertex3f(0.65668153+$x,0.27045412+$y,0.65684738+$z);


    glNormal3f( -0.000843464140334404,0.000718179483508604,0.000475821856698996);
    glTexCoord2f(0.56337574,0.54020003); glVertex3f(0.6627339+$x,0.28565443+$y,0.65703312+$z);
    glTexCoord2f(0.55110555,0.6444951); glVertex3f(0.69265637+$x,0.32302816+$y,0.65366523+$z);
    glTexCoord2f(0.52988056,0.34243862); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);


    glNormal3f( 8.19960281715017e-005,-4.62584982586012e-005,0.0002151706465943);
    glTexCoord2f(0.48525176,0.6356137); glVertex3f(0.6627339+$x,0.28565443+$y,0.65703312+$z);
    glTexCoord2f(0.4818343,0.63792349); glVertex3f(0.66615737+$x,0.28273947+$y,0.65510185+$z);
    glTexCoord2f(0.45740658,0.59628597); glVertex3f(0.69265637+$x,0.32302816+$y,0.65366523+$z);


    glNormal3f( -0.000625829002600002,0.000532871061635801,0.000353047018135008);
    glTexCoord2f(0.55110555,0.6444951); glVertex3f(0.69265637+$x,0.32302816+$y,0.65366523+$z);
    glTexCoord2f(0.54173319,0.71546866); glVertex3f(0.71289973+$x,0.34864441+$y,0.65088578+$z);
    glTexCoord2f(0.52988056,0.34243862); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);


    glNormal3f( 5.75738807095012e-005,-2.95800301757007e-005,0.0001467050480531);
    glTexCoord2f(0.45740658,0.59628597); glVertex3f(0.69265637+$x,0.32302816+$y,0.65366523+$z);
    glTexCoord2f(0.45475887,0.59821031); glVertex3f(0.69607984+$x,0.3201132+$y,0.65173396+$z);
    glTexCoord2f(0.45033047,0.59343957); glVertex3f(0.71289973+$x,0.34864441+$y,0.65088578+$z);


    glNormal3f( 8.19960281715017e-005,-4.62584982586012e-005,0.0002151706465943);
    glTexCoord2f(0.45740658,0.59628597); glVertex3f(0.69265637+$x,0.32302816+$y,0.65366523+$z);
    glTexCoord2f(0.4818343,0.63792349); glVertex3f(0.66615737+$x,0.28273947+$y,0.65510185+$z);
    glTexCoord2f(0.45475887,0.59821031); glVertex3f(0.69607984+$x,0.3201132+$y,0.65173396+$z);


    glNormal3f( -0.000936406801981802,0.000797316912510102,0.00052825306441609);
    glTexCoord2f(0.54173319,0.71546866); glVertex3f(0.71289973+$x,0.34864441+$y,0.65088578+$z);
    glTexCoord2f(0.52667694,0.78664447); glVertex3f(0.73249182+$x,0.37507212+$y,0.64572709+$z);
    glTexCoord2f(0.52988056,0.34243862); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);


    glNormal3f( 6.60766827711996e-005,-2.01772427078e-005,0.000147584366742999);
    glTexCoord2f(0.45033047,0.59343957); glVertex3f(0.71289973+$x,0.34864441+$y,0.65088578+$z);
    glTexCoord2f(0.47980711,0.62958926); glVertex3f(0.73591528+$x,0.37215716+$y,0.64379581+$z);
    glTexCoord2f(0.47028747,0.63537843); glVertex3f(0.73249182+$x,0.37507212+$y,0.64572709+$z);


    glNormal3f( 6.60764476436984e-005,-2.01769416525977e-005,0.000147584601870503);
    glTexCoord2f(0.45033047,0.59343957); glVertex3f(0.71289973+$x,0.34864441+$y,0.65088578+$z);
    glTexCoord2f(0.45295003,0.59203309); glVertex3f(0.7163232+$x,0.34572945+$y,0.64895451+$z);
    glTexCoord2f(0.47980711,0.62958926); glVertex3f(0.73591528+$x,0.37215716+$y,0.64379581+$z);


    glNormal3f( -0.00266078308736159,0.00226556159540919,0.0015010236004112);
    glTexCoord2f(0.52667694,0.78664447); glVertex3f(0.73249182+$x,0.37507212+$y,0.64572709+$z);
    glTexCoord2f(0.48474348,0.89188196); glVertex3f(0.7589951+$x,0.4167062+$y,0.62986785+$z);
    glTexCoord2f(0.52988056,0.34243862); glVertex3f(0.59883407+$x,0.22174416+$y,0.64022395+$z);


    glNormal3f( 0.000126636116252799,3.10821917199925e-006,0.000219788608585598);
    glTexCoord2f(0.47028747,0.63537843); glVertex3f(0.73249182+$x,0.37507212+$y,0.64572709+$z);
    glTexCoord2f(0.47980711,0.62958926); glVertex3f(0.73591528+$x,0.37215716+$y,0.64379581+$z);
    glTexCoord2f(0.54597912,0.76275538); glVertex3f(0.7589951+$x,0.4167062+$y,0.62986785+$z);


    glNormal3f( -0.00214925373087919,0.0018300121633448,0.00121245496813339);
    glTexCoord2f(0.48474348,0.89188196); glVertex3f(0.7589951+$x,0.4167062+$y,0.62986785+$z);
    glTexCoord2f(0.46106664,0.92478693); glVertex3f(0.76667996+$x,0.43122319+$y,0.62157925+$z);
    glTexCoord2f(0.23079912,0.64240467); glVertex3f(0.64740742+$x,0.36368477+$y,0.51208997+$z);


    glNormal3f( 5.21971647333006e-005,1.35342338697995e-005,7.20995392608998e-005);
    glTexCoord2f(0.54597912,0.76275538); glVertex3f(0.7589951+$x,0.4167062+$y,0.62986785+$z);
    glTexCoord2f(0.55918376,0.75459458); glVertex3f(0.76241857+$x,0.41379124+$y,0.62793658+$z);
    glTexCoord2f(0.58242942,0.82733976); glVertex3f(0.76667996+$x,0.43122319+$y,0.62157925+$z);


    glNormal3f( -0.00378913953642601,0.0032263182221445,0.00213755985721451);
    glTexCoord2f(0.46106664,0.92478693); glVertex3f(0.76667996+$x,0.43122319+$y,0.62157925+$z);
    glTexCoord2f(0.41739262,0.97171679); glVertex3f(0.77680271+$x,0.45369015+$y,0.60561289+$z);
    glTexCoord2f(0.17962802,0.67228717); glVertex3f(0.64935876+$x,0.38199834+$y,0.4879075+$z);


    glNormal3f( 8.99312912543993e-005,3.51104898492003e-005,0.000106422374891199);
    glTexCoord2f(0.58242942,0.82733976); glVertex3f(0.76667996+$x,0.43122319+$y,0.62157925+$z);
    glTexCoord2f(0.6011354,0.81554339); glVertex3f(0.77010343+$x,0.42830823+$y,0.61964797+$z);
    glTexCoord2f(0.65810014,0.94828856); glVertex3f(0.77680271+$x,0.45369015+$y,0.60561289+$z);


    glNormal3f( 5.21973390527992e-005,1.35341912558997e-005,7.20995392608996e-005);
    glTexCoord2f(0.58242942,0.82733976); glVertex3f(0.76667996+$x,0.43122319+$y,0.62157925+$z);
    glTexCoord2f(0.55918376,0.75459458); glVertex3f(0.76241857+$x,0.41379124+$y,0.62793658+$z);
    glTexCoord2f(0.6011354,0.81554339); glVertex3f(0.77010343+$x,0.42830823+$y,0.61964797+$z);


    glNormal3f( -0.00930694705231679,0.0079245313766358,0.0052503127750882);
    glTexCoord2f(0.41739262,0.97171679); glVertex3f(0.77680271+$x,0.45369015+$y,0.60561289+$z);
    glTexCoord2f(0.32193541,1.04285329); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);
    glTexCoord2f(0.071791846,0.6338303); glVertex3f(0.62247392+$x,0.38495707+$y,0.43578445+$z);


    glNormal3f( 0.000186426554748598,0.0001055056771435,0.0001712245769566);
    glTexCoord2f(0.38377627,0.79330993); glVertex3f(0.77680271+$x,0.45369015+$y,0.60561289+$z);
    glTexCoord2f(0.38955002,0.78568747); glVertex3f(0.78022618+$x,0.45077519+$y,0.60368162+$z);
    glTexCoord2f(0.4710472,0.85942087); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);


    glNormal3f( 8.99310374351988e-005,3.51105568420006e-005,0.0001064223748912);
    glTexCoord2f(0.65810014,0.94828856); glVertex3f(0.77680271+$x,0.45369015+$y,0.60561289+$z);
    glTexCoord2f(0.6011354,0.81554339); glVertex3f(0.77010343+$x,0.42830823+$y,0.61964797+$z);
    glTexCoord2f(0.67808584,0.93546506); glVertex3f(0.78022618+$x,0.45077519+$y,0.60368162+$z);


    glNormal3f( -0.0097727502993192,0.00832114673970299,0.005513085091413);
    glTexCoord2f(0.32193541,1.04285329); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);
    glTexCoord2f(-0.35096775,0.16435506); glVertex3f(0.41429417+$x,0.28282474+$y,0.22090828+$z);
    glTexCoord2f(0.071791846,0.6338303); glVertex3f(0.62247392+$x,0.38495707+$y,0.43578445+$z);


    glNormal3f( 0.000222592180588495,0.000160341005767899,0.000152568017059299);
    glTexCoord2f(0.4710472,0.85942087); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);
    glTexCoord2f(0.47597821,0.85136683); glVertex3f(0.79255979+$x,0.49028849+$y,0.56590556+$z);
    glTexCoord2f(0.58308957,0.91534198); glVertex3f(0.79477659+$x,0.53296628+$y,0.51781919+$z);


    glNormal3f( 0.000186426554748596,0.0001055056771435,0.000171224576956599);
    glTexCoord2f(0.4710472,0.85942087); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);
    glTexCoord2f(0.38955002,0.78568747); glVertex3f(0.78022618+$x,0.45077519+$y,0.60368162+$z);
    glTexCoord2f(0.47597821,0.85136683); glVertex3f(0.79255979+$x,0.49028849+$y,0.56590556+$z);


    glNormal3f( -0.0196273971875509,0.0167120287236205,0.0110723684195698);
    glTexCoord2f(0.20565293,1.098974); glVertex3f(0.79477659+$x,0.53296628+$y,0.51781919+$z);
    glTexCoord2f(-0.3615742,0.4015383); glVertex3f(0.4934947+$x,0.37207821+$y,0.22658852+$z);
    glTexCoord2f(0.32193541,1.04285329); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);


    glNormal3f( 3.29515439812998e-005,2.59841430641003e-005,1.91923216806003e-005);
    glTexCoord2f(0.58308957,0.91534198); glVertex3f(0.79477659+$x,0.53296628+$y,0.51781919+$z);
    glTexCoord2f(0.58722325,0.90671941); glVertex3f(0.79820005+$x,0.53005132+$y,0.51588792+$z);
    glTexCoord2f(0.60126348,0.9224552); glVertex3f(0.79501722+$x,0.53836751+$y,0.51009342+$z);


    glNormal3f( -0.002815988056288,0.00239771342342737,0.00158857828644061);
    glTexCoord2f(0.18789258,1.10567358); glVertex3f(0.79501722+$x,0.53836751+$y,0.51009342+$z);
    glTexCoord2f(-0.3615742,0.4015383); glVertex3f(0.4934947+$x,0.37207821+$y,0.22658852+$z);
    glTexCoord2f(0.20565293,1.098974); glVertex3f(0.79477659+$x,0.53296628+$y,0.51781919+$z);


    glNormal3f( 0.0001984926757512,0.000167767537358699,9.86382399003995e-005);
    glTexCoord2f(0.60126348,0.9224552); glVertex3f(0.79501722+$x,0.53836751+$y,0.51009342+$z);
    glTexCoord2f(0.60422441,0.91338337); glVertex3f(0.79844069+$x,0.53545255+$y,0.50816214+$z);
    glTexCoord2f(0.70676051,0.95507558); glVertex3f(0.79349391+$x,0.56847691+$y,0.46194765+$z);


    glNormal3f( 3.29516271432002e-005,2.59842328374001e-005,1.91924048424998e-005);
    glTexCoord2f(0.60126348,0.9224552); glVertex3f(0.79501722+$x,0.53836751+$y,0.51009342+$z);
    glTexCoord2f(0.58722325,0.90671941); glVertex3f(0.79820005+$x,0.53005132+$y,0.51588792+$z);
    glTexCoord2f(0.60422441,0.91338337); glVertex3f(0.79844069+$x,0.53545255+$y,0.50816214+$z);


    glNormal3f( -0.0133690814189536,0.0113832950870499,0.00754187627511878);
    glTexCoord2f(0.078285347,1.13827013); glVertex3f(0.79349391+$x,0.56847691+$y,0.46194765+$z);
    glTexCoord2f(-0.33599666,0.55983287); glVertex3f(0.55021438+$x,0.42610563+$y,0.24558643+$z);
    glTexCoord2f(0.18789258,1.10567358); glVertex3f(0.79501722+$x,0.53836751+$y,0.51009342+$z);


    glNormal3f( 6.51731495671002e-005,5.93890869646008e-005,2.5890143625e-005);
    glTexCoord2f(0.70676051,0.95507558); glVertex3f(0.79349391+$x,0.56847691+$y,0.46194765+$z);
    glTexCoord2f(0.74489604,0.95369658); glVertex3f(0.79527925+$x,0.57451932+$y,0.44359281+$z);
    glTexCoord2f(0.74336847,0.96309027); glVertex3f(0.79185579+$x,0.57743428+$y,0.44552408+$z);


    glNormal3f( 6.51729660186992e-005,5.93892705129997e-005,2.58901861956996e-005);
    glTexCoord2f(0.70676051,0.95507558); glVertex3f(0.79349391+$x,0.56847691+$y,0.46194765+$z);
    glTexCoord2f(0.7093621,0.94592206); glVertex3f(0.79691738+$x,0.56556196+$y,0.46001638+$z);
    glTexCoord2f(0.74489604,0.95369658); glVertex3f(0.79527925+$x,0.57451932+$y,0.44359281+$z);


    glNormal3f( -0.00345411873956019,0.00294105870216128,0.0019485661142265);
    glTexCoord2f(0.041331094,1.14598056); glVertex3f(0.79185579+$x,0.57743428+$y,0.44552408+$z);
    glTexCoord2f(-0.33157119,0.68595928); glVertex3f(0.59363774+$x,0.47179263+$y,0.25360327+$z);
    glTexCoord2f(0.078285347,1.13827013); glVertex3f(0.79349391+$x,0.56847691+$y,0.46194765+$z);


    glNormal3f( 0.000156688627575601,0.000152730200580202,4.72304874392007e-005);
    glTexCoord2f(0.74336847,0.96309027); glVertex3f(0.79185579+$x,0.57743428+$y,0.44552408+$z);
    glTexCoord2f(0.74489604,0.95369658); glVertex3f(0.79527925+$x,0.57451932+$y,0.44359281+$z);
    glTexCoord2f(0.83142257,0.97509731); glVertex3f(0.78528755+$x,0.59682304+$y,0.40461659+$z);


    glNormal3f( -0.0080426412650541,0.00684802095712009,0.004537081910314);
    glTexCoord2f(-0.050054012,1.15739811); glVertex3f(0.78528755+$x,0.59682304+$y,0.40461659+$z);
    glTexCoord2f(-0.33157119,0.68595928); glVertex3f(0.59363774+$x,0.47179263+$y,0.25360327+$z);
    glTexCoord2f(0.041331094,1.14598056); glVertex3f(0.79185579+$x,0.57743428+$y,0.44552408+$z);


    glNormal3f( 8.75820024261004e-005,9.28035478544022e-005,1.51795077809008e-005);
    glTexCoord2f(0.884872,0.15457406); glVertex3f(0.78528755+$x,0.59682304+$y,0.40461659+$z);
    glTexCoord2f(0.89259282,0.15942041); glVertex3f(0.78871102+$x,0.59390808+$y,0.40268532+$z);
    glTexCoord2f(0.85885755,0.196019); glVertex3f(0.77965086+$x,0.60605643+$y,0.38068836+$z);


    glNormal3f( -0.0030480443830232,0.002595300670294,0.0017194880084916);
    glTexCoord2f(-0.10294715,1.15858866); glVertex3f(0.77965086+$x,0.60605643+$y,0.38068836+$z);
    glTexCoord2f(-0.35523238,0.83186344); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);
    glTexCoord2f(-0.050054012,1.15739811); glVertex3f(0.78528755+$x,0.59682304+$y,0.40461659+$z);


    glNormal3f( 0.000106263318236501,0.000122641491786398,3.25856899979939e-006);
    glTexCoord2f(0.85885755,0.196019); glVertex3f(0.77965086+$x,0.60605643+$y,0.38068836+$z);
    glTexCoord2f(0.83358243,0.25388651); glVertex3f(0.77358016+$x,0.61217726+$y,0.34828917+$z);
    glTexCoord2f(0.82569462,0.24895345); glVertex3f(0.7701567+$x,0.61509222+$y,0.35022044+$z);


    glNormal3f( 8.75821239096003e-005,9.2803418486401e-005,1.51793862974002e-005);
    glTexCoord2f(0.85885755,0.196019); glVertex3f(0.77965086+$x,0.60605643+$y,0.38068836+$z);
    glTexCoord2f(0.89259282,0.15942041); glVertex3f(0.78871102+$x,0.59390808+$y,0.40268532+$z);
    glTexCoord2f(0.86664088,0.20087276); glVertex3f(0.78307432+$x,0.60314147+$y,0.37875708+$z);


    glNormal3f( -0.0035251215032282,0.003001515195424,0.00198862044270659);
    glTexCoord2f(-0.16940709,1.15290665); glVertex3f(0.7701567+$x,0.61509222+$y,0.35022044+$z);
    glTexCoord2f(-0.35523238,0.83186344); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);
    glTexCoord2f(-0.10294715,1.15858866); glVertex3f(0.77965086+$x,0.60605643+$y,0.38068836+$z);


    glNormal3f( 9.10961018881008e-005,0.000118815590227299,-1.78529319666006e-005);
    glTexCoord2f(0.82569462,0.24895345); glVertex3f(0.7701567+$x,0.61509222+$y,0.35022044+$z);
    glTexCoord2f(0.83358243,0.25388651); glVertex3f(0.77358016+$x,0.61217726+$y,0.34828917+$z);
    glTexCoord2f(0.79433961,0.29911324); glVertex3f(0.75840127+$x,0.61988669+$y,0.32214572+$z);


    glNormal3f( -0.002893842881921,0.0024640030741318,0.0016324991397333);
    glTexCoord2f(-0.22973225,1.13830017); glVertex3f(0.75840127+$x,0.61988669+$y,0.32214572+$z);
    glTexCoord2f(-0.35523238,0.83186344); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);
    glTexCoord2f(-0.16940709,1.15290665); glVertex3f(0.7701567+$x,0.61509222+$y,0.35022044+$z);


    glNormal3f( 5.62990428271985e-005,8.49125977966002e-005,-2.8363956508399e-005);
    glTexCoord2f(0.79433961,0.29911324); glVertex3f(0.75840127+$x,0.61988669+$y,0.32214572+$z);
    glTexCoord2f(0.80239199,0.30414181); glVertex3f(0.76182474+$x,0.61697173+$y,0.32021444+$z);
    glTexCoord2f(0.77179382,0.33522132); glVertex3f(0.74810062+$x,0.62037217+$y,0.30315354+$z);


    glNormal3f( 9.10961789823979e-005,0.0001188160034507,-1.78528548722986e-005);
    glTexCoord2f(0.79433961,0.29911324); glVertex3f(0.75840127+$x,0.61988669+$y,0.32214572+$z);
    glTexCoord2f(0.83358243,0.25388651); glVertex3f(0.77358016+$x,0.61217726+$y,0.34828917+$z);
    glTexCoord2f(0.80239199,0.30414181); glVertex3f(0.76182474+$x,0.61697173+$y,0.32021444+$z);


    glNormal3f( -0.000682658358961603,0.0005812595852133,0.000385106645401803);
    glTexCoord2f(-0.26968172,1.12125487); glVertex3f(0.74810062+$x,0.62037217+$y,0.30315354+$z);
    glTexCoord2f(-0.37075698,0.97964928); glVertex3f(0.68876356+$x,0.58578215+$y,0.25017819+$z);
    glTexCoord2f(-0.22973225,1.13830017); glVertex3f(0.75840127+$x,0.61988669+$y,0.32214572+$z);


    glNormal3f( 6.66321096448003e-005,0.000130013994274599,-7.81208476586e-005);
    glTexCoord2f(0.77179382,0.33522132); glVertex3f(0.74810062+$x,0.62037217+$y,0.30315354+$z);
    glTexCoord2f(0.74440832,0.39815691); glVertex3f(0.73152937+$x,0.61166276+$y,0.27452453+$z);
    glTexCoord2f(0.73604078,0.39297466); glVertex3f(0.72810591+$x,0.61457772+$y,0.27645581+$z);


    glNormal3f( 6.66319104487993e-005,0.000130014114852199,-7.81207690401996e-005);
    glTexCoord2f(0.77179382,0.33522132); glVertex3f(0.74810062+$x,0.62037217+$y,0.30315354+$z);
    glTexCoord2f(0.78009519,0.34032508); glVertex3f(0.75152409+$x,0.61745722+$y,0.30122227+$z);
    glTexCoord2f(0.74440832,0.39815691); glVertex3f(0.73152937+$x,0.61166276+$y,0.27452453+$z);


    glNormal3f( -7.87806996674983e-005,6.70791802743003e-005,4.44423659729986e-005);
    glTexCoord2f(-0.32395745,1.08029476); glVertex3f(0.72810591+$x,0.61457772+$y,0.27645581+$z);
    glTexCoord2f(-0.34074889,1.0592688); glVertex3f(0.7191185+$x,0.60975047+$y,0.26781031+$z);
    glTexCoord2f(-0.26968172,1.12125487); glVertex3f(0.74810062+$x,0.62037217+$y,0.30315354+$z);


    glNormal3f( 1.58785153000002e-005,4.69547286147999e-005,-4.27238379385998e-005);
    glTexCoord2f(0.73604078,0.39297466); glVertex3f(0.72810591+$x,0.61457772+$y,0.27645581+$z);
    glTexCoord2f(0.74440832,0.39815691); glVertex3f(0.73152937+$x,0.61166276+$y,0.27452453+$z);
    glTexCoord2f(0.72182132,0.41601009); glVertex3f(0.7191185+$x,0.60975047+$y,0.26781031+$z);


    glNormal3f( -0.000659834757469603,0.000561825408361799,0.000372231660240403);
    glTexCoord2f(-0.34074889,1.0592688); glVertex3f(0.7191185+$x,0.60975047+$y,0.26781031+$z);
    glTexCoord2f(-0.37075698,0.97964928); glVertex3f(0.68876356+$x,0.58578215+$y,0.25017819+$z);
    glTexCoord2f(-0.26968172,1.12125487); glVertex3f(0.74810062+$x,0.62037217+$y,0.30315354+$z);


    glNormal3f( 5.10738746560071e-006,0.000118986922379599,-0.0001705382603728);
    glTexCoord2f(0.66193461,0.32983784); glVertex3f(0.7191185+$x,0.60975047+$y,0.26781031+$z);
    glTexCoord2f(0.6436096,0.3146514); glVertex3f(0.72254197+$x,0.60683551+$y,0.26587903+$z);
    glTexCoord2f(0.79256346,0.16946959); glVertex3f(0.68876356+$x,0.58578215+$y,0.25017819+$z);


    glNormal3f( -0.000339142536003697,0.000288767732626203,0.000191319875544295);
    glTexCoord2f(-0.37075698,0.97964928); glVertex3f(0.68876356+$x,0.58578215+$y,0.25017819+$z);
    glTexCoord2f(-0.37247709,0.96387678); glVertex3f(0.6832096+$x,0.58031478+$y,0.24858513+$z);
    glTexCoord2f(-0.22973225,1.13830017); glVertex3f(0.75840127+$x,0.61988669+$y,0.32214572+$z);


    glNormal3f( -5.91526148229988e-006,1.61799894474003e-005,-3.49069484155002e-005);
    glTexCoord2f(0.79256346,0.16946959); glVertex3f(0.68876356+$x,0.58578215+$y,0.25017819+$z);
    glTexCoord2f(0.77552303,0.15547904); glVertex3f(0.69218703+$x,0.58286719+$y,0.24824692+$z);
    glTexCoord2f(0.80264248,0.1452794); glVertex3f(0.6832096+$x,0.58031478+$y,0.24858513+$z);


    glNormal3f( 5.10759799919998e-006,0.0001189865845955,-0.0001705382603728);
    glTexCoord2f(0.79256346,0.16946959); glVertex3f(0.68876356+$x,0.58578215+$y,0.25017819+$z);
    glTexCoord2f(0.6436096,0.3146514); glVertex3f(0.72254197+$x,0.60683551+$y,0.26587903+$z);
    glTexCoord2f(0.77552303,0.15547904); glVertex3f(0.69218703+$x,0.58286719+$y,0.24824692+$z);


    glNormal3f( -0.00381444952475701,0.0032478672195307,0.00215183864884671);
    glTexCoord2f(-0.37247709,0.96387678); glVertex3f(0.6832096+$x,0.58031478+$y,0.24858513+$z);
    glTexCoord2f(-0.35523238,0.83186344); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);
    glTexCoord2f(-0.22973225,1.13830017); glVertex3f(0.75840127+$x,0.61988669+$y,0.32214572+$z);


    glNormal3f( -0.000102560513311499,7.8322375336899e-005,-0.000300017940689503);
    glTexCoord2f(0.80264248,0.1452794); glVertex3f(0.6832096+$x,0.58031478+$y,0.24858513+$z);
    glTexCoord2f(0.79711997,0.14084221); glVertex3f(0.68663307+$x,0.57739983+$y,0.24665385+$z);
    glTexCoord2f(0.85015593,0.082533042); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);


    glNormal3f( -5.91528362429981e-006,1.61800792217e-005,-3.49068586412007e-005);
    glTexCoord2f(0.80264248,0.1452794); glVertex3f(0.6832096+$x,0.58031478+$y,0.24858513+$z);
    glTexCoord2f(0.77552303,0.15547904); glVertex3f(0.69218703+$x,0.58286719+$y,0.24824692+$z);
    glTexCoord2f(0.79711997,0.14084221); glVertex3f(0.68663307+$x,0.57739983+$y,0.24665385+$z);


    glNormal3f( -0.00912861384289689,0.0077726892548925,0.00514970854367519);
    glTexCoord2f(-0.35523238,0.83186344); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);
    glTexCoord2f(-0.33157119,0.68595928); glVertex3f(0.59363774+$x,0.47179263+$y,0.25360327+$z);
    glTexCoord2f(-0.050054012,1.15739811); glVertex3f(0.78528755+$x,0.59682304+$y,0.40461659+$z);


    glNormal3f( -5.97175592960997e-005,5.08473484139998e-005,3.36879842038003e-005);
    glTexCoord2f(-0.35523238,0.83186344); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);
    glTexCoord2f(-0.33080799,0.66684458); glVertex3f(0.58723672+$x,0.46465724+$y,0.25302628+$z);
    glTexCoord2f(-0.33157119,0.68595928); glVertex3f(0.59363774+$x,0.47179263+$y,0.25360327+$z);


    glNormal3f( -0.000133752342271199,9.18240160979991e-005,-0.000375688210739397);
    glTexCoord2f(0.85015593,0.082533042); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);
    glTexCoord2f(0.85482594,0.068593439); glVertex3f(0.59066018+$x,0.46174228+$y,0.251095+$z);
    glTexCoord2f(0.85527307,0.068854411); glVertex3f(0.58723672+$x,0.46465724+$y,0.25302628+$z);


    glNormal3f( -0.00143083254289099,0.0012183015317393,0.000807173706890695);
    glTexCoord2f(-0.33157119,0.68595928); glVertex3f(0.59363774+$x,0.47179263+$y,0.25360327+$z);
    glTexCoord2f(-0.33080799,0.66684458); glVertex3f(0.58723672+$x,0.46465724+$y,0.25302628+$z);
    glTexCoord2f(0.078285347,1.13827013); glVertex3f(0.79349391+$x,0.56847691+$y,0.46194765+$z);


    glNormal3f( -0.0072818524050562,0.00620023543838431,0.0041078996271481);
    glTexCoord2f(-0.33080799,0.66684458); glVertex3f(0.58723672+$x,0.46465724+$y,0.25302628+$z);
    glTexCoord2f(-0.33599666,0.55983287); glVertex3f(0.55021438+$x,0.42610563+$y,0.24558643+$z);
    glTexCoord2f(0.078285347,1.13827013); glVertex3f(0.79349391+$x,0.56847691+$y,0.46194765+$z);


    glNormal3f( -5.27670882047991e-005,9.69705336761988e-005,-0.000239898534976998);
    glTexCoord2f(0.85527307,0.068854411); glVertex3f(0.58723672+$x,0.46465724+$y,0.25302628+$z);
    glTexCoord2f(0.85482594,0.068593439); glVertex3f(0.59066018+$x,0.46174228+$y,0.251095+$z);
    glTexCoord2f(0.85600094,0.068837448); glVertex3f(0.55021438+$x,0.42610563+$y,0.24558643+$z);


    glNormal3f( -0.00265614889345221,0.00226161824402271,0.0014984075720028);
    glTexCoord2f(-0.33599666,0.55983287); glVertex3f(0.55021438+$x,0.42610563+$y,0.24558643+$z);
    glTexCoord2f(-0.34035482,0.52653035); glVertex3f(0.53838557+$x,0.41456029+$y,0.24204405+$z);
    glTexCoord2f(0.18789258,1.10567358); glVertex3f(0.79501722+$x,0.53836751+$y,0.51009342+$z);


    glNormal3f( -1.19713082007998e-005,3.49718221235e-005,-7.4005399385901e-005);
    glTexCoord2f(0.85600094,0.068837448); glVertex3f(0.55021438+$x,0.42610563+$y,0.24558643+$z);
    glTexCoord2f(0.85657831,0.069244244); glVertex3f(0.55363784+$x,0.42319068+$y,0.24365516+$z);
    glTexCoord2f(0.84780598,0.075236309); glVertex3f(0.53838557+$x,0.41456029+$y,0.24204405+$z);


    glNormal3f( -0.00947378857736299,0.00806659125672739,0.00534443246775059);
    glTexCoord2f(-0.34035482,0.52653035); glVertex3f(0.53838557+$x,0.41456029+$y,0.24204405+$z);
    glTexCoord2f(-0.3615742,0.4015383); glVertex3f(0.4934947+$x,0.37207821+$y,0.22658852+$z);
    glTexCoord2f(0.18789258,1.10567358); glVertex3f(0.79501722+$x,0.53836751+$y,0.51009342+$z);


    glNormal3f( -3.69926942889006e-005,0.0001396083827027,-0.000276290767924098);
    glTexCoord2f(0.84780598,0.075236309); glVertex3f(0.53838557+$x,0.41456029+$y,0.24204405+$z);
    glTexCoord2f(0.85116088,0.078351866); glVertex3f(0.54180904+$x,0.41164534+$y,0.24011277+$z);
    glTexCoord2f(0.80318149,0.12333253); glVertex3f(0.4934947+$x,0.37207821+$y,0.22658852+$z);


    glNormal3f( -1.19713945047001e-005,3.49719907573002e-005,-7.40054856897996e-005);
    glTexCoord2f(0.84780598,0.075236309); glVertex3f(0.53838557+$x,0.41456029+$y,0.24204405+$z);
    glTexCoord2f(0.85657831,0.069244244); glVertex3f(0.55363784+$x,0.42319068+$y,0.24365516+$z);
    glTexCoord2f(0.85116088,0.078351866); glVertex3f(0.54180904+$x,0.41164534+$y,0.24011277+$z);


    glNormal3f( -0.00622391246355951,0.0052994386126564,0.00351108490366341);
    glTexCoord2f(-0.3615742,0.4015383); glVertex3f(0.4934947+$x,0.37207821+$y,0.22658852+$z);
    glTexCoord2f(-0.36968484,0.34221927); glVertex3f(0.47243286+$x,0.35157296+$y,0.22020282+$z);
    glTexCoord2f(0.32193541,1.04285329); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);


    glNormal3f( -2.09871140955e-005,6.25372882587996e-005,-0.000131593324291399);
    glTexCoord2f(0.80318149,0.12333253); glVertex3f(0.4934947+$x,0.37207821+$y,0.22658852+$z);
    glTexCoord2f(0.79716002,0.13050725); glVertex3f(0.47585632+$x,0.348658+$y,0.21827155+$z);
    glTexCoord2f(0.79844776,0.13140952); glVertex3f(0.47243286+$x,0.35157296+$y,0.22020282+$z);


    glNormal3f( -3.69921633750991e-005,0.000139607764316799,-0.0002762908553962);
    glTexCoord2f(0.80318149,0.12333253); glVertex3f(0.4934947+$x,0.37207821+$y,0.22658852+$z);
    glTexCoord2f(0.85116088,0.078351866); glVertex3f(0.54180904+$x,0.41164534+$y,0.24011277+$z);
    glTexCoord2f(0.80599209,0.12601508); glVertex3f(0.49691816+$x,0.36916325+$y,0.22465725+$z);


    glNormal3f( -0.00680125470962389,0.0057910251061318,0.0038367798809312);
    glTexCoord2f(-0.36968484,0.34221927); glVertex3f(0.47243286+$x,0.35157296+$y,0.22020282+$z);
    glTexCoord2f(-0.3724371,0.28362565); glVertex3f(0.45223922+$x,0.33042758+$y,0.21632231+$z);
    glTexCoord2f(0.32193541,1.04285329); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);


    glNormal3f( -2.95259066029998e-005,5.22841418873997e-005,-0.000131254015469199);
    glTexCoord2f(0.79844776,0.13140952); glVertex3f(0.47243286+$x,0.35157296+$y,0.22020282+$z);
    glTexCoord2f(0.79716002,0.13050725); glVertex3f(0.47585632+$x,0.348658+$y,0.21827155+$z);
    glTexCoord2f(0.81857129,0.1115966); glVertex3f(0.45223922+$x,0.33042758+$y,0.21632231+$z);


    glNormal3f( -0.00581378038567461,0.00495022945435841,0.0032797161432701);
    glTexCoord2f(-0.3724371,0.28362565); glVertex3f(0.45223922+$x,0.33042758+$y,0.21632231+$z);
    glTexCoord2f(-0.36935039,0.23951756); glVertex3f(0.43763935+$x,0.31363841+$y,0.21578257+$z);
    glTexCoord2f(0.32193541,1.04285329); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);


    glNormal3f( 7.18365190792994e-005,-5.73908118768997e-005,-0.0001579644695057);
    glTexCoord2f(0.81857129,0.1115966); glVertex3f(0.45223922+$x,0.33042758+$y,0.21632231+$z);
    glTexCoord2f(0.88727761,0.014039886); glVertex3f(0.41771763+$x,0.27990978+$y,0.218977+$z);
    glTexCoord2f(0.84801066,0.079905148); glVertex3f(0.43763935+$x,0.31363841+$y,0.21578257+$z);


    glNormal3f( -0.000105301826768399,5.75822860918994e-005,-0.0002735747215744);
    glTexCoord2f(0.81857129,0.1115966); glVertex3f(0.45223922+$x,0.33042758+$y,0.21632231+$z);
    glTexCoord2f(0.8124591,0.10654621); glVertex3f(0.45566268+$x,0.32751262+$y,0.21439104+$z);
    glTexCoord2f(0.88727761,0.014039886); glVertex3f(0.41771763+$x,0.27990978+$y,0.218977+$z);


    glNormal3f( -2.95259066029997e-005,5.22841418873997e-005,-0.0001312540154692);
    glTexCoord2f(0.81857129,0.1115966); glVertex3f(0.45223922+$x,0.33042758+$y,0.21632231+$z);
    glTexCoord2f(0.79716002,0.13050725); glVertex3f(0.47585632+$x,0.348658+$y,0.21827155+$z);
    glTexCoord2f(0.8124591,0.10654621); glVertex3f(0.45566268+$x,0.32751262+$y,0.21439104+$z);


    glNormal3f( -0.0117684821109126,0.0100204416035655,0.00663893345907269);
    glTexCoord2f(-0.36935039,0.23951756); glVertex3f(0.43763935+$x,0.31363841+$y,0.21578257+$z);
    glTexCoord2f(-0.35096775,0.16435506); glVertex3f(0.41429417+$x,0.28282474+$y,0.22090828+$z);
    glTexCoord2f(0.32193541,1.04285329); glVertex3f(0.78913632+$x,0.49320345+$y,0.56783683+$z);


    glNormal3f( -7.44510642192003e-005,2.75384160738001e-005,-0.000173539632591);
    glTexCoord2f(0.84801066,0.079905148); glVertex3f(0.43763935+$x,0.31363841+$y,0.21578257+$z);
    glTexCoord2f(0.88727761,0.014039886); glVertex3f(0.41771763+$x,0.27990978+$y,0.218977+$z);
    glTexCoord2f(0.89641157,0.021194887); glVertex3f(0.41429417+$x,0.28282474+$y,0.22090828+$z);


    glNormal3f( -0.0013261924531505,0.0011292049797583,0.000748142833166301);
    glTexCoord2f(-0.35096775,0.16435506); glVertex3f(0.41429417+$x,0.28282474+$y,0.22090828+$z);
    glTexCoord2f(-0.33731306,0.1363279); glVertex3f(0.40528709+$x,0.26919905+$y,0.22550777+$z);
    glTexCoord2f(-0.17809861,0.3285038); glVertex3f(0.49013028+$x,0.31448611+$y,0.30755096+$z);


    glNormal3f( 7.92695208084015e-005,-9.96681517644004e-005,-0.0001400286604236);
    glTexCoord2f(0.89641157,0.021194887); glVertex3f(0.41429417+$x,0.28282474+$y,0.22090828+$z);
    glTexCoord2f(1.00768994,-0.14033827); glVertex3f(0.38275805+$x,0.21957116+$y,0.24807782+$z);
    glTexCoord2f(0.9264021,-0.01092561); glVertex3f(0.40528709+$x,0.26919905+$y,0.22550777+$z);


    glNormal3f( -0.000201358496300801,-3.21087555747994e-005,-0.000308472629342);
    glTexCoord2f(0.89641157,0.021194887); glVertex3f(0.41429417+$x,0.28282474+$y,0.22090828+$z);
    glTexCoord2f(0.88727761,0.014039886); glVertex3f(0.41771763+$x,0.27990978+$y,0.218977+$z);
    glTexCoord2f(1.00768994,-0.14033827); glVertex3f(0.38275805+$x,0.21957116+$y,0.24807782+$z);


    glNormal3f( -0.0038936532314208,0.003315306572158,0.0021965201287866);
    glTexCoord2f(-0.33731306,0.1363279); glVertex3f(0.40528709+$x,0.26919905+$y,0.22550777+$z);
    glTexCoord2f(-0.27949455,0.050242985); glVertex3f(0.37933458+$x,0.22248611+$y,0.25000909+$z);
    glTexCoord2f(-0.20323544,0.27323554); glVertex3f(0.4684979+$x,0.29833853+$y,0.29357665+$z);


    glNormal3f( -0.000161635422367799,-3.37582299927013e-005,-0.000235570617726302);
    glTexCoord2f(0.9264021,-0.01092561); glVertex3f(0.40528709+$x,0.26919905+$y,0.22550777+$z);
    glTexCoord2f(1.00768994,-0.14033827); glVertex3f(0.38275805+$x,0.21957116+$y,0.24807782+$z);
    glTexCoord2f(1.01798605,-0.13260891); glVertex3f(0.37933458+$x,0.22248611+$y,0.25000909+$z);


    glNormal3f( -0.0006728418221531,0.000572900767290798,0.000379568990442501);
    glTexCoord2f(-0.27949455,0.050242985); glVertex3f(0.37933458+$x,0.22248611+$y,0.25000909+$z);
    glTexCoord2f(-0.26804602,0.036231297); glVertex3f(0.37515838+$x,0.21371046+$y,0.25585165+$z);
    glTexCoord2f(-0.16659349,0.16494389); glVertex3f(0.43628191+$x,0.25126367+$y,0.30752132+$z);


    glNormal3f( 5.47555993609004e-005,-8.74908010947981e-005,-9.22743308714971e-005);
    glTexCoord2f(0.69563289,0.67840949); glVertex3f(0.37933458+$x,0.22248611+$y,0.25000909+$z);
    glTexCoord2f(0.75763305,0.48060068); glVertex3f(0.35045901+$x,0.1397132+$y,0.31135626+$z);
    glTexCoord2f(0.70455283,0.65833239); glVertex3f(0.37515838+$x,0.21371046+$y,0.25585165+$z);


    glNormal3f( -0.000393436983919799,-6.67622594395018e-005,-0.000275266547124301);
    glTexCoord2f(0.40077924,0.84125139); glVertex3f(0.37933458+$x,0.22248611+$y,0.25000909+$z);
    glTexCoord2f(0.40998483,0.81916527); glVertex3f(0.37858184+$x,0.2107955+$y,0.25392038+$z);
    glTexCoord2f(0.54516575,0.69250704); glVertex3f(0.35045901+$x,0.1397132+$y,0.31135626+$z);


    glNormal3f( -3.39789391601998e-005,-1.19364397965003e-005,-4.22166520797004e-005);
    glTexCoord2f(1.01798605,-0.13260891); glVertex3f(0.37933458+$x,0.22248611+$y,0.25000909+$z);
    glTexCoord2f(1.00768994,-0.14033827); glVertex3f(0.38275805+$x,0.21957116+$y,0.24807782+$z);
    glTexCoord2f(1.02701063,-0.16611183); glVertex3f(0.37858184+$x,0.2107955+$y,0.25392038+$z);


    glNormal3f( -0.0067852731922501,0.0057774182402897,0.0038277650453843);
    glTexCoord2f(-0.26804602,0.036231297); glVertex3f(0.37515838+$x,0.21371046+$y,0.25585165+$z);
    glTexCoord2f(-0.15960905,-0.091599615); glVertex3f(0.34703555+$x,0.14262816+$y,0.31328754+$z);
    glTexCoord2f(0.077525062,-0.093088169); glVertex3f(0.38770856+$x,0.10932305+$y,0.4356553+$z);


    glNormal3f( -0.000304703146258398,-0.000142316412857,-0.000325324335294799);
    glTexCoord2f(0.70455283,0.65833239); glVertex3f(0.37515838+$x,0.21371046+$y,0.25585165+$z);
    glTexCoord2f(0.75763305,0.48060068); glVertex3f(0.35045901+$x,0.1397132+$y,0.31135626+$z);
    glTexCoord2f(0.76656678,0.4837745); glVertex3f(0.34703555+$x,0.14262816+$y,0.31328754+$z);


    glNormal3f( -0.005450210664724,0.0046406605777812,0.00307461854236845);
    glTexCoord2f(-0.15960905,-0.091599615); glVertex3f(0.34703555+$x,0.14262816+$y,0.31328754+$z);
    glTexCoord2f(-0.050777897,-0.19571504); glVertex3f(0.32879117+$x,0.081973995+$y,0.37249478+$z);
    glTexCoord2f(0.077525062,-0.093088169); glVertex3f(0.38770856+$x,0.10932305+$y,0.4356553+$z);


    glNormal3f( -0.000289726187135472,-0.000167459386160198,-0.000260829315688589);
    glTexCoord2f(-0.15960905,-0.091599615); glVertex3f(0.34703555+$x,0.14262816+$y,0.31328754+$z);
    glTexCoord2f(-0.057335979,-0.20208162); glVertex3f(0.33221464+$x,0.079059037+$y,0.37056351+$z);
    glTexCoord2f(-0.050777897,-0.19571504); glVertex3f(0.32879117+$x,0.081973995+$y,0.37249478+$z);


    glNormal3f( -0.000289726937378638,-0.0001674586651914,-0.000260828709639179);
    glTexCoord2f(-0.15960905,-0.091599615); glVertex3f(0.34703555+$x,0.14262816+$y,0.31328754+$z);
    glTexCoord2f(-0.16552127,-0.097715346); glVertex3f(0.35045901+$x,0.1397132+$y,0.31135626+$z);
    glTexCoord2f(-0.057335979,-0.20208162); glVertex3f(0.33221464+$x,0.079059037+$y,0.37056351+$z);


    glNormal3f( -0.00129099826403885,0.0010992389138857,0.0007282888535069);
    glTexCoord2f(-0.050777897,-0.19571504); glVertex3f(0.32879117+$x,0.081973995+$y,0.37249478+$z);
    glTexCoord2f(-0.024731059,-0.219187); glVertex3f(0.32531259+$x,0.067998075+$y,0.38742297+$z);
    glTexCoord2f(0.077525062,-0.093088169); glVertex3f(0.38770856+$x,0.10932305+$y,0.4356553+$z);


    glNormal3f( -2.61057474341768e-005,-8.21935161978005e-005,-8.30335719071601e-005);
    glTexCoord2f(0.424611,0.8489074); glVertex3f(0.32879117+$x,0.081973995+$y,0.37249478+$z);
    glTexCoord2f(0.44038845,0.69338373); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);
    glTexCoord2f(0.43151657,0.80931754); glVertex3f(0.32531259+$x,0.067998075+$y,0.38742297+$z);


    glNormal3f( -0.000249958942550902,-0.000100112638765799,-0.000131167185474439);
    glTexCoord2f(-0.050777897,-0.19571504); glVertex3f(0.32879117+$x,0.081973995+$y,0.37249478+$z);
    glTexCoord2f(-0.030088724,-0.24189388); glVertex3f(0.32873605+$x,0.065083117+$y,0.38549169+$z);
    glTexCoord2f(0.056841784,-0.35442366); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);


    glNormal3f( -0.00384719153858504,0.0032757462360389,0.00217030955386348);
    glTexCoord2f(-0.024731059,-0.219187); glVertex3f(0.32531259+$x,0.067998075+$y,0.38742297+$z);
    glTexCoord2f(0.054156923,-0.2888844); glVertex3f(0.31742004+$x,0.029087611+$y,0.43216159+$z);
    glTexCoord2f(0.12496866,-0.12125842); glVertex3f(0.38575721+$x,0.091009479+$y,0.45983776+$z);


    glNormal3f( -0.000205557810087239,-0.000137918678372899,-0.000156215257952979);
    glTexCoord2f(-0.024731059,-0.219187); glVertex3f(0.32531259+$x,0.067998075+$y,0.38742297+$z);
    glTexCoord2f(0.048624373,-0.29579525); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);
    glTexCoord2f(0.054156923,-0.2888844); glVertex3f(0.31742004+$x,0.029087611+$y,0.43216159+$z);


    glNormal3f( -0.0101016554163582,0.00860119634869222,0.00569862995500971);
    glTexCoord2f(0.054156923,-0.2888844); glVertex3f(0.31742004+$x,0.029087611+$y,0.43216159+$z);
    glTexCoord2f(0.11272741,-0.32927678); glVertex3f(0.31424346+$x,0.0057661953+$y,0.46173069+$z);
    glTexCoord2f(0.71173287,0.153326); glVertex3f(0.57639145+$x,0.13642001+$y,0.72922473+$z);


    glNormal3f( -0.000131232635096739,-9.50940931203995e-005,-8.90997642901187e-005);
    glTexCoord2f(0.054156923,-0.2888844); glVertex3f(0.31742004+$x,0.029087611+$y,0.43216159+$z);
    glTexCoord2f(0.048624373,-0.29579525); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);
    glTexCoord2f(0.11272741,-0.32927678); glVertex3f(0.31424346+$x,0.0057661953+$y,0.46173069+$z);


    glNormal3f( -0.00946170009664083,0.00805630150451478,0.00533761103005881);
    glTexCoord2f(0.11272741,-0.32927678); glVertex3f(0.31424346+$x,0.0057661953+$y,0.46173069+$z);
    glTexCoord2f(0.17104309,-0.36612654); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);
    glTexCoord2f(0.71173287,0.153326); glVertex3f(0.57639145+$x,0.13642001+$y,0.72922473+$z);


    glNormal3f( -7.05106470523153e-005,-0.000143935131059702,-0.000108017142642814);
    glTexCoord2f(0.48995704,0.77634045); glVertex3f(0.31424346+$x,0.0057661953+$y,0.46173069+$z);
    glTexCoord2f(0.47622365,0.84888308); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);
    glTexCoord2f(0.49316227,0.7065843); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);


    glNormal3f( -0.012391271292572,0.010550724297425,0.0069902667840116);
    glTexCoord2f(0.17104309,-0.36612654); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);
    glTexCoord2f(0.25671489,-0.41140866); glVertex3f(0.31340047+$x,-0.042761798+$y,0.53348187+$z);
    glTexCoord2f(0.73384276,0.10372462); glVertex3f(0.5645251+$x,0.11446657+$y,0.74132519+$z);


    glNormal3f( 3.97592641504986e-005,-3.38535548370009e-005,-2.24293025416905e-005);
    glTexCoord2f(0.46538681,0.54883983); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);
    glTexCoord2f(0.34647659,0.49885953); glVertex3f(0.31442134+$x,-0.050708064+$y,0.54728517+$z);
    glTexCoord2f(0.37558149,0.50929893); glVertex3f(0.31340047+$x,-0.042761798+$y,0.53348187+$z);


    glNormal3f( -0.000232648959075912,-0.000196382979870899,-0.00011599548156865);
    glTexCoord2f(0.19512165,-0.2884162); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);
    glTexCoord2f(0.27784396,-0.43148783); glVertex3f(0.31784481+$x,-0.053623022+$y,0.5453539+$z);
    glTexCoord2f(0.28462647,-0.42376976); glVertex3f(0.31442134+$x,-0.050708064+$y,0.54728517+$z);


    glNormal3f( -0.000232649341680219,-0.000196383031288299,-0.00011599548156865);
    glTexCoord2f(0.19512165,-0.2884162); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);
    glTexCoord2f(0.18337902,-0.29489502); glVertex3f(0.31612654+$x,-0.018277549+$y,0.48895949+$z);
    glTexCoord2f(0.27784396,-0.43148783); glVertex3f(0.31784481+$x,-0.053623022+$y,0.5453539+$z);


    glNormal3f( -0.000125805981153139,-9.68537197564995e-005,-7.68239080114597e-005);
    glTexCoord2f(0.19512165,-0.2884162); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);
    glTexCoord2f(0.13737043,-0.18449876); glVertex3f(0.31766692+$x,0.002851237+$y,0.45979942+$z);
    glTexCoord2f(0.18337902,-0.29489502); glVertex3f(0.31612654+$x,-0.018277549+$y,0.48895949+$z);


    glNormal3f( -0.010017952373891,0.00852992827430708,0.00565141046378313);
    glTexCoord2f(0.25671489,-0.41140866); glVertex3f(0.31340047+$x,-0.042761798+$y,0.53348187+$z);
    glTexCoord2f(0.76511437,-0.047357368); glVertex3f(0.52188213+$x,0.051100818+$y,0.76137506+$z);
    glTexCoord2f(0.75126648,0.049134097); glVertex3f(0.55021628+$x,0.09096489+$y,0.75143285+$z);


    glNormal3f( -0.00310651375476134,0.00264508557660269,0.00175247225527748);
    glTexCoord2f(0.28462647,-0.42376976); glVertex3f(0.31442134+$x,-0.050708064+$y,0.54728517+$z);
    glTexCoord2f(0.76511437,-0.047357368); glVertex3f(0.52188213+$x,0.051100818+$y,0.76137506+$z);
    glTexCoord2f(0.25671489,-0.41140866); glVertex3f(0.31340047+$x,-0.042761798+$y,0.53348187+$z);


    glNormal3f( -0.000202895498967591,-0.0001956118127337,-6.44169046420096e-005);
    glTexCoord2f(0.28462647,-0.42376976); glVertex3f(0.31442134+$x,-0.050708064+$y,0.54728517+$z);
    glTexCoord2f(0.27784396,-0.43148783); glVertex3f(0.31784481+$x,-0.053623022+$y,0.5453539+$z);
    glTexCoord2f(0.39220405,-0.46018941); glVertex3f(0.32235586+$x,-0.076280275+$y,0.59994756+$z);


    glNormal3f( -0.0108362508893948,0.00922668051868532,0.00611303570651333);
    glTexCoord2f(0.39220405,-0.46018941); glVertex3f(0.32235586+$x,-0.076280275+$y,0.59994756+$z);
    glTexCoord2f(0.76511437,-0.047357368); glVertex3f(0.52188213+$x,0.051100818+$y,0.76137506+$z);
    glTexCoord2f(0.28462647,-0.42376976); glVertex3f(0.31442134+$x,-0.050708064+$y,0.54728517+$z);


    glNormal3f( -0.000167778783356181,-0.0001896348339869,-1.11884631164797e-005);
    glTexCoord2f(0.76967809,0.71888001); glVertex3f(0.32235586+$x,-0.076280275+$y,0.59994756+$z);
    glTexCoord2f(0.76184734,0.72263735); glVertex3f(0.32577933+$x,-0.079195233+$y,0.59801628+$z);
    glTexCoord2f(0.7299092,0.63597116); glVertex3f(0.33628761+$x,-0.091410809+$y,0.64748083+$z);


    glNormal3f( -0.000202895725540122,-0.0001956118578442,-6.44169046420096e-005);
    glTexCoord2f(0.39220405,-0.46018941); glVertex3f(0.32235586+$x,-0.076280275+$y,0.59994756+$z);
    glTexCoord2f(0.27784396,-0.43148783); glVertex3f(0.31784481+$x,-0.053623022+$y,0.5453539+$z);
    glTexCoord2f(0.38902262,-0.46940448); glVertex3f(0.32577933+$x,-0.079195233+$y,0.59801628+$z);


    glNormal3f( -0.00666850020455982,0.00567799020818499,0.00376188933817275);
    glTexCoord2f(0.49121175,-0.47257055); glVertex3f(0.33628761+$x,-0.091410809+$y,0.64748083+$z);
    glTexCoord2f(0.7618666,-0.14611787); glVertex3f(0.48972161+$x,0.011975412+$y,0.76341957+$z);
    glTexCoord2f(0.39220405,-0.46018941); glVertex3f(0.32235586+$x,-0.076280275+$y,0.59994756+$z);


    glNormal3f( -3.58290125007298e-005,-4.58647178740996e-005,5.71342463220995e-006);
    glTexCoord2f(0.7299092,0.63597116); glVertex3f(0.33628761+$x,-0.091410809+$y,0.64748083+$z);
    glTexCoord2f(0.72156338,0.6398013); glVertex3f(0.33971108+$x,-0.094325768+$y,0.64554955+$z);
    glTexCoord2f(0.72194404,0.61067194); glVertex3f(0.34068198+$x,-0.093483555+$y,0.65839898+$z);


    glNormal3f( -0.00016777883282073,-0.000189634833986899,-1.11884526081997e-005);
    glTexCoord2f(0.7299092,0.63597116); glVertex3f(0.33628761+$x,-0.091410809+$y,0.64748083+$z);
    glTexCoord2f(0.76184734,0.72263735); glVertex3f(0.32577933+$x,-0.079195233+$y,0.59801628+$z);
    glTexCoord2f(0.72156338,0.6398013); glVertex3f(0.33971108+$x,-0.094325768+$y,0.64554955+$z);


    glNormal3f( -0.000855091388104697,0.000728079547424498,0.000482381347824638);
    glTexCoord2f(0.51424507,-0.47187376); glVertex3f(0.34068198+$x,-0.093483555+$y,0.65839898+$z);
    glTexCoord2f(0.74174218,-0.26647232); glVertex3f(0.4476073+$x,-0.034145739+$y,0.75837853+$z);
    glTexCoord2f(0.49121175,-0.47257055); glVertex3f(0.33628761+$x,-0.091410809+$y,0.64748083+$z);


    glNormal3f( -5.03658896070897e-005,-0.000167584333698799,1.47899125997799e-005);
    glTexCoord2f(0.72194404,0.61067194); glVertex3f(0.34068198+$x,-0.093483555+$y,0.65839898+$z);
    glTexCoord2f(0.72156338,0.6398013); glVertex3f(0.33971108+$x,-0.094325768+$y,0.64554955+$z);
    glTexCoord2f(0.69213374,0.53973558); glVertex3f(0.35599764+$x,-0.095431093+$y,0.68848773+$z);


    glNormal3f( 5.84547504339997e-005,-4.97721585165994e-005,-3.29759605475199e-005);
    glTexCoord2f(0.518854,0.49857835); glVertex3f(0.35599764+$x,-0.095431093+$y,0.68848773+$z);
    glTexCoord2f(0.44909621,0.54176113); glVertex3f(0.3812669+$x,-0.087672685+$y,0.72157109+$z);
    glTexCoord2f(0.48170259,0.51708057); glVertex3f(0.36795103+$x,-0.093066033+$y,0.70610718+$z);


    glNormal3f( -0.00095211250062327,0.000810689525176099,0.00053711370521468);
    glTexCoord2f(0.57855409,-0.46043826); glVertex3f(0.35599764+$x,-0.095431093+$y,0.68848773+$z);
    glTexCoord2f(0.70671193,-0.35851341); glVertex3f(0.41187647+$x,-0.067467064+$y,0.74533377+$z);
    glTexCoord2f(0.51424507,-0.47187376); glVertex3f(0.34068198+$x,-0.093483555+$y,0.65839898+$z);


    glNormal3f( -8.14530573640804e-005,-0.000162061654219398,0.0001002195338961);
    glTexCoord2f(0.2730978,0.83530597); glVertex3f(0.35599764+$x,-0.095431093+$y,0.68848773+$z);
    glTexCoord2f(0.2143824,0.77722595); glVertex3f(0.38469037+$x,-0.090587644+$y,0.71963982+$z);
    glTexCoord2f(0.22177941,0.77129562); glVertex3f(0.3812669+$x,-0.087672685+$y,0.72157109+$z);


    glNormal3f( -8.14530573640804e-005,-0.000162061654219398,0.0001002195338961);
    glTexCoord2f(0.2730978,0.83530597); glVertex3f(0.35599764+$x,-0.095431093+$y,0.68848773+$z);
    glTexCoord2f(0.26570079,0.8412363); glVertex3f(0.35942111+$x,-0.098346052+$y,0.68655646+$z);
    glTexCoord2f(0.2143824,0.77722595); glVertex3f(0.38469037+$x,-0.090587644+$y,0.71963982+$z);


    glNormal3f( -9.14687254053698e-005,-0.000132586641885399,3.797717961761e-005);
    glTexCoord2f(0.2730978,0.83530597); glVertex3f(0.35599764+$x,-0.095431093+$y,0.68848773+$z);
    glTexCoord2f(0.30668433,0.8923558); glVertex3f(0.34410545+$x,-0.096398513+$y,0.6564677+$z);
    glTexCoord2f(0.26570079,0.8412363); glVertex3f(0.35942111+$x,-0.098346052+$y,0.68655646+$z);


    glNormal3f( -0.000358266515401649,0.000305051365167898,0.00020210815892851);
    glTexCoord2f(0.61696354,-0.44487305); glVertex3f(0.36795103+$x,-0.093066033+$y,0.70610718+$z);
    glTexCoord2f(0.70671193,-0.35851341); glVertex3f(0.41187647+$x,-0.067467064+$y,0.74533377+$z);
    glTexCoord2f(0.57855409,-0.46043826); glVertex3f(0.35599764+$x,-0.095431093+$y,0.68848773+$z);


    glNormal3f( -0.0001144875712448,9.74821329057997e-005,6.45856415853603e-005);
    glTexCoord2f(0.65137367,-0.42278013); glVertex3f(0.3812669+$x,-0.087672685+$y,0.72157109+$z);
    glTexCoord2f(0.69465952,-0.37713805); glVertex3f(0.40373539+$x,-0.073721961+$y,0.74034332+$z);
    glTexCoord2f(0.61696354,-0.44487305); glVertex3f(0.36795103+$x,-0.093066033+$y,0.70610718+$z);


    glNormal3f( 2.0020327247651e-005,-0.000148357049486001,8.62903197048493e-005);
    glTexCoord2f(0.58061771,0.55196095); glVertex3f(0.3812669+$x,-0.087672685+$y,0.72157109+$z);
    glTexCoord2f(0.51423526,0.49855715); glVertex3f(0.41529993+$x,-0.070382022+$y,0.7434025+$z);
    glTexCoord2f(0.53679224,0.50693375); glVertex3f(0.40373539+$x,-0.073721961+$y,0.74034332+$z);


    glNormal3f( -3.02447263301811e-005,-0.000140466147040797,0.000158398953156379);
    glTexCoord2f(0.49550804,0.50420688); glVertex3f(0.3812669+$x,-0.087672685+$y,0.72157109+$z);
    glTexCoord2f(0.50220797,0.49749902); glVertex3f(0.38469037+$x,-0.090587644+$y,0.71963982+$z);
    glTexCoord2f(0.56211283,0.55733313); glVertex3f(0.41529993+$x,-0.070382022+$y,0.7434025+$z);


    glNormal3f( -0.000117607905265181,0.0001001390952692,6.63458483331611e-005);
    glTexCoord2f(0.69465952,-0.37713805); glVertex3f(0.40373539+$x,-0.073721961+$y,0.74034332+$z);
    glTexCoord2f(0.70671193,-0.35851341); glVertex3f(0.41187647+$x,-0.067467064+$y,0.74533377+$z);
    glTexCoord2f(0.61696354,-0.44487305); glVertex3f(0.36795103+$x,-0.093066033+$y,0.70610718+$z);


    glNormal3f( -2.46705722190971e-006,-3.28072295286001e-005,4.51442959582599e-005);
    glTexCoord2f(0.73320397,0.29679609); glVertex3f(0.40373539+$x,-0.073721961+$y,0.74034332+$z);
    glTexCoord2f(0.75554488,0.30573299); glVertex3f(0.41529993+$x,-0.070382022+$y,0.7434025+$z);
    glTexCoord2f(0.74884017,0.31243608); glVertex3f(0.41187647+$x,-0.067467064+$y,0.74533377+$z);


    glNormal3f( -0.00255740351025959,0.0021775371672033,0.00144270392238172);
    glTexCoord2f(0.70671193,-0.35851341); glVertex3f(0.41187647+$x,-0.067467064+$y,0.74533377+$z);
    glTexCoord2f(0.74174218,-0.26647232); glVertex3f(0.4476073+$x,-0.034145739+$y,0.75837853+$z);
    glTexCoord2f(0.51424507,-0.47187376); glVertex3f(0.34068198+$x,-0.093483555+$y,0.65839898+$z);


    glNormal3f( 2.63275478126714e-005,-0.000113664224571302,0.000218228425252891);
    glTexCoord2f(0.74884017,0.31243608); glVertex3f(0.41187647+$x,-0.067467064+$y,0.74533377+$z);
    glTexCoord2f(0.82481245,0.37501733); glVertex3f(0.45103077+$x,-0.037060697+$y,0.75644726+$z);
    glTexCoord2f(0.81810774,0.38172042); glVertex3f(0.4476073+$x,-0.034145739+$y,0.75837853+$z);


    glNormal3f( 2.63275478126713e-005,-0.000113664113436401,0.00021822812118922);
    glTexCoord2f(0.74884017,0.31243608); glVertex3f(0.41187647+$x,-0.067467064+$y,0.74533377+$z);
    glTexCoord2f(0.75554488,0.30573299); glVertex3f(0.41529993+$x,-0.070382022+$y,0.7434025+$z);
    glTexCoord2f(0.82481245,0.37501733); glVertex3f(0.45103077+$x,-0.037060697+$y,0.75644726+$z);


    glNormal3f( -0.0048260540587799,0.00410921310600939,0.00272251332161149);
    glTexCoord2f(0.74174218,-0.26647232); glVertex3f(0.4476073+$x,-0.034145739+$y,0.75837853+$z);
    glTexCoord2f(0.7618666,-0.14611787); glVertex3f(0.48972161+$x,0.011975412+$y,0.76341957+$z);
    glTexCoord2f(0.49121175,-0.47257055); glVertex3f(0.33628761+$x,-0.091410809+$y,0.64748083+$z);


    glNormal3f( 7.43779754154517e-005,-9.85919526825021e-005,0.000280655821662952);
    glTexCoord2f(0.81810774,0.38172042); glVertex3f(0.4476073+$x,-0.034145739+$y,0.75837853+$z);
    glTexCoord2f(0.82481245,0.37501733); glVertex3f(0.45103077+$x,-0.037060697+$y,0.75644726+$z);
    glTexCoord2f(0.90393707,0.46757052); glVertex3f(0.48972161+$x,0.011975412+$y,0.76341957+$z);


    glNormal3f( -0.00399951960762965,0.00340544806994331,0.00225624215310604);
    glTexCoord2f(0.7618666,-0.14611787); glVertex3f(0.48972161+$x,0.011975412+$y,0.76341957+$z);
    glTexCoord2f(0.76562943,-0.084570539); glVertex3f(0.51008144+$x,0.036192511+$y,0.76295839+$z);
    glTexCoord2f(0.39220405,-0.46018941); glVertex3f(0.32235586+$x,-0.076280275+$y,0.59994756+$z);


    glNormal3f( 0.000191463594277315,-0.000159798487898504,6.1386940428313e-005);
    glTexCoord2f(0.74182746,0.66323922); glVertex3f(0.48972161+$x,0.011975412+$y,0.76341957+$z);
    glTexCoord2f(0.75573878,0.54227115); glVertex3f(0.45103077+$x,-0.037060697+$y,0.75644726+$z);
    glTexCoord2f(0.74274761,0.72453492); glVertex3f(0.51008144+$x,0.036192511+$y,0.76295839+$z);


    glNormal3f( -0.00260829703422219,0.00222087181405411,0.00147141409737072);
    glTexCoord2f(0.76562943,-0.084570539); glVertex3f(0.51008144+$x,0.036192511+$y,0.76295839+$z);
    glTexCoord2f(0.76511437,-0.047357368); glVertex3f(0.52188213+$x,0.051100818+$y,0.76137506+$z);
    glTexCoord2f(0.39220405,-0.46018941); glVertex3f(0.32235586+$x,-0.076280275+$y,0.59994756+$z);


    glNormal3f( 3.34073065100306e-005,-1.73698516545007e-005,8.54365084032393e-005);
    glTexCoord2f(0.45739586,0.61158166); glVertex3f(0.51008144+$x,0.036192511+$y,0.76295839+$z);
    glTexCoord2f(0.48283397,0.63727509); glVertex3f(0.52530559+$x,0.04818586+$y,0.75944379+$z);
    glTexCoord2f(0.47912847,0.63946295); glVertex3f(0.52188213+$x,0.051100818+$y,0.76137506+$z);


    glNormal3f( 4.81140778886792e-005,-3.77414976013006e-005,0.000142254320449065);
    glTexCoord2f(0.45739586,0.61158166); glVertex3f(0.51008144+$x,0.036192511+$y,0.76295839+$z);
    glTexCoord2f(0.41714992,0.50646187); glVertex3f(0.49314507+$x,0.0090604536+$y,0.7614883+$z);
    glTexCoord2f(0.46957829,0.60462015); glVertex3f(0.5135049+$x,0.033277553+$y,0.76102712+$z);


    glNormal3f( 0.000105969410908622,-2.06841356239019e-005,0.000219065913144817);
    glTexCoord2f(0.47912847,0.63946295); glVertex3f(0.52188213+$x,0.051100818+$y,0.76137506+$z);
    glTexCoord2f(0.48283397,0.63727509); glVertex3f(0.52530559+$x,0.04818586+$y,0.75944379+$z);
    glTexCoord2f(0.493245,0.65974822); glVertex3f(0.55021628+$x,0.09096489+$y,0.75143285+$z);


    glNormal3f( -2.89762938359997e-006,1.87586978509001e-005,-1.71909708685001e-005);
    glTexCoord2f(-0.1099093,0.68060229); glVertex3f(0.33302957+$x,0.3970261+$y,0.41679802+$z);
    glTexCoord2f(-0.10868428,0.67193198); glVertex3f(0.32976633+$x,0.39935829+$y,0.41989293+$z);
    glTexCoord2f(-0.10117832,0.68123918); glVertex3f(0.336635+$x,0.39971742+$y,0.41912706+$z);


    glNormal3f( -1.03336240308001e-005,8.80977253090002e-006,-1.75343252893001e-005);
    glTexCoord2f(0.9377108,0.31652768); glVertex3f(0.33302957+$x,0.3970261+$y,0.41679802+$z);
    glTexCoord2f(0.95111483,0.31621163); glVertex3f(0.32692146+$x,0.39601819+$y,0.41989135+$z);
    glTexCoord2f(0.9454571,0.32255537); glVertex3f(0.32976633+$x,0.39935829+$y,0.41989293+$z);


    glNormal3f( -1.19322003153e-005,1.01724599148e-005,-2.02468756954999e-005);
    glTexCoord2f(0.94424379,0.30920258); glVertex3f(0.32974461+$x,0.39316929+$y,0.41679622+$z);
    glTexCoord2f(0.95111483,0.31621163); glVertex3f(0.32692146+$x,0.39601819+$y,0.41989135+$z);
    glTexCoord2f(0.9377108,0.31652768); glVertex3f(0.33302957+$x,0.3970261+$y,0.41679802+$z);


    glNormal3f( -1.89726372260999e-005,-1.14999418199943e-007,-1.71995938594999e-005);
    glTexCoord2f(0.15859616,0.44373297); glVertex3f(0.32766025+$x,0.38918032+$y,0.41912212+$z);
    glTexCoord2f(0.16172482,0.45684831); glVertex3f(0.32692146+$x,0.39601819+$y,0.41989135+$z);
    glTexCoord2f(0.15319632,0.4519907); glVertex3f(0.32974461+$x,0.39316929+$y,0.41679622+$z);


    glNormal3f( -1.64308727298001e-005,-9.96076239999758e-008,-1.48952335193999e-005);
    glTexCoord2f(0.15859616,0.44373297); glVertex3f(0.32766025+$x,0.38918032+$y,0.41912212+$z);
    glTexCoord2f(0.1658782,0.44964347); glVertex3f(0.32511636+$x,0.39256363+$y,0.42190565+$z);
    glTexCoord2f(0.16172482,0.45684831); glVertex3f(0.32692146+$x,0.39601819+$y,0.41989135+$z);


    glNormal3f( -0.000828612949862401,-0.000190753345621398,-0.000525420058433398);
    glTexCoord2f(0.38809463,0.16698811); glVertex3f(0.27908689+$x,0.2472397+$y,0.5472561+$z);
    glTexCoord2f(0.1658782,0.44964347); glVertex3f(0.32511636+$x,0.39256363+$y,0.42190565+$z);
    glTexCoord2f(0.15859616,0.44373297); glVertex3f(0.32766025+$x,0.38918032+$y,0.41912212+$z);


    glNormal3f( -0.000828614203366893,-0.0001907533456214,-0.000525420518728098);
    glTexCoord2f(0.38809463,0.16698811); glVertex3f(0.27908689+$x,0.2472397+$y,0.5472561+$z);
    glTexCoord2f(0.39530141,0.17268777); glVertex3f(0.276543+$x,0.25062302+$y,0.55003963+$z);
    glTexCoord2f(0.1658782,0.44964347); glVertex3f(0.32511636+$x,0.39256363+$y,0.42190565+$z);


    glNormal3f( -2.21322300368998e-005,-9.34771334250002e-006,-8.86487774969986e-006);
    glTexCoord2f(0.39387684,0.15989986); glVertex3f(0.27876168+$x,0.24418745+$y,0.55128652+$z);
    glTexCoord2f(0.39530141,0.17268777); glVertex3f(0.276543+$x,0.25062302+$y,0.55003963+$z);
    glTexCoord2f(0.38809463,0.16698811); glVertex3f(0.27908689+$x,0.2472397+$y,0.5472561+$z);


    glNormal3f( -1.91670167381998e-005,-8.09535598770002e-006,-7.67730388169978e-006);
    glTexCoord2f(0.39387684,0.15989986); glVertex3f(0.27876168+$x,0.24418745+$y,0.55128652+$z);
    glTexCoord2f(0.40075363,0.16777216); glVertex3f(0.27626135+$x,0.24797968+$y,0.55353007+$z);
    glTexCoord2f(0.39530141,0.17268777); glVertex3f(0.276543+$x,0.25062302+$y,0.55003963+$z);


    glNormal3f( -2.05641786668e-005,-1.50514429932999e-005,2.52336734929993e-006);
    glTexCoord2f(0.40358805,0.15401536); glVertex3f(0.28028271+$x,0.24288973+$y,0.55594148+$z);
    glTexCoord2f(0.40075363,0.16777216); glVertex3f(0.27626135+$x,0.24797968+$y,0.55353007+$z);
    glTexCoord2f(0.39387684,0.15989986); glVertex3f(0.27876168+$x,0.24418745+$y,0.55128652+$z);


    glNormal3f( -1.78092291191e-005,-1.30349511580999e-005,2.18547321409989e-006);
    glTexCoord2f(0.40358805,0.15401536); glVertex3f(0.28028271+$x,0.24288973+$y,0.55594148+$z);
    glTexCoord2f(0.40890584,0.16419851); glVertex3f(0.27757862+$x,0.24685584+$y,0.5575614+$z);
    glTexCoord2f(0.40075363,0.16777216); glVertex3f(0.27626135+$x,0.24797968+$y,0.55353007+$z);


    glNormal3f( -1.46888404322001e-005,-1.56980925974001e-005,1.39145238698e-005);
    glTexCoord2f(0.81568094,0.59161198); glVertex3f(0.28324249+$x,0.24369433+$y,0.5599737+$z);
    glTexCoord2f(0.82908759,0.59143915); glVertex3f(0.27757862+$x,0.24685584+$y,0.5575614+$z);
    glTexCoord2f(0.82247673,0.59869411); glVertex3f(0.28028271+$x,0.24288973+$y,0.55594148+$z);


    glNormal3f( -1.27208353140002e-005,-1.35949543110002e-005,1.20501486159002e-005);
    glTexCoord2f(0.81568094,0.59161198); glVertex3f(0.28324249+$x,0.24369433+$y,0.5599737+$z);
    glTexCoord2f(0.82320229,0.58530591); glVertex3f(0.28014185+$x,0.24755262+$y,0.5610534+$z);
    glTexCoord2f(0.82908759,0.59143915); glVertex3f(0.27757862+$x,0.24685584+$y,0.5575614+$z);


    glNormal3f( -2.50938560159998e-006,1.62455742752999e-005,-1.48874724309002e-005);
    glTexCoord2f(-0.10868428,0.67193198); glVertex3f(0.32976633+$x,0.39935829+$y,0.41989293+$z);
    glTexCoord2f(-0.10145397,0.67301994); glVertex3f(0.3328887+$x,0.40168899+$y,0.42190995+$z);
    glTexCoord2f(-0.10117832,0.68123918); glVertex3f(0.336635+$x,0.39971742+$y,0.41912706+$z);


    glNormal3f( -9.61185194340003e-006,1.85126710199998e-005,-6.51244122210007e-006);
    glTexCoord2f(-0.10868428,0.67193198); glVertex3f(0.32976633+$x,0.39935829+$y,0.41989293+$z);
    glTexCoord2f(-0.10579003,0.6640738); glVertex3f(0.32769787+$x,0.39990002+$y,0.42448577+$z);
    glTexCoord2f(-0.10145397,0.67301994); glVertex3f(0.3328887+$x,0.40168899+$y,0.42190995+$z);


    glNormal3f( -5.54942779039996e-006,1.06883856403999e-005,-3.75994246419993e-006);
    glTexCoord2f(-0.10145397,0.67301994); glVertex3f(0.3328887+$x,0.40168899+$y,0.42190995+$z);
    glTexCoord2f(-0.10579003,0.6640738); glVertex3f(0.32769787+$x,0.39990002+$y,0.42448577+$z);
    glTexCoord2f(-0.10177397,0.66482714); glVertex3f(0.32950058+$x,0.40124565+$y,0.42565031+$z);


    glNormal3f( 5.67083244603049e-005,0.000848698878443601,-0.000524930145225807);
    glTexCoord2f(-0.10145397,0.67301994); glVertex3f(0.3328887+$x,0.40168899+$y,0.42190995+$z);
    glTexCoord2f(0.21739621,0.65756961); glVertex3f(0.46523234+$x,0.47215996+$y,0.55014343+$z);
    glTexCoord2f(-0.10117832,0.68123918); glVertex3f(0.336635+$x,0.39971742+$y,0.41912706+$z);


    glNormal3f( -1.53396889506e-005,1.30693008976e-005,-8.45001467110006e-006);
    glTexCoord2f(0.16172482,0.45684831); glVertex3f(0.32692146+$x,0.39601819+$y,0.41989135+$z);
    glTexCoord2f(0.17089909,0.46444162); glVertex3f(0.32769787+$x,0.39990002+$y,0.42448577+$z);
    glTexCoord2f(0.16095751,0.46536328); glVertex3f(0.32976633+$x,0.39935829+$y,0.41989293+$z);


    glNormal3f( -1.98033730194001e-005,6.54725411000003e-006,-6.51798961379997e-006);
    glTexCoord2f(0.1658782,0.44964347); glVertex3f(0.32511636+$x,0.39256363+$y,0.42190565+$z);
    glTexCoord2f(0.17100334,0.45965713); glVertex3f(0.32605538+$x,0.39797158+$y,0.42448489+$z);
    glTexCoord2f(0.16172482,0.45684831); glVertex3f(0.32692146+$x,0.39601819+$y,0.41989135+$z);


    glNormal3f( -0.000968547389234305,0.000168550187874601,-0.000180447719892899);
    glTexCoord2f(0.1658782,0.44964347); glVertex3f(0.32511636+$x,0.39256363+$y,0.42190565+$z);
    glTexCoord2f(0.39530141,0.17268777); glVertex3f(0.276543+$x,0.25062302+$y,0.55003963+$z);
    glTexCoord2f(0.17310526,0.45559034); glVertex3f(0.32501319+$x,0.3959771+$y,0.42564782+$z);


    glNormal3f( -1.14333098886999e-005,3.7800726642e-006,-3.76325480089999e-006);
    glTexCoord2f(0.17310526,0.45559034); glVertex3f(0.32501319+$x,0.3959771+$y,0.42564782+$z);
    glTexCoord2f(0.17100334,0.45965713); glVertex3f(0.32605538+$x,0.39797158+$y,0.42448489+$z);
    glTexCoord2f(0.1658782,0.44964347); glVertex3f(0.32511636+$x,0.39256363+$y,0.42190565+$z);


    glNormal3f( -1.03169278664999e-005,6.60481959699999e-006,2.08179472249986e-006);
    glTexCoord2f(0.17310526,0.45559034); glVertex3f(0.32501319+$x,0.3959771+$y,0.42564782+$z);
    glTexCoord2f(0.18028293,0.4615538); glVertex3f(0.32737847+$x,0.39850611+$y,0.42934596+$z);
    glTexCoord2f(0.17100334,0.45965713); glVertex3f(0.32605538+$x,0.39797158+$y,0.42448489+$z);


    glNormal3f( -0.000848968364225201,0.000482703788783397,0.000212886798137296);
    glTexCoord2f(0.17310526,0.45559034); glVertex3f(0.32501319+$x,0.3959771+$y,0.42564782+$z);
    glTexCoord2f(0.4025063,0.17834191); glVertex3f(0.27643984+$x,0.25403649+$y,0.5537818+$z);
    glTexCoord2f(0.18028293,0.4615538); glVertex3f(0.32737847+$x,0.39850611+$y,0.42934596+$z);


    glNormal3f( -8.8566472944002e-006,7.54560566499998e-006,-4.8786068563e-006);
    glTexCoord2f(0.17100334,0.45965713); glVertex3f(0.32605538+$x,0.39797158+$y,0.42448489+$z);
    glTexCoord2f(0.17089909,0.46444162); glVertex3f(0.32769787+$x,0.39990002+$y,0.42448577+$z);
    glTexCoord2f(0.16172482,0.45684831); glVertex3f(0.32692146+$x,0.39601819+$y,0.41989135+$z);


    glNormal3f( -9.3738114444002e-006,7.98309454510005e-006,1.67353949989993e-006);
    glTexCoord2f(0.18028293,0.4615538); glVertex3f(0.32737847+$x,0.39850611+$y,0.42934596+$z);
    glTexCoord2f(0.17089909,0.46444162); glVertex3f(0.32769787+$x,0.39990002+$y,0.42448577+$z);
    glTexCoord2f(0.17100334,0.45965713); glVertex3f(0.32605538+$x,0.39797158+$y,0.42448489+$z);


    glNormal3f( -0.000611736751123202,0.000761221286452306,0.000213013539204599);
    glTexCoord2f(-0.1021003,0.65663401); glVertex3f(0.32737847+$x,0.39850611+$y,0.42934596+$z);
    glTexCoord2f(0.21621668,0.6418782); glVertex3f(0.4597221+$x,0.46897707+$y,0.55757944+$z);
    glTexCoord2f(-0.10177397,0.66482714); glVertex3f(0.32950058+$x,0.40124565+$y,0.42565031+$z);


    glNormal3f( -0.0272312636575532,0.0231864470687417,0.0153619249668983);
    glTexCoord2f(0.18028293,0.4615538); glVertex3f(0.32737847+$x,0.39850611+$y,0.42934596+$z);
    glTexCoord2f(0.68975291,0.41228774); glVertex3f(0.41114875+$x,0.32703646+$y,0.68571343+$z);
    glTexCoord2f(0.45917095,0.69139126); glVertex3f(0.4597221+$x,0.46897707+$y,0.55757944+$z);


    glNormal3f( -8.16328142109998e-006,9.13346719090003e-006,2.08302127409995e-006);
    glTexCoord2f(-0.10177397,0.66482714); glVertex3f(0.32950058+$x,0.40124565+$y,0.42565031+$z);
    glTexCoord2f(-0.10579003,0.6640738); glVertex3f(0.32769787+$x,0.39990002+$y,0.42448577+$z);
    glTexCoord2f(-0.1021003,0.65663401); glVertex3f(0.32737847+$x,0.39850611+$y,0.42934596+$z);


    glNormal3f( -0.000320437790968802,0.000929483275568001,-0.000180090839637598);
    glTexCoord2f(-0.10177397,0.66482714); glVertex3f(0.32950058+$x,0.40124565+$y,0.42565031+$z);
    glTexCoord2f(0.21676935,0.64962874); glVertex3f(0.46184422+$x,0.47171661+$y,0.55388379+$z);
    glTexCoord2f(-0.10145397,0.67301994); glVertex3f(0.3328887+$x,0.40168899+$y,0.42190995+$z);


    glNormal3f( -0.000968547389234302,0.000168551431792701,-0.0001804462663521);
    glTexCoord2f(0.39530141,0.17268777); glVertex3f(0.276543+$x,0.25062302+$y,0.55003963+$z);
    glTexCoord2f(0.4025063,0.17834191); glVertex3f(0.27643984+$x,0.25403649+$y,0.5537818+$z);
    glTexCoord2f(0.17310526,0.45559034); glVertex3f(0.32501319+$x,0.3959771+$y,0.42564782+$z);


    glNormal3f( -1.25899650502002e-005,4.0058571520006e-007,-7.12465792800036e-007);
    glTexCoord2f(0.39530141,0.17268777); glVertex3f(0.276543+$x,0.25062302+$y,0.55003963+$z);
    glTexCoord2f(0.40569757,0.17596038); glVertex3f(0.27627724+$x,0.25251036+$y,0.55579703+$z);
    glTexCoord2f(0.4025063,0.17834191); glVertex3f(0.27643984+$x,0.25403649+$y,0.5537818+$z);


    glNormal3f( -0.000848967119866803,0.000482702544425005,0.000212885862827404);
    glTexCoord2f(0.4025063,0.17834191); glVertex3f(0.27643984+$x,0.25403649+$y,0.5537818+$z);
    glTexCoord2f(0.40970839,0.18399996); glVertex3f(0.27880511+$x,0.25656549+$y,0.55747994+$z);
    glTexCoord2f(0.18028293,0.4615538); glVertex3f(0.32737847+$x,0.39850611+$y,0.42934596+$z);


    glNormal3f( -1.07403590682002e-005,5.36788062610019e-006,3.19849410510005e-006);
    glTexCoord2f(0.4025063,0.17834191); glVertex3f(0.27643984+$x,0.25403649+$y,0.5537818+$z);
    glTexCoord2f(0.40569757,0.17596038); glVertex3f(0.27627724+$x,0.25251036+$y,0.55579703+$z);
    glTexCoord2f(0.40970839,0.18399996); glVertex3f(0.27880511+$x,0.25656549+$y,0.55747994+$z);


    glNormal3f( -9.74304760580005e-006,4.51704990690004e-006,6.25036805719998e-006);
    glTexCoord2f(0.40970839,0.18399996); glVertex3f(0.27880511+$x,0.25656549+$y,0.55747994+$z);
    glTexCoord2f(0.41030587,0.17521461); glVertex3f(0.27703776+$x,0.25186151+$y,0.5581245+$z);
    glTexCoord2f(0.41559895,0.176736); glVertex3f(0.27851765+$x,0.25226381+$y,0.56014061+$z);


    glNormal3f( -1.05301495746e-005,4.60365487570004e-006,4.72421591710016e-006);
    glTexCoord2f(0.40970839,0.18399996); glVertex3f(0.27880511+$x,0.25656549+$y,0.55747994+$z);
    glTexCoord2f(0.40569757,0.17596038); glVertex3f(0.27627724+$x,0.25251036+$y,0.55579703+$z);
    glTexCoord2f(0.41030587,0.17521461); glVertex3f(0.27703776+$x,0.25186151+$y,0.5581245+$z);


    glNormal3f( -0.0272312669359244,0.0231864487947136,0.0153619265192976);
    glTexCoord2f(0.40970839,0.18399996); glVertex3f(0.27880511+$x,0.25656549+$y,0.55747994+$z);
    glTexCoord2f(0.68975291,0.41228774); glVertex3f(0.41114875+$x,0.32703646+$y,0.68571343+$z);
    glTexCoord2f(0.18028293,0.4615538); glVertex3f(0.32737847+$x,0.39850611+$y,0.42934596+$z);


    glNormal3f( -0.000611736751123201,0.000761222605743608,0.000213012861890398);
    glTexCoord2f(0.21621668,0.6418782); glVertex3f(0.4597221+$x,0.46897707+$y,0.55757944+$z);
    glTexCoord2f(0.21676935,0.64962874); glVertex3f(0.46184422+$x,0.47171661+$y,0.55388379+$z);
    glTexCoord2f(-0.10177397,0.66482714); glVertex3f(0.32950058+$x,0.40124565+$y,0.42565031+$z);


    glNormal3f( -7.00994658899998e-006,9.74752465399997e-006,3.2004615791999e-006);
    glTexCoord2f(0.21621668,0.6418782); glVertex3f(0.4597221+$x,0.46897707+$y,0.55757944+$z);
    glTexCoord2f(0.22080539,0.64639076); glVertex3f(0.4633241+$x,0.47211891+$y,0.55589989+$z);
    glTexCoord2f(0.21676935,0.64962874); glVertex3f(0.46184422+$x,0.47171661+$y,0.55388379+$z);


    glNormal3f( -6.2228544099002e-006,9.66102238600035e-006,4.72666189680004e-006);
    glTexCoord2f(0.21621668,0.6418782); glVertex3f(0.4597221+$x,0.46897707+$y,0.55757944+$z);
    glTexCoord2f(0.22415363,0.64014002); glVertex3f(0.46408462+$x,0.47147004+$y,0.5582274+$z);
    glTexCoord2f(0.22080539,0.64639076); glVertex3f(0.4633241+$x,0.47211891+$y,0.55589989+$z);


    glNormal3f( -0.000501894064346902,0.000667508857259897,0.000549174643897595);
    glTexCoord2f(0.21621668,0.6418782); glVertex3f(0.4597221+$x,0.46897707+$y,0.55757944+$z);
    glTexCoord2f(-0.26344331,0.2494632); glVertex3f(0.41114875+$x,0.32703646+$y,0.68571343+$z);
    glTexCoord2f(0.22626699,0.63004571); glVertex3f(0.46392201+$x,0.46994392+$y,0.56024258+$z);


    glNormal3f( -0.000320439110707201,0.000929483275567999,-0.000180089550082398);
    glTexCoord2f(0.21676935,0.64962874); glVertex3f(0.46184422+$x,0.47171661+$y,0.55388379+$z);
    glTexCoord2f(0.21739621,0.65756961); glVertex3f(0.46523234+$x,0.47215996+$y,0.55014343+$z);
    glTexCoord2f(-0.10145397,0.67301994); glVertex3f(0.3328887+$x,0.40168899+$y,0.42190995+$z);


    glNormal3f( -2.39858476300008e-006,1.23660726887998e-005,-7.06935878000064e-007);
    glTexCoord2f(0.21676935,0.64962874); glVertex3f(0.46184422+$x,0.47171661+$y,0.55388379+$z);
    glTexCoord2f(0.22080539,0.64639076); glVertex3f(0.4633241+$x,0.47211891+$y,0.55589989+$z);
    glTexCoord2f(0.21739621,0.65756961); glVertex3f(0.46523234+$x,0.47215996+$y,0.55014343+$z);


    glNormal3f( 4.94571498159988e-006,2.02153041976998e-005,-7.66395991739989e-006);
    glTexCoord2f(0.21739621,0.65756961); glVertex3f(0.46523234+$x,0.47215996+$y,0.55014343+$z);
    glTexCoord2f(0.22446055,0.65560867); glVertex3f(0.46779557+$x,0.47285674+$y,0.55363544+$z);
    glTexCoord2f(0.21793725,0.66554789); glVertex3f(0.46897864+$x,0.47018838+$y,0.54736054+$z);


    glNormal3f( -4.15433320929997e-006,2.14187241281997e-005,-1.22440287570005e-006);
    glTexCoord2f(0.21739621,0.65756961); glVertex3f(0.46523234+$x,0.47215996+$y,0.55014343+$z);
    glTexCoord2f(0.22080539,0.64639076); glVertex3f(0.4633241+$x,0.47211891+$y,0.55589989+$z);
    glTexCoord2f(0.22446055,0.65560867); glVertex3f(0.46779557+$x,0.47285674+$y,0.55363544+$z);


    glNormal3f( -2.18064127455999e-005,6.93952375599806e-007,-1.23406334939994e-006);
    glTexCoord2f(0.40075363,0.16777216); glVertex3f(0.27626135+$x,0.24797968+$y,0.55353007+$z);
    glTexCoord2f(0.40569757,0.17596038); glVertex3f(0.27627724+$x,0.25251036+$y,0.55579703+$z);
    glTexCoord2f(0.39530141,0.17268777); glVertex3f(0.276543+$x,0.25062302+$y,0.55003963+$z);


    glNormal3f( -2.08123419451001e-005,-2.92213988079994e-006,5.98597881849995e-006);
    glTexCoord2f(0.40890584,0.16419851); glVertex3f(0.27757862+$x,0.24685584+$y,0.5575614+$z);
    glTexCoord2f(0.41030587,0.17521461); glVertex3f(0.27703776+$x,0.25186151+$y,0.5581245+$z);
    glTexCoord2f(0.40075363,0.16777216); glVertex3f(0.27626135+$x,0.24797968+$y,0.55353007+$z);


    glNormal3f( -1.70874892962002e-005,-3.33201568830014e-006,1.32075736197001e-005);
    glTexCoord2f(0.41910814,0.16554732); glVertex3f(0.28014185+$x,0.24755262+$y,0.5610534+$z);
    glTexCoord2f(0.41559895,0.176736); glVertex3f(0.27851765+$x,0.25226381+$y,0.56014061+$z);
    glTexCoord2f(0.40890584,0.16419851); glVertex3f(0.27757862+$x,0.24685584+$y,0.5575614+$z);


    glNormal3f( -0.000668457476219598,-8.7474876188303e-005,0.000737954919451698);
    glTexCoord2f(0.30455363,0.63232386); glVertex3f(0.28014185+$x,0.24755262+$y,0.5610534+$z);
    glTexCoord2f(0.1061502,0.75915265); glVertex3f(0.41248548+$x,0.31802358+$y,0.68928688+$z);
    glTexCoord2f(0.30128832,0.62721874); glVertex3f(0.27851765+$x,0.25226381+$y,0.56014061+$z);


    glNormal3f( -9.86544621370012e-006,-1.92375931360001e-006,7.62542895429992e-006);
    glTexCoord2f(0.41559895,0.176736); glVertex3f(0.27851765+$x,0.25226381+$y,0.56014061+$z);
    glTexCoord2f(0.41030587,0.17521461); glVertex3f(0.27703776+$x,0.25186151+$y,0.5581245+$z);
    glTexCoord2f(0.40890584,0.16419851); glVertex3f(0.27757862+$x,0.24685584+$y,0.5575614+$z);


    glNormal3f( -0.000739119408406408,0.000388984751674204,0.000549042407153602);
    glTexCoord2f(0.41559895,0.176736); glVertex3f(0.27851765+$x,0.25226381+$y,0.56014061+$z);
    glTexCoord2f(0.69567278,0.40507039); glVertex3f(0.41086129+$x,0.32273477+$y,0.6883741+$z);
    glTexCoord2f(0.40970839,0.18399996); glVertex3f(0.27880511+$x,0.25656549+$y,0.55747994+$z);


    glNormal3f( -1.20159387755999e-005,-1.68708492090021e-006,3.45598298010015e-006);
    glTexCoord2f(0.41030587,0.17521461); glVertex3f(0.27703776+$x,0.25186151+$y,0.5581245+$z);
    glTexCoord2f(0.40569757,0.17596038); glVertex3f(0.27627724+$x,0.25251036+$y,0.55579703+$z);
    glTexCoord2f(0.40075363,0.16777216); glVertex3f(0.27626135+$x,0.24797968+$y,0.55353007+$z);


    glNormal3f( 1.00339152126e-005,1.96549802357999e-005,2.20063720099999e-006);
    glTexCoord2f(0.22446055,0.65560867); glVertex3f(0.46779557+$x,0.47285674+$y,0.55363544+$z);
    glTexCoord2f(0.23223613,0.65143152); glVertex3f(0.46911283+$x,0.47173292+$y,0.55766672+$z);
    glTexCoord2f(0.22640999,0.66492618); glVertex3f(0.47193838+$x,0.47099292+$y,0.55139279+$z);


    glNormal3f( -4.29565123399993e-007,2.10086169885997e-005,5.99704136119995e-006);
    glTexCoord2f(0.22080539,0.64639076); glVertex3f(0.4633241+$x,0.47211891+$y,0.55589989+$z);
    glTexCoord2f(0.23223613,0.65143152); glVertex3f(0.46911283+$x,0.47173292+$y,0.55766672+$z);
    glTexCoord2f(0.22446055,0.65560867); glVertex3f(0.46779557+$x,0.47285674+$y,0.55363544+$z);


    glNormal3f( -6.01264799979996e-006,8.89662782919999e-006,6.2523471706998e-006);
    glTexCoord2f(0.22626699,0.63004571); glVertex3f(0.46392201+$x,0.46994392+$y,0.56024258+$z);
    glTexCoord2f(0.22415363,0.64014002); glVertex3f(0.46408462+$x,0.47147004+$y,0.5582274+$z);
    glTexCoord2f(0.21621668,0.6418782); glVertex3f(0.4597221+$x,0.46897707+$y,0.55757944+$z);


    glNormal3f( 3.25874790400151e-007,1.00415826805001e-005,7.63090674779986e-006);
    glTexCoord2f(0.22626699,0.63004571); glVertex3f(0.46392201+$x,0.46994392+$y,0.56024258+$z);
    glTexCoord2f(0.24256656,0.6429787); glVertex3f(0.46883118+$x,0.46908958+$y,0.56115717+$z);
    glTexCoord2f(0.22415363,0.64014002); glVertex3f(0.46408462+$x,0.47147004+$y,0.5582274+$z);


    glNormal3f( -2.03474780266916e-005,0.000673456199918999,0.000738308748776103);
    glTexCoord2f(0.33625047,0.69418312); glVertex3f(0.46392201+$x,0.46994392+$y,0.56024258+$z);
    glTexCoord2f(0.12448433,0.79925846); glVertex3f(0.41534865+$x,0.32800331+$y,0.68837656+$z);
    glTexCoord2f(0.33354412,0.6887604); glVertex3f(0.46883118+$x,0.46908958+$y,0.56115717+$z);


    glNormal3f( -2.48047397199999e-007,1.21296174107005e-005,3.46258012030012e-006);
    glTexCoord2f(0.22415363,0.64014002); glVertex3f(0.46408462+$x,0.47147004+$y,0.5582274+$z);
    glTexCoord2f(0.23223613,0.65143152); glVertex3f(0.46911283+$x,0.47173292+$y,0.55766672+$z);
    glTexCoord2f(0.22080539,0.64639076); glVertex3f(0.4633241+$x,0.47211891+$y,0.55589989+$z);


    glNormal3f( 5.64498375200156e-007,1.73928000725001e-005,1.32172284693999e-005);
    glTexCoord2f(0.22415363,0.64014002); glVertex3f(0.46408462+$x,0.47147004+$y,0.5582274+$z);
    glTexCoord2f(0.24256656,0.6429787); glVertex3f(0.46883118+$x,0.46908958+$y,0.56115717+$z);
    glTexCoord2f(0.23223613,0.65143152); glVertex3f(0.46911283+$x,0.47173292+$y,0.55766672+$z);


    glNormal3f( 1.13919516968e-005,1.47156399850001e-005,1.20634826435998e-005);
    glTexCoord2f(0.23223613,0.65143152); glVertex3f(0.46911283+$x,0.47173292+$y,0.55766672+$z);
    glTexCoord2f(0.24256656,0.6429787); glVertex3f(0.46883118+$x,0.46908958+$y,0.56115717+$z);
    glTexCoord2f(0.25027106,0.65780542); glVertex3f(0.47313422+$x,0.46664298+$y,0.56007815+$z);


    glNormal3f( 0.000466649363260394,0.000498954014392001,0.000729615748060799);
    glTexCoord2f(0.33354412,0.6887604); glVertex3f(0.46883118+$x,0.46908958+$y,0.56115717+$z);
    glTexCoord2f(0.12281594,0.79411589); glVertex3f(0.42025782+$x,0.32714896+$y,0.68929115+$z);
    glTexCoord2f(0.33082104,0.68336502); glVertex3f(0.47313422+$x,0.46664298+$y,0.56007815+$z);


    glNormal3f( -0.000668456818621908,-8.74749244038956e-005,0.000737954261854006);
    glTexCoord2f(0.1061502,0.75915265); glVertex3f(0.41248548+$x,0.31802358+$y,0.68928688+$z);
    glTexCoord2f(0.10223873,0.75510558); glVertex3f(0.41086129+$x,0.32273477+$y,0.6883741+$z);
    glTexCoord2f(0.30128832,0.62721874); glVertex3f(0.27851765+$x,0.25226381+$y,0.56014061+$z);


    glNormal3f( -1.16299899275999e-005,-4.25986825199762e-007,1.84955941952001e-005);
    glTexCoord2f(0.1061502,0.75915265); glVertex3f(0.41248548+$x,0.31802358+$y,0.68928688+$z);
    glTexCoord2f(0.10966522,0.77175621); glVertex3f(0.41560785+$x,0.32035429+$y,0.6913039+$z);
    glTexCoord2f(0.10223873,0.75510558); glVertex3f(0.41086129+$x,0.32273477+$y,0.6883741+$z);


    glNormal3f( -0.000739120717347998,0.000388984751674206,0.000549043727715395);
    glTexCoord2f(0.69567278,0.40507039); glVertex3f(0.41086129+$x,0.32273477+$y,0.6883741+$z);
    glTexCoord2f(0.68975291,0.41228774); glVertex3f(0.41114875+$x,0.32703646+$y,0.68571343+$z);
    glTexCoord2f(0.40970839,0.18399996); glVertex3f(0.27880511+$x,0.25656549+$y,0.55747994+$z);


    glNormal3f( -8.58968141089998e-006,5.13111612150007e-006,7.36779874629991e-006);
    glTexCoord2f(0.69567278,0.40507039); glVertex3f(0.41086129+$x,0.32273477+$y,0.6883741+$z);
    glTexCoord2f(0.69857277,0.40880705); glVertex3f(0.41266398+$x,0.3240804+$y,0.68953862+$z);
    glTexCoord2f(0.68975291,0.41228774); glVertex3f(0.41114875+$x,0.32703646+$y,0.68571343+$z);


    glNormal3f( -0.000501892635272312,0.000667507074818801,0.000549173214822996);
    glTexCoord2f(-0.26344331,0.2494632); glVertex3f(0.41114875+$x,0.32703646+$y,0.68571343+$z);
    glTexCoord2f(-0.25334903,0.23714355); glVertex3f(0.41534865+$x,0.32800331+$y,0.68837656+$z);
    glTexCoord2f(0.22626699,0.63004571); glVertex3f(0.46392201+$x,0.46994392+$y,0.56024258+$z);


    glNormal3f( -6.43603999800011e-006,7.65983389409975e-006,7.36907848549997e-006);
    glTexCoord2f(-0.26344331,0.2494632); glVertex3f(0.41114875+$x,0.32703646+$y,0.68571343+$z);
    glTexCoord2f(-0.26057065,0.23376669); glVertex3f(0.41430648+$x,0.32600881+$y,0.68953954+$z);
    glTexCoord2f(-0.25334903,0.23714355); glVertex3f(0.41534865+$x,0.32800331+$y,0.68837656+$z);


    glNormal3f( -7.37925422309991e-006,6.28148056340008e-006,7.77731323429989e-006);
    glTexCoord2f(0.072899677,0.79746809); glVertex3f(0.41114875+$x,0.32703646+$y,0.68571343+$z);
    glTexCoord2f(0.10053499,0.77339742); glVertex3f(0.41266398+$x,0.3240804+$y,0.68953862+$z);
    glTexCoord2f(0.10873556,0.78978562); glVertex3f(0.41430648+$x,0.32600881+$y,0.68953954+$z);


    glNormal3f( -2.03462058327907e-005,0.000673456199918999,0.000738309283601403);
    glTexCoord2f(0.12448433,0.79925846); glVertex3f(0.41534865+$x,0.32800331+$y,0.68837656+$z);
    glTexCoord2f(0.12281594,0.79411589); glVertex3f(0.42025782+$x,0.32714896+$y,0.68929115+$z);
    glTexCoord2f(0.33354412,0.6887604); glVertex3f(0.46883118+$x,0.46908958+$y,0.56115717+$z);


    glNormal3f( -1.43857967949976e-006,1.153946754e-005,1.85011604085001e-005);
    glTexCoord2f(0.12448433,0.79925846); glVertex3f(0.41534865+$x,0.32800331+$y,0.68837656+$z);
    glTexCoord2f(0.11528938,0.78359007); glVertex3f(0.41845272+$x,0.32369441+$y,0.69130545+$z);
    glTexCoord2f(0.12281594,0.79411589); glVertex3f(0.42025782+$x,0.32714896+$y,0.68929115+$z);


    glNormal3f( -8.30506583000273e-007,6.66237261989977e-006,1.06816739280001e-005);
    glTexCoord2f(0.12448433,0.79925846); glVertex3f(0.41534865+$x,0.32800331+$y,0.68837656+$z);
    glTexCoord2f(0.10873556,0.78978562); glVertex3f(0.41430648+$x,0.32600881+$y,0.68953954+$z);
    glTexCoord2f(0.11528938,0.78359007); glVertex3f(0.41845272+$x,0.32369441+$y,0.69130545+$z);


    glNormal3f( 8.65575934699995e-006,6.71983021200011e-006,1.92813884009999e-005);
    glTexCoord2f(0.12281594,0.79411589); glVertex3f(0.42025782+$x,0.32714896+$y,0.68929115+$z);
    glTexCoord2f(0.11528938,0.78359007); glVertex3f(0.41845272+$x,0.32369441+$y,0.69130545+$z);
    glTexCoord2f(0.11790124,0.78053186); glVertex3f(0.4224765+$x,0.32071339+$y,0.69053803+$z);


    glNormal3f( -6.71454334359996e-006,-2.45942889200068e-007,1.0678381024e-005);
    glTexCoord2f(0.10966522,0.77175621); glVertex3f(0.41560785+$x,0.32035429+$y,0.6913039+$z);
    glTexCoord2f(0.10053499,0.77339742); glVertex3f(0.41266398+$x,0.3240804+$y,0.68953862+$z);
    glTexCoord2f(0.10223873,0.75510558); glVertex3f(0.41086129+$x,0.32273477+$y,0.6883741+$z);


    glNormal3f( -5.9020225041e-006,5.01742911509989e-006,2.04331776201001e-005);
    glTexCoord2f(0.11528938,0.78359007); glVertex3f(0.41845272+$x,0.32369441+$y,0.69130545+$z);
    glTexCoord2f(0.10053499,0.77339742); glVertex3f(0.41266398+$x,0.3240804+$y,0.68953862+$z);
    glTexCoord2f(0.10966522,0.77175621); glVertex3f(0.41560785+$x,0.32035429+$y,0.6913039+$z);


    glNormal3f( -3.40752775109996e-006,2.89669263420021e-006,1.17970526784e-005);
    glTexCoord2f(0.10873556,0.78978562); glVertex3f(0.41430648+$x,0.32600881+$y,0.68953954+$z);
    glTexCoord2f(0.10053499,0.77339742); glVertex3f(0.41266398+$x,0.3240804+$y,0.68953862+$z);
    glTexCoord2f(0.11528938,0.78359007); glVertex3f(0.41845272+$x,0.32369441+$y,0.69130545+$z);


    glNormal3f( -0.0001025600630258,7.83219449227007e-005,-0.000300017920817992);
    glTexCoord2f(0.79711997,0.14084221); glVertex3f(0.68663307+$x,0.57739983+$y,0.24665385+$z);
    glTexCoord2f(0.84773779,0.080736911); glVertex3f(0.64379658+$x,0.52623777+$y,0.24794111+$z);
    glTexCoord2f(0.85015593,0.082533042); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);


    glNormal3f( 0.0256083904753023,-0.0218046314062005,-0.0144464193484849);
    glTexCoord2f(1.14551405,0.78219293); glVertex3f(0.68663307+$x,0.57739983+$y,0.24665385+$z);
    glTexCoord2f(-0.038969949,-0.18979687); glVertex3f(0.49314507+$x,0.0090604536+$y,0.7614883+$z);
    glTexCoord2f(1.13038384,0.65378148); glVertex3f(0.64379658+$x,0.52623777+$y,0.24794111+$z);


    glNormal3f( 0.0262924988292619,-0.0223871207117874,-0.0148323396752371);
    glTexCoord2f(1.13038384,0.65378148); glVertex3f(0.64379658+$x,0.52623777+$y,0.24794111+$z);
    glTexCoord2f(-0.038969949,-0.18979687); glVertex3f(0.49314507+$x,0.0090604536+$y,0.7614883+$z);
    glTexCoord2f(-0.040017396,-0.3111878); glVertex3f(0.45103077+$x,-0.037060697+$y,0.75644726+$z);


    glNormal3f( -0.000133751668166701,9.18235189686008e-005,-0.000375688210739391);
    glTexCoord2f(0.84773779,0.080736911); glVertex3f(0.64379658+$x,0.52623777+$y,0.24794111+$z);
    glTexCoord2f(0.85482594,0.068593439); glVertex3f(0.59066018+$x,0.46174228+$y,0.251095+$z);
    glTexCoord2f(0.85015593,0.082533042); glVertex3f(0.64037312+$x,0.52915273+$y,0.24987238+$z);


    glNormal3f( 5.97174879422002e-005,-5.08473159427002e-005,-3.36886291587014e-005);
    glTexCoord2f(1.13038384,0.65378148); glVertex3f(0.64379658+$x,0.52623777+$y,0.24794111+$z);
    glTexCoord2f(1.10877508,0.51189054); glVertex3f(0.59706121+$x,0.46887767+$y,0.25167199+$z);
    glTexCoord2f(1.10820112,0.49329449); glVertex3f(0.59066018+$x,0.46174228+$y,0.251095+$z);


    glNormal3f( 0.00372018968891352,-0.00316760987008204,-0.00209866561127059);
    glTexCoord2f(1.14361664,0.79748683); glVertex3f(0.69218703+$x,0.58286719+$y,0.24824692+$z);
    glTexCoord2f(-0.038969949,-0.18979687); glVertex3f(0.49314507+$x,0.0090604536+$y,0.7614883+$z);
    glTexCoord2f(1.14551405,0.78219293); glVertex3f(0.68663307+$x,0.57739983+$y,0.24665385+$z);


    glNormal3f( 1.58785153000003e-005,4.69547957569995e-005,-4.27238570614999e-005);
    glTexCoord2f(0.74440832,0.39815691); glVertex3f(0.73152937+$x,0.61166276+$y,0.27452453+$z);
    glTexCoord2f(0.73025517,0.42119267); glVertex3f(0.72254197+$x,0.60683551+$y,0.26587903+$z);
    glTexCoord2f(0.72182132,0.41601009); glVertex3f(0.7191185+$x,0.60975047+$y,0.26781031+$z);


    glNormal3f( 0.00681972766908645,-0.00580675353533498,-0.0038472002139497);
    glTexCoord2f(1.09730063,0.89427831); glVertex3f(0.73152937+$x,0.61166276+$y,0.27452453+$z);
    glTexCoord2f(0.0046959723,-0.000619916); glVertex3f(0.55363974+$x,0.088049932+$y,0.74950158+$z);
    glTexCoord2f(1.11367566,0.87420214); glVertex3f(0.72254197+$x,0.60683551+$y,0.26587903+$z);


    glNormal3f( 0.021980904857708,-0.0187159551753823,-0.0124000499856351);
    glTexCoord2f(1.11367566,0.87420214); glVertex3f(0.72254197+$x,0.60683551+$y,0.26587903+$z);
    glTexCoord2f(-0.032108572,-0.12887964); glVertex3f(0.5135049+$x,0.033277553+$y,0.76102712+$z);
    glTexCoord2f(1.14361664,0.79748683); glVertex3f(0.69218703+$x,0.58286719+$y,0.24824692+$z);


    glNormal3f( 0.00647368821612682,-0.00551211445013897,-0.00365199083364981);
    glTexCoord2f(1.11367566,0.87420214); glVertex3f(0.72254197+$x,0.60683551+$y,0.26587903+$z);
    glTexCoord2f(-0.025245998,-0.092558235); glVertex3f(0.52530559+$x,0.04818586+$y,0.75944379+$z);
    glTexCoord2f(-0.032108572,-0.12887964); glVertex3f(0.5135049+$x,0.033277553+$y,0.76102712+$z);


    glNormal3f( 5.62988382137993e-005,8.49124605553995e-005,-2.83638192671999e-005);
    glTexCoord2f(0.80239199,0.30414181); glVertex3f(0.76182474+$x,0.61697173+$y,0.32021444+$z);
    glTexCoord2f(0.78009519,0.34032508); glVertex3f(0.75152409+$x,0.61745722+$y,0.30122227+$z);
    glTexCoord2f(0.77179382,0.33522132); glVertex3f(0.74810062+$x,0.62037217+$y,0.30315354+$z);


    glNormal3f( 0.00734062761393411,-0.00625028455730341,-0.0041410584720543);
    glTexCoord2f(1.00581919,0.94921023); glVertex3f(0.76182474+$x,0.61697173+$y,0.32021444+$z);
    glTexCoord2f(0.19365373,0.2673703); glVertex3f(0.62380482+$x,0.22145774+$y,0.67252102+$z);
    glTexCoord2f(1.04450451,0.93319536); glVertex3f(0.75152409+$x,0.61745722+$y,0.30122227+$z);


    glNormal3f( 0.0167315146597518,-0.0142462842116122,-0.00943871753881836);
    glTexCoord2f(1.04450451,0.93319536); glVertex3f(0.75152409+$x,0.61745722+$y,0.30122227+$z);
    glTexCoord2f(0.0046959723,-0.000619916); glVertex3f(0.55363974+$x,0.088049932+$y,0.74950158+$z);
    glTexCoord2f(1.09730063,0.89427831); glVertex3f(0.73152937+$x,0.61166276+$y,0.27452453+$z);


    glNormal3f( 0.00518424712905612,-0.00441420022739321,-0.00292457931574086);
    glTexCoord2f(1.04450451,0.93319536); glVertex3f(0.75152409+$x,0.61745722+$y,0.30122227+$z);
    glTexCoord2f(0.030970684,0.049726201); glVertex3f(0.56794856+$x,0.11155161+$y,0.73939392+$z);
    glTexCoord2f(0.0046959723,-0.000619916); glVertex3f(0.55363974+$x,0.088049932+$y,0.74950158+$z);


    glNormal3f( 0.000106263379444801,0.000122641552493401,3.25856899980007e-006);
    glTexCoord2f(0.86664088,0.20087276); glVertex3f(0.78307432+$x,0.60314147+$y,0.37875708+$z);
    glTexCoord2f(0.83358243,0.25388651); glVertex3f(0.77358016+$x,0.61217726+$y,0.34828917+$z);
    glTexCoord2f(0.85885755,0.196019); glVertex3f(0.77965086+$x,0.60605643+$y,0.38068836+$z);


    glNormal3f( 0.00762352268610152,-0.00649115795301691,-0.00430064563883011);
    glTexCoord2f(0.88355586,0.96733704); glVertex3f(0.78307432+$x,0.60314147+$y,0.37875708+$z);
    glTexCoord2f(0.23746873,0.37723477); glVertex3f(0.65668153+$x,0.27045412+$y,0.65684738+$z);
    glTexCoord2f(0.94763617,0.96255824); glVertex3f(0.77358016+$x,0.61217726+$y,0.34828917+$z);


    glNormal3f( 0.00283572091705949,-0.0024145167816233,-0.00159971243599751);
    glTexCoord2f(0.88355586,0.96733704); glVertex3f(0.78307432+$x,0.60314147+$y,0.37875708+$z);
    glTexCoord2f(0.24401914,0.4067658); glVertex3f(0.66615737+$x,0.28273947+$y,0.65510185+$z);
    glTexCoord2f(0.23746873,0.37723477); glVertex3f(0.65668153+$x,0.27045412+$y,0.65684738+$z);


    glNormal3f( 0.00811441180915345,-0.00690912882761809,-0.0045775660089949);
    glTexCoord2f(0.94763617,0.96255824); glVertex3f(0.77358016+$x,0.61217726+$y,0.34828917+$z);
    glTexCoord2f(0.23746873,0.37723477); glVertex3f(0.65668153+$x,0.27045412+$y,0.65684738+$z);
    glTexCoord2f(1.00581919,0.94921023); glVertex3f(0.76182474+$x,0.61697173+$y,0.32021444+$z);


    glNormal3f( 0.000156688627575601,0.000152730590342404,4.72307104764019e-005);
    glTexCoord2f(0.74489604,0.95369658); glVertex3f(0.79527925+$x,0.57451932+$y,0.44359281+$z);
    glTexCoord2f(0.83270705,0.96567749); glVertex3f(0.78871102+$x,0.59390808+$y,0.40268532+$z);
    glTexCoord2f(0.83142257,0.97509731); glVertex3f(0.78528755+$x,0.59682304+$y,0.40461659+$z);


    glNormal3f( 0.00637151700636479,-0.00542511781824539,-0.00359435146219919);
    glTexCoord2f(0.74489604,0.95369658); glVertex3f(0.79527925+$x,0.57451932+$y,0.44359281+$z);
    glTexCoord2f(0.26000284,0.49836706); glVertex3f(0.69607984+$x,0.3201132+$y,0.65173396+$z);
    glTexCoord2f(0.83270705,0.96567749); glVertex3f(0.78871102+$x,0.59390808+$y,0.40268532+$z);


    glNormal3f( 0.00462468664345352,-0.00393775643013952,-0.00260891778695071);
    glTexCoord2f(0.74489604,0.95369658); glVertex3f(0.79527925+$x,0.57451932+$y,0.44359281+$z);
    glTexCoord2f(0.27191521,0.56072421); glVertex3f(0.7163232+$x,0.34572945+$y,0.64895451+$z);
    glTexCoord2f(0.26000284,0.49836706); glVertex3f(0.69607984+$x,0.3201132+$y,0.65173396+$z);


    glNormal3f( 0.0042518663773216,-0.00362031357561121,-0.00239859941119621);
    glTexCoord2f(0.83270705,0.96567749); glVertex3f(0.78871102+$x,0.59390808+$y,0.40268532+$z);
    glTexCoord2f(0.26000284,0.49836706); glVertex3f(0.69607984+$x,0.3201132+$y,0.65173396+$z);
    glTexCoord2f(0.88355586,0.96733704); glVertex3f(0.78307432+$x,0.60314147+$y,0.37875708+$z);


    glNormal3f( 0.000198491883362698,0.000167767487890899,9.86382893681997e-005);
    glTexCoord2f(0.60422441,0.91338337); glVertex3f(0.79844069+$x,0.53545255+$y,0.50816214+$z);
    glTexCoord2f(0.7093621,0.94592206); glVertex3f(0.79691738+$x,0.56556196+$y,0.46001638+$z);
    glTexCoord2f(0.70676051,0.95507558); glVertex3f(0.79349391+$x,0.56847691+$y,0.46194765+$z);


    glNormal3f( 0.00377813087621171,-0.00321694550960929,-0.00213135270564899);
    glTexCoord2f(0.60422441,0.91338337); glVertex3f(0.79844069+$x,0.53545255+$y,0.50816214+$z);
    glTexCoord2f(0.2888579,0.62297643); glVertex3f(0.73591528+$x,0.37215716+$y,0.64379581+$z);
    glTexCoord2f(0.7093621,0.94592206); glVertex3f(0.79691738+$x,0.56556196+$y,0.46001638+$z);


    glNormal3f( 0.0030572439195239,-0.00260313363174001,-0.00172467715486031);
    glTexCoord2f(0.60422441,0.91338337); glVertex3f(0.79844069+$x,0.53545255+$y,0.50816214+$z);
    glTexCoord2f(0.33125143,0.71402786); glVertex3f(0.76241857+$x,0.41379124+$y,0.62793658+$z);
    glTexCoord2f(0.2888579,0.62297643); glVertex3f(0.73591528+$x,0.37215716+$y,0.64379581+$z);


    glNormal3f( 0.000222592180588498,0.000160340524904202,0.000152567590281402);
    glTexCoord2f(0.47597821,0.85136683); glVertex3f(0.79255979+$x,0.49028849+$y,0.56590556+$z);
    glTexCoord2f(0.58722325,0.90671941); glVertex3f(0.79820005+$x,0.53005132+$y,0.51588792+$z);
    glTexCoord2f(0.58308957,0.91534198); glVertex3f(0.79477659+$x,0.53296628+$y,0.51781919+$z);


    glNormal3f( 0.0013596830085034,-0.00115772161025559,-0.000767035827567593);
    glTexCoord2f(0.47597821,0.85136683); glVertex3f(0.79255979+$x,0.49028849+$y,0.56590556+$z);
    glTexCoord2f(0.33125143,0.71402786); glVertex3f(0.76241857+$x,0.41379124+$y,0.62793658+$z);
    glTexCoord2f(0.58722325,0.90671941); glVertex3f(0.79820005+$x,0.53005132+$y,0.51588792+$z);


    glNormal3f( 0.000292999217010599,-0.000249476453012011,-0.000165287177569213);
    glTexCoord2f(0.58722325,0.90671941); glVertex3f(0.79820005+$x,0.53005132+$y,0.51588792+$z);
    glTexCoord2f(0.33125143,0.71402786); glVertex3f(0.76241857+$x,0.41379124+$y,0.62793658+$z);
    glTexCoord2f(0.60422441,0.91338337); glVertex3f(0.79844069+$x,0.53545255+$y,0.50816214+$z);


    glNormal3f( 0.00153021875603122,-0.0013029268571629,-0.000863239975479999);
    glTexCoord2f(0.7093621,0.94592206); glVertex3f(0.79691738+$x,0.56556196+$y,0.46001638+$z);
    glTexCoord2f(0.2888579,0.62297643); glVertex3f(0.73591528+$x,0.37215716+$y,0.64379581+$z);
    glTexCoord2f(0.74489604,0.95369658); glVertex3f(0.79527925+$x,0.57451932+$y,0.44359281+$z);


    glNormal3f( 0.000217830051522598,-0.000185474877341498,-0.000122884535049399);
    glTexCoord2f(0.38955002,0.78568747); glVertex3f(0.78022618+$x,0.45077519+$y,0.60368162+$z);
    glTexCoord2f(0.35163241,0.74327517); glVertex3f(0.77010343+$x,0.42830823+$y,0.61964797+$z);
    glTexCoord2f(0.47597821,0.85136683); glVertex3f(0.79255979+$x,0.49028849+$y,0.56590556+$z);


    glNormal3f( 0.000266447825707306,-0.000226870886853003,-0.000150310867307202);
    glTexCoord2f(0.35163241,0.74327517); glVertex3f(0.77010343+$x,0.42830823+$y,0.61964797+$z);
    glTexCoord2f(0.33125143,0.71402786); glVertex3f(0.76241857+$x,0.41379124+$y,0.62793658+$z);
    glTexCoord2f(0.47597821,0.85136683); glVertex3f(0.79255979+$x,0.49028849+$y,0.56590556+$z);


    glNormal3f( 0.000126635670762402,3.10858924979855e-006,0.000219789054076);
    glTexCoord2f(0.47980711,0.62958926); glVertex3f(0.73591528+$x,0.37215716+$y,0.64379581+$z);
    glTexCoord2f(0.55918376,0.75459458); glVertex3f(0.76241857+$x,0.41379124+$y,0.62793658+$z);
    glTexCoord2f(0.54597912,0.76275538); glVertex3f(0.7589951+$x,0.4167062+$y,0.62986785+$z);


    glNormal3f( 0.00424698115033798,-0.00361615228020097,-0.00239584184408408);
    glTexCoord2f(0.2888579,0.62297643); glVertex3f(0.73591528+$x,0.37215716+$y,0.64379581+$z);
    glTexCoord2f(0.27191521,0.56072421); glVertex3f(0.7163232+$x,0.34572945+$y,0.64895451+$z);
    glTexCoord2f(0.74489604,0.95369658); glVertex3f(0.79527925+$x,0.57451932+$y,0.44359281+$z);


    glNormal3f( 5.7573880709498e-005,-2.95800301756987e-005,0.000146705048053103);
    glTexCoord2f(0.45475887,0.59821031); glVertex3f(0.69607984+$x,0.3201132+$y,0.65173396+$z);
    glTexCoord2f(0.45295003,0.59203309); glVertex3f(0.7163232+$x,0.34572945+$y,0.64895451+$z);
    glTexCoord2f(0.45033047,0.59343957); glVertex3f(0.71289973+$x,0.34864441+$y,0.65088578+$z);


    glNormal3f( 0.00924895612911208,-0.0078751546632464,-0.00521759671121651);
    glTexCoord2f(0.26000284,0.49836706); glVertex3f(0.69607984+$x,0.3201132+$y,0.65173396+$z);
    glTexCoord2f(0.24401914,0.4067658); glVertex3f(0.66615737+$x,0.28273947+$y,0.65510185+$z);
    glTexCoord2f(0.88355586,0.96733704); glVertex3f(0.78307432+$x,0.60314147+$y,0.37875708+$z);


    glNormal3f( 2.88144780233004e-005,-1.23246533830005e-005,6.96800988773988e-005);
    glTexCoord2f(0.48657266,0.64216045); glVertex3f(0.65668153+$x,0.27045412+$y,0.65684738+$z);
    glTexCoord2f(0.4818343,0.63792349); glVertex3f(0.66615737+$x,0.28273947+$y,0.65510185+$z);
    glTexCoord2f(0.48642789,0.64237535); glVertex3f(0.65325807+$x,0.27336908+$y,0.65877865+$z);


    glNormal3f( 0.0110626031759568,-0.00941940672284297,-0.00624072230228327);
    glTexCoord2f(0.23746873,0.37723477); glVertex3f(0.65668153+$x,0.27045412+$y,0.65684738+$z);
    glTexCoord2f(0.19365373,0.2673703); glVertex3f(0.62380482+$x,0.22145774+$y,0.67252102+$z);
    glTexCoord2f(1.00581919,0.94921023); glVertex3f(0.76182474+$x,0.61697173+$y,0.32021444+$z);


    glNormal3f( 0.0061060790705482,-0.00519911018876431,-0.00344461426212901);
    glTexCoord2f(0.19365373,0.2673703); glVertex3f(0.62380482+$x,0.22145774+$y,0.67252102+$z);
    glTexCoord2f(0.12706006,0.17675485); glVertex3f(0.60041007+$x,0.17589144+$y,0.69982568+$z);
    glTexCoord2f(1.04450451,0.93319536); glVertex3f(0.75152409+$x,0.61745722+$y,0.30122227+$z);


    glNormal3f( 0.00476652789102154,-0.00405853036318591,-0.0026889356877792);
    glTexCoord2f(0.12706006,0.17675485); glVertex3f(0.60041007+$x,0.17589144+$y,0.69982568+$z);
    glTexCoord2f(0.06091322,0.094341531); glVertex3f(0.57981492+$x,0.13350505+$y,0.72729346+$z);
    glTexCoord2f(1.04450451,0.93319536); glVertex3f(0.75152409+$x,0.61745722+$y,0.30122227+$z);


    glNormal3f( 0.00349768443039535,-0.00297815418295017,-0.00197314371095639);
    glTexCoord2f(0.06091322,0.094341531); glVertex3f(0.57981492+$x,0.13350505+$y,0.72729346+$z);
    glTexCoord2f(0.030970684,0.049726201); glVertex3f(0.56794856+$x,0.11155161+$y,0.73939392+$z);
    glTexCoord2f(1.04450451,0.93319536); glVertex3f(0.75152409+$x,0.61745722+$y,0.30122227+$z);


    glNormal3f( 7.48515102646583e-005,6.96897490220134e-006,0.000122166692513081);
    glTexCoord2f(0.49435222,0.65903012); glVertex3f(0.55363974+$x,0.088049932+$y,0.74950158+$z);
    glTexCoord2f(0.4920786,0.65665706); glVertex3f(0.56794856+$x,0.11155161+$y,0.73939392+$z);
    glTexCoord2f(0.49318907,0.65609532); glVertex3f(0.5645251+$x,0.11446657+$y,0.74132519+$z);


    glNormal3f( 0.0141212889925762,-0.0120237724349542,-0.00796621772720817);
    glTexCoord2f(0.0046959723,-0.000619916); glVertex3f(0.55363974+$x,0.088049932+$y,0.74950158+$z);
    glTexCoord2f(-0.025245998,-0.092558235); glVertex3f(0.52530559+$x,0.04818586+$y,0.75944379+$z);
    glTexCoord2f(1.11367566,0.87420214); glVertex3f(0.72254197+$x,0.60683551+$y,0.26587903+$z);


    glNormal3f( 3.34073065100306e-005,-1.73698516545003e-005,8.54365084032404e-005);
    glTexCoord2f(0.46957829,0.60462015); glVertex3f(0.5135049+$x,0.033277553+$y,0.76102712+$z);
    glTexCoord2f(0.48283397,0.63727509); glVertex3f(0.52530559+$x,0.04818586+$y,0.75944379+$z);
    glTexCoord2f(0.45739586,0.61158166); glVertex3f(0.51008144+$x,0.036192511+$y,0.76295839+$z);


    glNormal3f( 0.0121645893249602,-0.0103577130746526,-0.006862388675868);
    glTexCoord2f(-0.032108572,-0.12887964); glVertex3f(0.5135049+$x,0.033277553+$y,0.76102712+$z);
    glTexCoord2f(-0.038969949,-0.18979687); glVertex3f(0.49314507+$x,0.0090604536+$y,0.7614883+$z);
    glTexCoord2f(1.14361664,0.79748683); glVertex3f(0.69218703+$x,0.58286719+$y,0.24824692+$z);


    glNormal3f( -6.89715443501444e-005,2.34651073378016e-005,0.000361522733573499);
    glTexCoord2f(0.30168768,0.31832492); glVertex3f(0.45103077+$x,-0.037060697+$y,0.75644726+$z);
    glTexCoord2f(0.41714992,0.50646187); glVertex3f(0.49314507+$x,0.0090604536+$y,0.7614883+$z);
    glTexCoord2f(0.45739586,0.61158166); glVertex3f(0.51008144+$x,0.036192511+$y,0.76295839+$z);


    glNormal3f( 0.0242921919990317,-0.0206839356123216,-0.0137039151927241);
    glTexCoord2f(-0.040017396,-0.3111878); glVertex3f(0.45103077+$x,-0.037060697+$y,0.75644726+$z);
    glTexCoord2f(-0.021680581,-0.4074273); glVertex3f(0.41529993+$x,-0.070382022+$y,0.7434025+$z);
    glTexCoord2f(1.13038384,0.65378148); glVertex3f(0.64379658+$x,0.52623777+$y,0.24794111+$z);


    glNormal3f( 0.026193798026962,-0.0223030778008123,-0.014776656034778);
    glTexCoord2f(-0.021680581,-0.4074273); glVertex3f(0.41529993+$x,-0.070382022+$y,0.7434025+$z);
    glTexCoord2f(1.10877508,0.51189054); glVertex3f(0.59706121+$x,0.46887767+$y,0.25167199+$z);
    glTexCoord2f(1.13038384,0.65378148); glVertex3f(0.64379658+$x,0.52623777+$y,0.24794111+$z);


    glNormal3f( -4.77979695340602e-005,4.06981625655995e-005,2.69642619197808e-005);
    glTexCoord2f(0.47516599,0.48627489); glVertex3f(0.38469037+$x,-0.090587644+$y,0.71963982+$z);
    glTexCoord2f(0.51474812,0.53507424); glVertex3f(0.40715886+$x,-0.076636919+$y,0.73841205+$z);
    glTexCoord2f(0.52527071,0.55452611); glVertex3f(0.41529993+$x,-0.070382022+$y,0.7434025+$z);


    glNormal3f( 0.016905004303205,-0.0143940072490981,-0.00953659119648251);
    glTexCoord2f(0.021629218,-0.48017992); glVertex3f(0.38469037+$x,-0.090587644+$y,0.71963982+$z);
    glTexCoord2f(1.10820112,0.49329449); glVertex3f(0.59066018+$x,0.46174228+$y,0.251095+$z);
    glTexCoord2f(-0.013077131,-0.4278008); glVertex3f(0.40715886+$x,-0.076636919+$y,0.73841205+$z);


    glNormal3f( 0.0221723987444842,-0.0188790080625092,-0.0125080805113061);
    glTexCoord2f(0.021629218,-0.48017992); glVertex3f(0.38469037+$x,-0.090587644+$y,0.71963982+$z);
    glTexCoord2f(1.11387747,0.38889756); glVertex3f(0.55363784+$x,0.42319068+$y,0.24365516+$z);
    glTexCoord2f(1.10820112,0.49329449); glVertex3f(0.59066018+$x,0.46174228+$y,0.251095+$z);


    glNormal3f( 0.00576687222174888,-0.00491028308282168,-0.00325325281576226);
    glTexCoord2f(-0.013077131,-0.4278008); glVertex3f(0.40715886+$x,-0.076636919+$y,0.73841205+$z);
    glTexCoord2f(1.10877508,0.51189054); glVertex3f(0.59706121+$x,0.46887767+$y,0.25167199+$z);
    glTexCoord2f(-0.021680581,-0.4074273); glVertex3f(0.41529993+$x,-0.070382022+$y,0.7434025+$z);


    glNormal3f( -5.84546397665598e-005,4.9772236657598e-005,3.29758576941803e-005);
    glTexCoord2f(0.42483361,0.49857835); glVertex3f(0.35942111+$x,-0.098346052+$y,0.68655646+$z);
    glTexCoord2f(0.46198502,0.51708057); glVertex3f(0.37137449+$x,-0.095980991+$y,0.7041759+$z);
    glTexCoord2f(0.4945914,0.54176113); glVertex3f(0.38469037+$x,-0.090587644+$y,0.71963982+$z);


    glNormal3f( 0.0100416292917755,-0.0085500842645314,-0.00566476232519124);
    glTexCoord2f(0.086911202,-0.52987006); glVertex3f(0.35942111+$x,-0.098346052+$y,0.68655646+$z);
    glTexCoord2f(1.11824632,0.35643959); glVertex3f(0.54180904+$x,0.41164534+$y,0.24011277+$z);
    glTexCoord2f(0.051711215,-0.50788132); glVertex3f(0.37137449+$x,-0.095980991+$y,0.7041759+$z);


    glNormal3f( 0.0105121773381271,-0.00895074477468322,-0.00593021817850303);
    glTexCoord2f(0.051711215,-0.50788132); glVertex3f(0.37137449+$x,-0.095980991+$y,0.7041759+$z);
    glTexCoord2f(1.11387747,0.38889756); glVertex3f(0.55363784+$x,0.42319068+$y,0.24365516+$z);
    glTexCoord2f(0.021629218,-0.48017992); glVertex3f(0.38469037+$x,-0.090587644+$y,0.71963982+$z);


    glNormal3f( -7.69317937553499e-005,-1.08671449825995e-005,2.890067878695e-005);
    glTexCoord2f(0.39426655,0.51706419); glVertex3f(0.33971108+$x,-0.094325768+$y,0.64554955+$z);
    glTexCoord2f(0.4168353,0.51189716); glVertex3f(0.34410545+$x,-0.096398513+$y,0.6564677+$z);
    glTexCoord2f(0.48302344,0.51053049); glVertex3f(0.35599764+$x,-0.095431093+$y,0.68848773+$z);


    glNormal3f( 0.0115902036568176,-0.009868643530588,-0.00653836106170312);
    glTexCoord2f(0.17116481,-0.55692233); glVertex3f(0.33971108+$x,-0.094325768+$y,0.64554955+$z);
    glTexCoord2f(1.14718866,0.17707629); glVertex3f(0.47585632+$x,0.348658+$y,0.21827155+$z);
    glTexCoord2f(1.13923805,0.23480931); glVertex3f(0.49691816+$x,0.36916325+$y,0.22465725+$z);


    glNormal3f( 0.00468390139424907,-0.00398817506490258,-0.00264232179396215);
    glTexCoord2f(0.17116481,-0.55692233); glVertex3f(0.33971108+$x,-0.094325768+$y,0.64554955+$z);
    glTexCoord2f(1.11824632,0.35643959); glVertex3f(0.54180904+$x,0.41164534+$y,0.24011277+$z);
    glTexCoord2f(0.14848692,-0.5522583); glVertex3f(0.34410545+$x,-0.096398513+$y,0.6564677+$z);


    glNormal3f( 0.014475542098375,-0.0123254064178522,-0.008166062369603);
    glTexCoord2f(0.14848692,-0.5522583); glVertex3f(0.34410545+$x,-0.096398513+$y,0.6564677+$z);
    glTexCoord2f(1.11824632,0.35643959); glVertex3f(0.54180904+$x,0.41164534+$y,0.24011277+$z);
    glTexCoord2f(0.086911202,-0.52987006); glVertex3f(0.35942111+$x,-0.098346052+$y,0.68655646+$z);


    glNormal3f( 0.0145915223162314,-0.0124241587286348,-0.0082314894287374);
    glTexCoord2f(0.27138932,-0.56176107); glVertex3f(0.32577933+$x,-0.079195233+$y,0.59801628+$z);
    glTexCoord2f(1.14718866,0.17707629); glVertex3f(0.47585632+$x,0.348658+$y,0.21827155+$z);
    glTexCoord2f(0.17116481,-0.55692233); glVertex3f(0.33971108+$x,-0.094325768+$y,0.64554955+$z);


    glNormal3f( 0.0116080579214645,-0.0098838484726578,-0.00654843602537241);
    glTexCoord2f(0.38458389,-0.54481092); glVertex3f(0.31784481+$x,-0.053623022+$y,0.5453539+$z);
    glTexCoord2f(1.14989549,0.11999667); glVertex3f(0.45566268+$x,0.32751262+$y,0.21439104+$z);
    glTexCoord2f(0.27138932,-0.56176107); glVertex3f(0.32577933+$x,-0.079195233+$y,0.59801628+$z);


    glNormal3f( 0.00576230968299569,-0.00490639861653209,-0.00325067936574221);
    glTexCoord2f(0.38458389,-0.54481092); glVertex3f(0.31784481+$x,-0.053623022+$y,0.5453539+$z);
    glTexCoord2f(1.14688414,0.076983684); glVertex3f(0.44106282+$x,0.31072345+$y,0.21385129+$z);
    glTexCoord2f(1.14989549,0.11999667); glVertex3f(0.45566268+$x,0.32751262+$y,0.21439104+$z);


    glNormal3f( -3.97591846878387e-005,3.38535650456977e-005,2.24293025416885e-005);
    glTexCoord2f(0.18337902,-0.29489502); glVertex3f(0.31612654+$x,-0.018277549+$y,0.48895949+$z);
    glTexCoord2f(0.25346942,-0.40000024); glVertex3f(0.31682394+$x,-0.045676756+$y,0.5315506+$z);
    glTexCoord2f(0.27784396,-0.43148783); glVertex3f(0.31784481+$x,-0.053623022+$y,0.5453539+$z);


    glNormal3f( 0.0023071880763059,-0.0019644866834851,-0.00130154842818722);
    glTexCoord2f(0.50774798,-0.50649625); glVertex3f(0.31612654+$x,-0.018277549+$y,0.48895949+$z);
    glTexCoord2f(1.11626382,-0.026739968); glVertex3f(0.40871055+$x,0.26628409+$y,0.22357649+$z);
    glTexCoord2f(1.12893723,0.0035942597); glVertex3f(0.41771763+$x,0.27990978+$y,0.218977+$z);


    glNormal3f( 0.00647477121932147,-0.0055130353031508,-0.00365260029423256);
    glTexCoord2f(0.50774798,-0.50649625); glVertex3f(0.31612654+$x,-0.018277549+$y,0.48895949+$z);
    glTexCoord2f(1.14688414,0.076983684); glVertex3f(0.44106282+$x,0.31072345+$y,0.21385129+$z);
    glTexCoord2f(0.41455749,-0.53721852); glVertex3f(0.31682394+$x,-0.045676756+$y,0.5315506+$z);


    glNormal3f( 0.00239497573820333,-0.00203923622690368,-0.00135107346632129);
    glTexCoord2f(0.41455749,-0.53721852); glVertex3f(0.31682394+$x,-0.045676756+$y,0.5315506+$z);
    glTexCoord2f(1.14688414,0.076983684); glVertex3f(0.44106282+$x,0.31072345+$y,0.21385129+$z);
    glTexCoord2f(0.38458389,-0.54481092); glVertex3f(0.31784481+$x,-0.053623022+$y,0.5453539+$z);


    glNormal3f( -0.000186527805836799,-4.80121055385006e-005,-5.79061469250802e-005);
    glTexCoord2f(0.093820846,-0.068777635); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);
    glTexCoord2f(0.13737043,-0.18449876); glVertex3f(0.31766692+$x,0.002851237+$y,0.45979942+$z);
    glTexCoord2f(0.19512165,-0.2884162); glVertex3f(0.31270307+$x,-0.015362591+$y,0.49089077+$z);


    glNormal3f( 0.00228041915437343,-0.0019416948026243,-0.00128644820286881);
    glTexCoord2f(0.63788076,-0.44724156); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);
    glTexCoord2f(1.11626382,-0.026739968); glVertex3f(0.40871055+$x,0.26628409+$y,0.22357649+$z);
    glTexCoord2f(0.57213085,-0.47945989); glVertex3f(0.31766692+$x,0.002851237+$y,0.45979942+$z);


    glNormal3f( 0.00269061669751672,-0.0022909655469407,-0.00151785467682904);
    glTexCoord2f(0.57213085,-0.47945989); glVertex3f(0.31766692+$x,0.002851237+$y,0.45979942+$z);
    glTexCoord2f(1.11626382,-0.026739968); glVertex3f(0.40871055+$x,0.26628409+$y,0.22357649+$z);
    glTexCoord2f(0.50774798,-0.50649625); glVertex3f(0.31612654+$x,-0.018277549+$y,0.48895949+$z);


    glNormal3f( -7.05062927348405e-005,-4.43880798752997e-005,-5.79860865916198e-005);
    glTexCoord2f(-0.057335979,-0.20208162); glVertex3f(0.33221464+$x,0.079059037+$y,0.37056351+$z);
    glTexCoord2f(-0.030088724,-0.24189388); glVertex3f(0.32873605+$x,0.065083117+$y,0.38549169+$z);
    glTexCoord2f(-0.050777897,-0.19571504); glVertex3f(0.32879117+$x,0.081973995+$y,0.37249478+$z);


    glNormal3f( 0.000336390578797738,-0.0002864242821093,-0.000189767134996831);
    glTexCoord2f(0.77198155,-0.36747151); glVertex3f(0.33221464+$x,0.079059037+$y,0.37056351+$z);
    glTexCoord2f(1.04107111,-0.13972684); glVertex3f(0.37858184+$x,0.2107955+$y,0.25392038+$z);
    glTexCoord2f(0.73824848,-0.38931411); glVertex3f(0.32873605+$x,0.065083117+$y,0.38549169+$z);


    glNormal3f( 0.00072486227910656,-0.000617193980521899,-0.000408914933190288);
    glTexCoord2f(0.90704921,-0.26760928); glVertex3f(0.35045901+$x,0.1397132+$y,0.31135626+$z);
    glTexCoord2f(1.04107111,-0.13972684); glVertex3f(0.37858184+$x,0.2107955+$y,0.25392038+$z);
    glTexCoord2f(0.77198155,-0.36747151); glVertex3f(0.33221464+$x,0.079059037+$y,0.37056351+$z);


    glNormal3f( 0.00156474595346541,-0.0013323258043302,-0.000882718027308781);
    glTexCoord2f(0.73824848,-0.38931411); glVertex3f(0.32873605+$x,0.065083117+$y,0.38549169+$z);
    glTexCoord2f(1.05508221,-0.12280529); glVertex3f(0.38275805+$x,0.21957116+$y,0.24807782+$z);
    glTexCoord2f(0.63788076,-0.44724156); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);


    glNormal3f( 0.000303291741894119,-0.000258242401712702,-0.000171095805537032);
    glTexCoord2f(1.04107111,-0.13972684); glVertex3f(0.37858184+$x,0.2107955+$y,0.25392038+$z);
    glTexCoord2f(1.05508221,-0.12280529); glVertex3f(0.38275805+$x,0.21957116+$y,0.24807782+$z);
    glTexCoord2f(0.73824848,-0.38931411); glVertex3f(0.32873605+$x,0.065083117+$y,0.38549169+$z);


    glNormal3f( 0.00377035634031068,-0.0032103241799118,-0.0021269651799153);
    glTexCoord2f(1.05508221,-0.12280529); glVertex3f(0.38275805+$x,0.21957116+$y,0.24807782+$z);
    glTexCoord2f(1.11626382,-0.026739968); glVertex3f(0.40871055+$x,0.26628409+$y,0.22357649+$z);
    glTexCoord2f(0.63788076,-0.44724156); glVertex3f(0.32084351+$x,0.026172653+$y,0.43023032+$z);


    glNormal3f( -0.000118991872762002,0.000101317175191401,6.71263778193994e-005);
    glTexCoord2f(0.47289505,0.83453004); glVertex3f(0.41771763+$x,0.27990978+$y,0.218977+$z);
    glTexCoord2f(0.48259329,0.80311773); glVertex3f(0.40871055+$x,0.26628409+$y,0.22357649+$z);
    glTexCoord2f(0.53425547,0.7016146); glVertex3f(0.38275805+$x,0.21957116+$y,0.24807782+$z);


    glNormal3f( 0.00679072957850971,-0.0057820660597992,-0.00383084552889721);
    glTexCoord2f(1.12893723,0.0035942597); glVertex3f(0.41771763+$x,0.27990978+$y,0.218977+$z);
    glTexCoord2f(1.14688414,0.076983684); glVertex3f(0.44106282+$x,0.31072345+$y,0.21385129+$z);
    glTexCoord2f(0.50774798,-0.50649625); glVertex3f(0.31612654+$x,-0.018277549+$y,0.48895949+$z);


    glNormal3f( -0.0001026880949432,8.74352147031e-005,5.79289044938997e-005);
    glTexCoord2f(0.27159752,0.88115441); glVertex3f(0.45566268+$x,0.32751262+$y,0.21439104+$z);
    glTexCoord2f(0.27045943,0.83805107); glVertex3f(0.44106282+$x,0.31072345+$y,0.21385129+$z);
    glTexCoord2f(0.28126723,0.76327589); glVertex3f(0.41771763+$x,0.27990978+$y,0.218977+$z);


    glNormal3f( 0.00969013536803625,-0.00825080362998211,-0.00546647917723192);
    glTexCoord2f(1.14989549,0.11999667); glVertex3f(0.45566268+$x,0.32751262+$y,0.21439104+$z);
    glTexCoord2f(1.14718866,0.17707629); glVertex3f(0.47585632+$x,0.348658+$y,0.21827155+$z);
    glTexCoord2f(0.27138932,-0.56176107); glVertex3f(0.32577933+$x,-0.079195233+$y,0.59801628+$z);


    glNormal3f( -2.09871140954995e-005,6.25372882587996e-005,-0.0001315933242914);
    glTexCoord2f(0.80599209,0.12601508); glVertex3f(0.49691816+$x,0.36916325+$y,0.22465725+$z);
    glTexCoord2f(0.79716002,0.13050725); glVertex3f(0.47585632+$x,0.348658+$y,0.21827155+$z);
    glTexCoord2f(0.80318149,0.12333253); glVertex3f(0.4934947+$x,0.37207821+$y,0.22658852+$z);


    glNormal3f( 0.0250438483563864,-0.0213239429013056,-0.0141279445671586);
    glTexCoord2f(1.13923805,0.23480931); glVertex3f(0.49691816+$x,0.36916325+$y,0.22465725+$z);
    glTexCoord2f(1.11824632,0.35643959); glVertex3f(0.54180904+$x,0.41164534+$y,0.24011277+$z);
    glTexCoord2f(0.17116481,-0.55692233); glVertex3f(0.33971108+$x,-0.094325768+$y,0.64554955+$z);


    glNormal3f( 0.00715597705598527,-0.00609305559771854,-0.00403688551663585);
    glTexCoord2f(1.11824632,0.35643959); glVertex3f(0.54180904+$x,0.41164534+$y,0.24011277+$z);
    glTexCoord2f(1.11387747,0.38889756); glVertex3f(0.55363784+$x,0.42319068+$y,0.24365516+$z);
    glTexCoord2f(0.051711215,-0.50788132); glVertex3f(0.37137449+$x,-0.095980991+$y,0.7041759+$z);


    glNormal3f( -5.27667869239992e-005,9.69701292181996e-005,-0.000239898130519003);
    glTexCoord2f(0.85482594,0.068593439); glVertex3f(0.59066018+$x,0.46174228+$y,0.251095+$z);
    glTexCoord2f(0.85657831,0.069244244); glVertex3f(0.55363784+$x,0.42319068+$y,0.24365516+$z);
    glTexCoord2f(0.85600094,0.068837448); glVertex3f(0.55021438+$x,0.42610563+$y,0.24558643+$z);


    glNormal3f( 0.00378783661943052,-0.00322520948318831,-0.00213682792046018);
    glTexCoord2f(1.10820112,0.49329449); glVertex3f(0.59066018+$x,0.46174228+$y,0.251095+$z);
    glTexCoord2f(1.10877508,0.51189054); glVertex3f(0.59706121+$x,0.46887767+$y,0.25167199+$z);
    glTexCoord2f(-0.013077131,-0.4278008); glVertex3f(0.40715886+$x,-0.076636919+$y,0.73841205+$z);

    glEnd();
    glBegin(GL_QUADS);
}

sub drawSingleNorthEastRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( -1, 1, 1); # Top face.
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}

sub drawSingleSouthEastRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( -1, 1, -1); # Top face.
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}

sub drawSingleSouthWestRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 1, 1, -1); # Top face.
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}

sub drawSingleNorthWestRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 1, 1, 1); # Top face.
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys2, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys2,  $z);
}

sub drawDoubleNorthEastRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( -1, 1, 1); # Top face.
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys2, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys2,  $z);
}

sub drawDoubleNorthWestRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 0, 1, 0); # Top face.
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys2, $zs);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys2, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys2,  $z);
}

sub drawDoubleSouthWestRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 0, 1, 0); # Top face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2,  $z);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys2, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys2,  $z);
}

sub drawDoubleSouthEastRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( -1, 1, -1); # Top face.
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}

sub drawTripleNorthSouthEastRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $xs2 = $x + 0.5*$s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $ys3 = $y + ($s+0.1)*0.5;
    my $zs = $z + $s;
    my $zs2 = $z + 0.5*$s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 0, 1, 0); # Top-North face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys3, $zs2);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs2, $ys3, $zs2);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);

    glNormal3f( 0, 1, 0); # Top-South face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys3,  $zs2);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs2, $ys3, $zs2);

    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys2, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2, $zs);

    glNormal3f(-1, 0, 0); # North-Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs2);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys3, $zs2);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys2,  $z);

    glNormal3f(-1, 0, 0); # North-Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $zs2);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys3,  $zs2);
}

sub drawSingleSouthRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 0, 1, -1); # Top face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}

sub drawSingleEastRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( -1, 1, 0); # Top face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}

sub drawSingleWestRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 1, 1, 0); # Top face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys2, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys2,  $z);
}

sub ourDrawRamp {
    my ($x, $y, $z, $s) = @_;
    my $brightness = $y/($zcount-15);
    glColor3f($brightness, $brightness, $brightness); # Basic polygon color
    my $tex_x1 =0;
    my $tex_x2 =1;
    my $tex_y1 =1;
    my $tex_y2 =0;

    my $xs = $x + $s;
    my $ys = $y + 0.1*$s;
    my $ys2 = $y + $s+0.1;
    my $zs = $z + $s;

    glNormal3f( 0,-1, 0); # Bottom Face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $y,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs, $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $y, $zs);

    glNormal3f( 0, 1, 0); # Top face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys,  $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    
    glNormal3f( 0, 0,-1); # Far face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $z);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f(  $x,  $y, $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f(  $x, $ys, $z);
    
    glNormal3f( 1, 0, 0); # Right face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2,  $z);
    
    glNormal3f( 0, 0, 1); # Front face.
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f(  $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f(  $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $xs,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $xs, $ys2, $zs);
    
    glNormal3f(-1, 0, 0); # Left Face.
    glTexCoord2f($tex_x1,$tex_y2); glVertex3f( $x,  $y,  $z);
    glTexCoord2f($tex_x2,$tex_y2); glVertex3f( $x,  $y, $zs);
    glTexCoord2f($tex_x2,$tex_y1); glVertex3f( $x, $ys, $zs);
    glTexCoord2f($tex_x1,$tex_y1); glVertex3f( $x, $ys,  $z);
}