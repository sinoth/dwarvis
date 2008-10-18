package Lifevis::df_internals;
use strict;

use base 'Exporter';

our @EXPORT = ( qw( get_df_tile_type_data get_df_item_id_data get_ramp_bitmasks ) );

# TODO: Make auto-converter from ods to this file.

my @TILE_TYPES;

use lib '.';
use lib '..';
use Lifevis::constants;

my @light_variance = ( 0.9, 0.85, 0.82, 0.8 );


$TILE_TYPES[1] = [RAMP,unknown,0.9];    #   MAPTILE_RAMPSPACE,
$TILE_TYPES[2] = [WALL,pool,0.9];    #   MAPTILE_POOL,
$TILE_TYPES[19] = [FLOOR,unknown,0.9];    #   MAPTILE_DRIFTWOOD_STACK,
$TILE_TYPES[24] = [TREE,tree,0.9];    #   MAPTILE_TREE,
$TILE_TYPES[25] = [STAIR,unknown,0.9];    #   MAPTILE_STAIR_UPDOWN_FROZEN_LIQUID,
$TILE_TYPES[26] = [STAIR_DOWN,unknown,0.9];    #   MAPTILE_STAIR_DOWN_FROZEN_LIQUID,
$TILE_TYPES[27] = [STAIR_UP,unknown,0.9];    #   MAPTILE_STAIR_UP_FROZEN_LIQUID,
$TILE_TYPES[32] = [EMPTY,unknown,0.9];    #   MAPTILE_AIR,
$TILE_TYPES[34] = [SHRUB,shrub,0.9];    #   MAPTILE_SHRUB,
$TILE_TYPES[35] = [EMPTY,unknown,0.9];    #   MAPTILE_CHASM,
$TILE_TYPES[36] = [STAIR,obsidian,0.9];    #   MAPTILE_STAIR_UPDOWN_LAVASTONE,
$TILE_TYPES[37] = [STAIR_DOWN,obsidian,0.9];    #   MAPTILE_STAIR_DOWN_LAVASTONE,
$TILE_TYPES[38] = [STAIR_UP,obsidian,0.9];    #   MAPTILE_STAIR_UP_LAVASTONE,
$TILE_TYPES[39] = [STAIR,soil,0.9];    #   MAPTILE_STAIR_UPDOWN_SOIL,
$TILE_TYPES[40] = [STAIR_DOWN,soil,0.9];    #   MAPTILE_STAIR_DOWN_SOIL,
$TILE_TYPES[41] = [STAIR_UP,soil,0.9];    #   MAPTILE_STAIR_UP_SOIL,
$TILE_TYPES[42] = [EMPTY,unknown,0.9];    #   MAPTILE_EERIE_PIT,
$TILE_TYPES[43] = [FLOOR,stone_detailed,0.9];    #   MAPTILE_STONE_FLOOR_DETAILED,
$TILE_TYPES[44] = [FLOOR,unknown,0.9];    #   MAPTILE_LAVASTONE_FLOOR_DETAILED,
$TILE_TYPES[45] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_FLOOR_DETAILED,
$TILE_TYPES[46] = [FLOOR,minstone_detailed,0.9];    #   MAPTILE_MINSTONE_FLOOR_DETAILED,
$TILE_TYPES[47] = [FLOOR,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_FLOOR_DETAILED,
$TILE_TYPES[49] = [STAIR,grass,0.9];    #   MAPTILE_STAIR_UPDOWN_GRASS1,
$TILE_TYPES[50] = [STAIR_DOWN,grass,0.9];    #   MAPTILE_STAIR_DOWN_GRASS1,//50
$TILE_TYPES[51] = [STAIR_UP,grass,0.9];    #   MAPTILE_STAIR_UP_GRASS1,
$TILE_TYPES[52] = [STAIR,grass,0.9];    #   MAPTILE_STAIR_UPDOWN_GRASS2,
$TILE_TYPES[53] = [STAIR_DOWN,grass,0.9];    #   MAPTILE_STAIR_DOWN_GRASS2,
$TILE_TYPES[54] = [STAIR_UP,grass,0.9];    #   MAPTILE_STAIR_UP_GRASS2,
$TILE_TYPES[55] = [STAIR,stone,0.9];    #   MAPTILE_STAIR_UPDOWN_STONE,
$TILE_TYPES[56] = [STAIR_DOWN,stone,0.9];    #   MAPTILE_STAIR_DOWN_STONE,
$TILE_TYPES[57] = [STAIR_UP,stone,0.9];    #   MAPTILE_STAIR_UP_STONE,
$TILE_TYPES[58] = [STAIR,minstone,0.9];    #   MAPTILE_STAIR_UPDOWN_MINSTONE,
$TILE_TYPES[59] = [STAIR_DOWN,minstone,0.9];    #   MAPTILE_STAIR_DOWN_MINSTONE,
$TILE_TYPES[60] = [STAIR_UP,minstone,0.9];    #   MAPTILE_STAIR_UP_MINSTONE,
$TILE_TYPES[61] = [STAIR,unknown,0.9];    #   MAPTILE_STAIR_UPDOWN_FEATSTONE,
$TILE_TYPES[62] = [STAIR_DOWN,unknown,0.9];    #   MAPTILE_STAIR_DOWN_FEATSTONE,
$TILE_TYPES[63] = [STAIR_UP,unknown,0.9];    #   MAPTILE_STAIR_UP_FEATSTONE,
$TILE_TYPES[65] = [FORTIF,stone,0.9];    #   MAPTILE_STONE_FORTIFICATION,
$TILE_TYPES[67] = [FLOOR,unknown,0.9];    #   MAPTILE_CAMPFIRE,
$TILE_TYPES[70] = [FLOOR,unknown,0.9];    #   MAPTILE_FIRE,
$TILE_TYPES[79] = [PILLAR,stone,0.9];    #   MAPTILE_STONE_PILLAR,
$TILE_TYPES[80] = [PILLAR,obsidian,0.9];    #   MAPTILE_LAVASTONE_PILLAR,
$TILE_TYPES[81] = [PILLAR,unknown,0.9];    #   MAPTILE_FEATSTONE_PILLAR,
$TILE_TYPES[82] = [PILLAR,minstone,0.9];    #   MAPTILE_MINSTONE_PILLAR,
$TILE_TYPES[83] = [PILLAR,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_PILLAR,
$TILE_TYPES[89] = [EMPTY,unknown,0.9];    #   MAPTILE_WATERFALL_LANDING,
$TILE_TYPES[90] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_SOURCE,//
$TILE_TYPES[176] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_WORN1,
$TILE_TYPES[177] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_WORN2,
$TILE_TYPES[178] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_WORN3,
$TILE_TYPES[219] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL,
$TILE_TYPES[231] = [SAPLING,sapling,0.9];    #   MAPTILE_SAPLING,
$TILE_TYPES[233] = [RAMP,grass_dry,0.9];    #   MAPTILE_RAMP_GRASS_DRY,
$TILE_TYPES[234] = [RAMP,unknown,0.9];    #   MAPTILE_RAMP_GRASS_DEAD,
$TILE_TYPES[235] = [RAMP,grass,0.9];    #   MAPTILE_RAMP_GRASS1,
$TILE_TYPES[236] = [RAMP,grass,0.9];    #   MAPTILE_RAMP_GRASS2,
$TILE_TYPES[237] = [RAMP,stone,0.9];    #   MAPTILE_RAMP_STONE,
$TILE_TYPES[238] = [RAMP,obsidian,0.9];    #   MAPTILE_RAMP_LAVASTONE,
$TILE_TYPES[239] = [RAMP,unknown,0.9];    #   MAPTILE_RAMP_FEATSTONE,
$TILE_TYPES[240] = [RAMP,minstone,0.9];    #   MAPTILE_RAMP_MINSTONE,
$TILE_TYPES[241] = [RAMP,soil,0.9];    #   MAPTILE_RAMP_SOIL,
$TILE_TYPES[242] = [FLOOR,unknown,0.9];    #   MAPTILE_ASH1,
$TILE_TYPES[243] = [FLOOR,unknown,0.9];    #   MAPTILE_ASH2,
$TILE_TYPES[244] = [FLOOR,unknown,0.9];    #   MAPTILE_ASH3,
$TILE_TYPES[245] = [RAMP,unknown,0.9];    #   MAPTILE_RAMP_FROZEN_LIQUID,
$TILE_TYPES[258] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_1,
$TILE_TYPES[259] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_2,
$TILE_TYPES[260] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_3,
$TILE_TYPES[261] = [FLOOR,unknown,0.9];    #   MAPTILE_FURROWED_SOIL,
$TILE_TYPES[262] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_0,
$TILE_TYPES[264] = [WALL,lava,0.9];    #   MAPTILE_LAVA,
$TILE_TYPES[265] = [WALL,soil,0.9];    #   MAPTILE_SOIL_WALL,
$TILE_TYPES[269] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_RD2,
$TILE_TYPES[270] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_R2D,
$TILE_TYPES[271] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_R2U,
$TILE_TYPES[272] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_RU2,
$TILE_TYPES[273] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_L2U,
$TILE_TYPES[274] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LU2,
$TILE_TYPES[275] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_L2D,
$TILE_TYPES[276] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LD2,
$TILE_TYPES[277] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LRUD,
$TILE_TYPES[278] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_RUD,
$TILE_TYPES[279] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LRD,
$TILE_TYPES[280] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LRU,
$TILE_TYPES[281] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LUD,
$TILE_TYPES[282] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_RD,
$TILE_TYPES[283] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_RU,
$TILE_TYPES[284] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LU,
$TILE_TYPES[285] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LD,
$TILE_TYPES[286] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_UD,
$TILE_TYPES[287] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_DET_LR,
$TILE_TYPES[288] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_RD2,
$TILE_TYPES[289] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_R2D,
$TILE_TYPES[290] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_R2U,
$TILE_TYPES[291] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_RU2,
$TILE_TYPES[292] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_L2U,
$TILE_TYPES[293] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LU2,
$TILE_TYPES[294] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_L2D,
$TILE_TYPES[295] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LD2,
$TILE_TYPES[296] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LRUD,
$TILE_TYPES[297] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_RUD,
$TILE_TYPES[298] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LRD,
$TILE_TYPES[299] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LRU,
$TILE_TYPES[300] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LUD,
$TILE_TYPES[301] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_RD,
$TILE_TYPES[302] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_RU,
$TILE_TYPES[303] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LU,
$TILE_TYPES[304] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LD,
$TILE_TYPES[305] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_UD,
$TILE_TYPES[306] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_DET_LR,
$TILE_TYPES[307] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_RD2,
$TILE_TYPES[308] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_R2D,
$TILE_TYPES[309] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_R2U,
$TILE_TYPES[310] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_RU2,
$TILE_TYPES[311] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_L2U,
$TILE_TYPES[312] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LU2,
$TILE_TYPES[313] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_L2D,
$TILE_TYPES[314] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LD2,
$TILE_TYPES[315] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LRUD,
$TILE_TYPES[316] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_RUD,
$TILE_TYPES[317] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LRD,
$TILE_TYPES[318] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LRU,
$TILE_TYPES[319] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LUD,
$TILE_TYPES[320] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_RD,
$TILE_TYPES[321] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_RU,
$TILE_TYPES[322] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LU,
$TILE_TYPES[323] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LD,
$TILE_TYPES[324] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_UD,
$TILE_TYPES[325] = [WALL,stone,0.9];    #   MAPTILE_STONE_WALL_DET_LR,
$TILE_TYPES[326] = [FORTIF,obsidian,0.9];    #   MAPTILE_LAVASTONE_FORTIFICATION,
$TILE_TYPES[327] = [FORTIF,unknown,0.9];    #   MAPTILE_FEATSTONE_FORTIFICATION,
$TILE_TYPES[328] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_WORN1,
$TILE_TYPES[329] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_WORN2,
$TILE_TYPES[330] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL_WORN3,
$TILE_TYPES[331] = [WALL,obsidian,0.9];    #   MAPTILE_LAVASTONE_WALL,
$TILE_TYPES[332] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_WORN1,
$TILE_TYPES[333] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_WORN2,
$TILE_TYPES[334] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL_WORN3,
$TILE_TYPES[335] = [WALL,unknown,0.9];    #   MAPTILE_FEATSTONE_WALL,
$TILE_TYPES[336] = [FLOOR,stone,$light_variance[0]];    #   MAPTILE_STONE_FLOOR1,
$TILE_TYPES[337] = [FLOOR,stone,$light_variance[1]];    #   MAPTILE_STONE_FLOOR2,
$TILE_TYPES[338] = [FLOOR,stone,$light_variance[2]];    #   MAPTILE_STONE_FLOOR3,
$TILE_TYPES[339] = [FLOOR,stone,$light_variance[3]];    #   MAPTILE_STONE_FLOOR4,
$TILE_TYPES[340] = [FLOOR,obsidian,$light_variance[0]];    #   MAPTILE_LAVASTONE_FLOOR1,
$TILE_TYPES[341] = [FLOOR,obsidian,$light_variance[1]];    #   MAPTILE_LAVASTONE_FLOOR2,
$TILE_TYPES[342] = [FLOOR,obsidian,$light_variance[2]];    #   MAPTILE_LAVASTONE_FLOOR3,
$TILE_TYPES[343] = [FLOOR,obsidian,$light_variance[3]];    #   MAPTILE_LAVASTONE_FLOOR4,
$TILE_TYPES[344] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_FLOOR1,
$TILE_TYPES[345] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_FLOOR2,
$TILE_TYPES[346] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_FLOOR3,
$TILE_TYPES[347] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_FLOOR4,
$TILE_TYPES[348] = [FLOOR,grass,$light_variance[0]];    #   MAPTILE_GRASS_FLOOR1,
$TILE_TYPES[349] = [FLOOR,grass,$light_variance[1]];    #   MAPTILE_GRASS_FLOOR2,
$TILE_TYPES[350] = [FLOOR,grass,$light_variance[2]];    #   MAPTILE_GRASS_FLOOR3,//350
$TILE_TYPES[351] = [FLOOR,grass,$light_variance[3]];    #   MAPTILE_GRASS_FLOOR4,
$TILE_TYPES[352] = [FLOOR,soil,$light_variance[0]];    #   MAPTILE_SOIL_FLOOR1,
$TILE_TYPES[353] = [FLOOR,soil,$light_variance[1]];    #   MAPTILE_SOIL_FLOOR2,
$TILE_TYPES[354] = [FLOOR,soil,$light_variance[2]];    #   MAPTILE_SOIL_FLOOR3,
$TILE_TYPES[355] = [FLOOR,soil,$light_variance[3]];    #   MAPTILE_SOIL_FLOOR4,
$TILE_TYPES[356] = [FLOOR,unknown,0.9];    #   MAPTILE_SOIL_FLOOR1_WET,
$TILE_TYPES[357] = [FLOOR,unknown,0.9];    #   MAPTILE_SOIL_FLOOR2_WET,
$TILE_TYPES[358] = [FLOOR,unknown,0.9];    #   MAPTILE_SOIL_FLOOR3_WET,
$TILE_TYPES[359] = [FLOOR,unknown,0.9];    #   MAPTILE_SOIL_FLOOR4_WET,
$TILE_TYPES[360] = [FORTIF,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_FORTIFICATION,
$TILE_TYPES[361] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_WORN1,
$TILE_TYPES[362] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_WORN2,
$TILE_TYPES[363] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_WORN3,
$TILE_TYPES[364] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL,
$TILE_TYPES[365] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_N,
$TILE_TYPES[366] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_S,
$TILE_TYPES[367] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_E,
$TILE_TYPES[368] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_W,
$TILE_TYPES[369] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_NW,
$TILE_TYPES[370] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_NE,
$TILE_TYPES[371] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_SW,
$TILE_TYPES[372] = [EMPTY,unknown,0.9];    #   MAPTILE_RIVER_SE,
$TILE_TYPES[373] = [WALL,water,0.9];    #   MAPTILE_STREAM_BED_WALL_N,
$TILE_TYPES[374] = [WALL,water,0.9];    #   MAPTILE_STREAM_BED_WALL_S,
$TILE_TYPES[375] = [WALL,water,0.9];    #   MAPTILE_STREAM_BED_WALL_E,
$TILE_TYPES[376] = [WALL,water,0.9];    #   MAPTILE_STREAM_BED_WALL_W,
$TILE_TYPES[377] = [WALL,water,0.9];    #   MAPTILE_STREAM_BED_WALL_NW,
$TILE_TYPES[378] = [WALL,water,0.9];    #   MAPTILE_STREAM_BED_WALL_NE,
$TILE_TYPES[379] = [WALL,water,0.9];    #   MAPTILE_STREAM_BED_WALL_SW,
$TILE_TYPES[380] = [WALL,water,0.9];    #   MAPTILE_STREAM_BED_WALL_SE,
$TILE_TYPES[381] = [FLOOR,water,0.9];    #   MAPTILE_STREAM_BED_TOP,
$TILE_TYPES[387] = [FLOOR,grass_dry,0.9];    #   MAPTILE_GRASS_FLOOR1_DRY,
$TILE_TYPES[388] = [FLOOR,grass_dry,0.9];    #   MAPTILE_GRASS_FLOOR2_DRY,
$TILE_TYPES[389] = [FLOOR,grass_dry,0.9];    #   MAPTILE_GRASS_FLOOR3_DRY,
$TILE_TYPES[390] = [FLOOR,grass_dry,0.9];    #   MAPTILE_GRASS_FLOOR4_DRY,//390
$TILE_TYPES[391] = [TREE,tree_dead,0.9];    #   MAPTILE_TREE_DEAD,
$TILE_TYPES[392] = [SAPLING,sapling_dead,0.9];    #   MAPTILE_SAPLING_DEAD,
$TILE_TYPES[393] = [SHRUB,shrub_dead,0.9];    #   MAPTILE_SHRUB_DEAD,
$TILE_TYPES[394] = [FLOOR,unknown,0.9];    #   MAPTILE_GRASS_FLOOR1_DEAD,
$TILE_TYPES[395] = [FLOOR,unknown,0.9];    #   MAPTILE_GRASS_FLOOR2_DEAD,
$TILE_TYPES[396] = [FLOOR,unknown,0.9];    #   MAPTILE_GRASS_FLOOR3_DEAD,
$TILE_TYPES[397] = [FLOOR,unknown,0.9];    #   MAPTILE_GRASS_FLOOR4_DEAD,
$TILE_TYPES[398] = [FLOOR,grassb,$light_variance[0]];    #   MAPTILE_GRASS_FLOOR1B,
$TILE_TYPES[399] = [FLOOR,grassb,$light_variance[1]];    #   MAPTILE_GRASS_FLOOR2B,
$TILE_TYPES[400] = [FLOOR,grassb,$light_variance[2]];    #   MAPTILE_GRASS_FLOOR3B,//400
$TILE_TYPES[401] = [FLOOR,grassb,$light_variance[3]];    #   MAPTILE_GRASS_FLOOR4B,
$TILE_TYPES[402] = [BOULDER,boulder,0.9];    #   MAPTILE_STONE_BOULDER,
$TILE_TYPES[403] = [FLOOR,obsidian,0.9];    #   MAPTILE_LAVASTONE_BOULDER,
$TILE_TYPES[404] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_BOULDER,
$TILE_TYPES[405] = [FLOOR,stone,0.9];    #   MAPTILE_STONE_PEBBLE1,
$TILE_TYPES[406] = [FLOOR,stone,0.9];    #   MAPTILE_STONE_PEBBLE2,
$TILE_TYPES[407] = [FLOOR,stone,0.9];    #   MAPTILE_STONE_PEBBLE3,
$TILE_TYPES[408] = [FLOOR,stone,0.9];    #   MAPTILE_STONE_PEBBLE4,
$TILE_TYPES[409] = [FLOOR,obsidian,0.9];    #   MAPTILE_LAVASTONE_PEBBLE1,
$TILE_TYPES[410] = [FLOOR,obsidian,0.9];    #   MAPTILE_LAVASTONE_PEBBLE2,
$TILE_TYPES[411] = [FLOOR,obsidian,0.9];    #   MAPTILE_LAVASTONE_PEBBLE3,
$TILE_TYPES[412] = [FLOOR,obsidian,0.9];    #   MAPTILE_LAVASTONE_PEBBLE4,
$TILE_TYPES[413] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_PEBBLE1,
$TILE_TYPES[414] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_PEBBLE2,
$TILE_TYPES[415] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_PEBBLE3,
$TILE_TYPES[416] = [FLOOR,unknown,0.9];    #   MAPTILE_FEATSTONE_PEBBLE4,
$TILE_TYPES[417] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_RD2,
$TILE_TYPES[418] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_R2D,
$TILE_TYPES[419] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_R2U,
$TILE_TYPES[420] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_RU2,
$TILE_TYPES[421] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_L2U,
$TILE_TYPES[422] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LU2,
$TILE_TYPES[423] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_L2D,
$TILE_TYPES[424] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LD2,
$TILE_TYPES[425] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LRUD,
$TILE_TYPES[426] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_RUD,
$TILE_TYPES[427] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LRD,
$TILE_TYPES[428] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LRU,
$TILE_TYPES[429] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LUD,
$TILE_TYPES[430] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_RD,
$TILE_TYPES[431] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_RU,
$TILE_TYPES[432] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LU,
$TILE_TYPES[433] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LD,
$TILE_TYPES[434] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_UD,
$TILE_TYPES[435] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_DET_LR,
$TILE_TYPES[436] = [FORTIF,minstone,0.9];    #   MAPTILE_MINSTONE_FORTIFICATION,
$TILE_TYPES[437] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_WORN1,
$TILE_TYPES[438] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_WORN2,
$TILE_TYPES[439] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL_WORN3,
$TILE_TYPES[440] = [WALL,minstone,0.9];    #   MAPTILE_MINSTONE_WALL,
$TILE_TYPES[441] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_FLOOR1,
$TILE_TYPES[442] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_FLOOR2,
$TILE_TYPES[443] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_FLOOR3,
$TILE_TYPES[444] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_FLOOR4,
$TILE_TYPES[445] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_BOULDER,
$TILE_TYPES[446] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_PEBBLE1,
$TILE_TYPES[447] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_PEBBLE2,
$TILE_TYPES[448] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_PEBBLE3,
$TILE_TYPES[449] = [FLOOR,minstone,0.9];    #   MAPTILE_MINSTONE_PEBBLE4,
$TILE_TYPES[450] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_RD2,//450
$TILE_TYPES[451] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_R2D,
$TILE_TYPES[452] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_R2U,
$TILE_TYPES[453] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_RU2,
$TILE_TYPES[454] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_L2U,
$TILE_TYPES[455] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LU2,
$TILE_TYPES[456] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_L2D,
$TILE_TYPES[457] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LD2,
$TILE_TYPES[458] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LRUD,
$TILE_TYPES[459] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_RUD,
$TILE_TYPES[460] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LRD,
$TILE_TYPES[461] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LRU,
$TILE_TYPES[462] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LUD,
$TILE_TYPES[463] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_RD,
$TILE_TYPES[464] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_RU,
$TILE_TYPES[465] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LU,
$TILE_TYPES[466] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LD,
$TILE_TYPES[467] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_UD,
$TILE_TYPES[468] = [WALL,unknown,0.9];    #   MAPTILE_FROZEN_LIQUID_WALL_DET_LR,
$TILE_TYPES[493] = [FLOOR,constructed_floor_detailed,0.9];    #   MAPTILE_CONSTRUCTED_FLOOR_DETAILED,
$TILE_TYPES[494] = [FORTIF,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_FORTIFICATION,
$TILE_TYPES[495] = [PILLAR,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_PILLAR,
$TILE_TYPES[496] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_RD2,
$TILE_TYPES[497] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_R2D,
$TILE_TYPES[498] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_R2U,
$TILE_TYPES[499] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_RU2,
$TILE_TYPES[500] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_L2U,//500
$TILE_TYPES[501] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LU2,
$TILE_TYPES[502] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_L2D,
$TILE_TYPES[503] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LD2,
$TILE_TYPES[504] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LRUD,
$TILE_TYPES[505] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_RUD,
$TILE_TYPES[506] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LRD,
$TILE_TYPES[507] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LRU,
$TILE_TYPES[508] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LUD,
$TILE_TYPES[509] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_RD,
$TILE_TYPES[510] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_RU,
$TILE_TYPES[511] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LU,
$TILE_TYPES[512] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LD,
$TILE_TYPES[513] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_UD,
$TILE_TYPES[514] = [WALL,constructed_wall,0.9];    #   MAPTILE_CONSTRUCTED_WALL_DET_LR,
$TILE_TYPES[515] = [STAIR,constructed_wall,0.9];    #   MAPTILE_STAIR_UPDOWN_CONSTRUCTED,
$TILE_TYPES[516] = [STAIR_DOWN,constructed_wall,0.9];    #   MAPTILE_STAIR_DOWN_CONSTRUCTED,
$TILE_TYPES[517] = [STAIR_UP,constructed_wall,0.9];    #   MAPTILE_STAIR_UP_CONSTRUCTED,
$TILE_TYPES[518] = [RAMP,constructed_wall,0.9];    #   MAPTILE_RAMP_CONSTRUCTED,


sub get_df_tile_type_data {
    return @TILE_TYPES;
}


my @item_ids;
    
$item_ids[0] = "Barrel";
$item_ids[2] = "Anvil";
$item_ids[8] = "Maple logs";
$item_ids[10] = "Tower-cap logs";
$item_ids[12] = "Bag";
$item_ids[16] = "Alder logs";

sub get_df_item_id_data {
    return @item_ids;
}


my @ramps = (
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

sub get_ramp_bitmasks {
    return @ramps;
}

1;