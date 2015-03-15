# General Description and Usage #

Map\_extract is based on Rick's reveal.exe and makes extensive use of his memory research. It accesses the memory of a running (and hopefully paused) Dwarf Fortress game to extract the landscape data and export the tile types and other parts into a gzipped text file.

# Details #

It will output the map data in two fashions:
  * **lite** (clear-text): Contains ONLY the type data and is formatted in a way that one can easily do ctrl+f to replace numbers with ascii symbols ([example](http://dwarvis.googlecode.com/files/ascii_map.txt))
  * **full** (gzipped): This is intended to be loaded by another application (i.e. 3d visualizer software). It contains for each tile the type, the designation flags and the occupancy flags.
  * **binary** (gzipped): This is intended to be loaded by another application (i.e. 3d visualizer software). It contains for each tile the type, the designation flags and the occupancy flags. Spec: see below.

Both files are formatted in such a way to represent the data exactly as seen in DF, i.e. top left tile in game will be top left in the map file.

  * The first line contains the name of the map that was entered while running the program, the x-size, the y-size and the z-size; seperated by |s.
  * Each z-level is one block, started by one line that only contains the index of the current z-level, enclosed in -s.
  * Each y-line has one line in the block, containing the tiles, seperated by |s.
  * Each tile is either represented by a "-1", meaning it is unallocated; or a triplet of numbers, seperated by :s.
  * The numbers mean, in sequence: "type:designation flags:occupancy flags".
  * The type ids are straight numbers, the meaning of which is still being decyphered, with results available [here](http://www.dwarffortresswiki.net/index.php/User:Mithaldu/Tile_types_in_DF_memory) and [here](http://spreadsheets.google.com/ccc?key=ppHCNfNceTrmxbXWDzf9aXg&hl=en).
  * The dependancy flags and occupancy flags are largely unknown, but some data on them is available in the [DFWiki](http://www.dwarffortresswiki.net/index.php/User:Rick/Memory_research#Data_Block).

Binary file format:
```
 (Uint32)(Uint8)\n               = File identifier.  Use first 32 bits as unique identifier for filetype (DFMM), last 8 for version of standard
 (char)(char)(char)...\n         = Map name, list of chars with newline at end
 (Uint8)(Uint8)(Uint8)\n         = (X)(Y)(Z) size, where Z = number of actual layers in file
 (Uint16)(Uint32)(Uint32)...\n   = Tile information for first layer, starting at upper left, going right then down, newline at end
 (Uint16)(Uint32)(Uint32)...\n   = ^ second layer,  (Type)(Designation)(Occupancy)
 ...
 (Uint16)(Uint32)(Uint32)...     = ^ last layer
```