This project is meant as a collection of 3rd party utilities for the game Dwarf Fortress. It concentrates on utilities that have the purpose of providing a 3-dimensual visualization of the ingame world. It contains two applications at the current time.

# Applications #

## Lifevis ##

This is the main program, a life viewer of a DF game. It shows a 3d representation centered on the current view, which constantly updates. It currently displays landscape, creatures, buildings and items, although the latter three aren't yet at full detail representation. Additionally it forwards all input to DF, so it can act as a remote control.

Please click the Feedback link to the right if you have questions about lifevis, want to make suggestions or provide general feedback.

[![](http://i37.tinypic.com/140byq8.jpg)](http://www.veoh.com/videos/v16314761MGwKDQR7)

## map\_extract ##

This script accesses the memory of a running (and hopefully paused) Dwarf Fortress game. It extracts the landscape data and exports the tile types and other parts into a gzipped text file. [More...](NotesOnMapExtract.md)


# Latest Updates #

(Changes are listed chronologically from the bottom up.)

Lifevis v0.254 - Date: 03:05:45, Freitag, 14. November 2008
  * All items are now stored in a hash again, due to unpredictably high id values exceeding the memory bounds when applied to an array.
  * Removed "item\_present" array in favor of visible flag on items, need to think about how to handle items vanishing from DF's memory list IF it happens.
  * All update loops and the render loop now set times at which they wish to be run again; these times are calculated by adding the configurable delay to the current time and subtracting the time it took for the loop to run the last time.
  * All update loops now run for a minimum configurable time slice before returning control to the dispatcher.
  * All update loops and the render loop now have functions for time measuring.
  * Item data is grabbed in buckets with each one spanning multiple item data sets.
  * Unit data is now grabbed as one string and dissected in Perl.
  * Speed-up of landscape updates when cell didn't change by comparing data extract in one step before cycling through the tiles in the cell.
Lifevis v0.249 - Date: 13:33:29, Dienstag, 11. November 2008
  * This effectively improves performance by skipping invisible cells.
  * Model drawing is now split into 1. drawing of landscape, 2. drawing of visibility masks and selecting cells based on visibility level, 3. drawing buildings, items, creatures in selected cells.
  * Landscape display list generation now generates crude visibility mask display lists.
  * Base lighting made brighter.
  * Lighting variances still not optimal.
  * Added glDeleteQueries call to OpenGL module.
  * Notes about OpenGL module changes added to documents.
  * All models are now drawn by z-layer in preparation for occlusion checks.
  * Creature, building and item lists in cell structure are now divided by z-layer.
  * Display list storage in caches changed to enable easier access and extension.
  * Documents and internals files updated to correspond with that.
  * Calculation of light variances changed.
  * Recompiled OpenGL module to include occlusion check calls.
  * Added QuadTree class to deal with creating occlusion check shapes.
  * Implemented zoom-by-fov in order to reduce z-clipping. (inactive)
  * Reduced z-buffer accuracy problems by clamping clipping planes to outer bounds of map.
  * Made landscape display lists be drawn in one call.
  * Fixed warning from threads when loading OpenGL twice by loading secondary modules later on.
  * Reactivated culling of invisible faces.
  * ModelGen now generates vertex array draw commands.
  * Adapted buildings, creatures, items to new generic method and phased out old specific methods.
  * Made model generation sub routines return display list ids.
  * Building drawing adapted to general model display lists.
  * Landscape drawing sketchily adapted to new parts subroutines.
  * General model->display list conversion routine created.
  * Model code generation switched to generating separate subroutines for faces in the cardinal directions and one for the main body.
  * Basis for parts-based display list generation laid.
  * Made the model generator code decidedly less retarded and easier to transition over to generate individual subroutines for the normals.
  * Added comments to model generator code.
  * Refactoring to prepare for switch to vertex arrays.
  * Improved handling of z-based lighting of buildings.
  * Added dedicated default building model.
Lifevis v0.227 - Date: 16:00:09, Samstag, 18. Oktober 2008
  * Input sent to DF is now immediate and doesn't follow Windows' repeat rules anymore.
  * Improved mouse interaction.
  * New cursor model.
  * Fixed Stairs-Down model to simply be a hole in the floor.
  * Added vtable export converter.
  * Made update loops for buildings and items assign vtable names and offsets to items.
  * Added basic models for doors and workshops.
  * Added basic building model distinction system.
  * Made range change buttons dim when range limits reached.
  * Made view range changes also change the clipping range to reduce z-fighting.
  * A lot of code refactoring.
Lifevis v0.215 - Date: 20:29:24, Dienstag, 14. Oktober 2008
  * Bugfix to make the view update when the drawing range is changed even then the cursor isn't moved.
  * Far clipping plane moved closer to reduce z-errors.
  * All Perl modules updated to most current versions, especially OpenGL, which is now at 0.57 and includes freeglut.
Lifevis v0.213 - Date: 16:38:01, Dienstag, 14. Oktober 2008
  * New self-compiled executables.
  * Items that are in bins now get ignored.
  * Interface cleaned up a bit.
  * Item data now stored in array and indexed by DF-internal item id, instead of in a hash indexed by memory address.
  * Items are now only stored when they are lying on the ground and not hidden.
Lifevis v0.209
  * Mostly performance improvements, as follows:
  * Memory loop now sleeps until needed.
  * Memory loop becomes less aggressive when all current cells are protected.
  * Idle tasks routine converted to "while"-loop with a central loop scheduler to cut number of routine calls.
  * Added higher priority for drawing-loop, tweaked fps limiter to be more exact.
  * Unnecessary cloning of arrays converted to much faster iteration over them.
Lifevis v0.204
  * Added display of item placeholders.
  * Tweaked settings to speed graphics up a bit.
  * Added export of data of items/buildings/creatures in current square.
  * Fixed bug in rendering loop that prevented buildings from rendering in cells without creatures.
Lifevis v0.200 - Date: 10:25:14, Mittwoch, 8. Oktober 2008
  * Buildings now get displayed as bright red blocks. Doesn't work 100% yet.
  * Added readme file.
  * Reduced creature update slowdown to 0. Made some small optimizations to creature updates.
Lifevis v0.198 - Date: 01:12:00, Mittwoch, 8. Oktober 2008
    * Calls to Win32::Process::Memory converted to direct calls, resulting in a speed-up of the update routines of roughly 200%.