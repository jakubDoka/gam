Hello, there is a package called sandbox in my oding project, there is also a
package called sim, in sim/sim.odin, there is a simulation implementation and
it does a bit smarter collisions if it can, the circel_collision function is
used to determine if something collides, the main issue here is that the
sandbox as fo right now does not do this, same goes for wall collisions. The
object can in theory skip trough a wall. In a normal scenareo this obviously
does not happen, but I want to handle this edge case.

So the sandbox as of right now works fine, but you need to extend it for cases
when the entityes are moving in steps higher then their radius/2, in those case
you should resort to the more precise collision algorithm where you find the
nearest collider in time as long as you have time to collide and execute that
collision.

When it comes to the spatial querying, add a quadtree to the sandbox and modify
the ents_query to match, then when you are querying for colliders use the same
formula used in the sim/sim.odin:ents_update.

When it comes to the wall collisions, try to invent some kind of algorithm to
the same, you can resort to doing something similar to the
sim/map.odin:map_wall_collision, loop here is acceptable since tiles are not uniform and thus can not be in a closed formula.

Make sure the PORTABLE BLOCK and MIMIC BLOCK are preserverd, basically, I should be able to paste it to the sim module and do minimal porting work

If you have questions ask them. Then:

1. analyzie mentioned code and understanding it.
2. make changes to the sandbox/sandbox.odin accordingly.
3. add more tests to the sandbox/sandbox_test.odin. Run them with -o:speed
4. add a velocity mode to the sandbox/main.odin where I can
   click->drag->release to launch and entity for testing purposes.
