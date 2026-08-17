I would like to split the client package into 2 packages, 1 that depends on
raylib and does the rendering, and 2 that has not refs to raylib and can be
used in the simt, your task right now is simple, identify all of the functions
that can be moved to the package 1 (client/pure) and move them there. Do this
incrementally and make sure `odin check client` has no errors. Just move as
much code as possible without including any raylib in the pure module, dont do
any modifications to the code besides namespacing the new functions in the
package 2 (pure.<item>)
