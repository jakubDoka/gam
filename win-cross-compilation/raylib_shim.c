#include "raylib.h"

// raylib 6.0 removed ImageDraw() in favor of ImageDrawImagePro(); this shim
// restores the old symbol so callers built against the older API keep linking.
void ImageDraw(Image *dst, Image src, Rectangle srcRec, Rectangle dstRec, Color tint) {
    ImageDrawImagePro(dst, src, srcRec, dstRec, (Vector2){0, 0}, 0.0f, tint);
}
