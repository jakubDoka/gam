package sim

import "core:fmt"
import la "core:math/linalg"
import "core:slice"
import "core:testing"

Quad_Config :: struct {
	quad_size: i32,
}

Quad_Ent :: struct {
	next: ^Quad_Ent,
	rect: Quad_Rect,
}

Quad_Tree :: struct {
	children:  ^[4]Quad_Tree,
	ents:      ^Quad_Ent,
	ent_count: int,
}

MIN_QUAD_SIZE :: 128
MAX_QUAD_ENTS :: 6

Quad_Insert_State :: struct {
	center:      [2]i32,
	quad_radius: i32,
	quad:        ^Quad_Tree,
}

Quad_Rect :: struct {
	top_left:     [2]i32,
	bottom_right: [2]i32,
}

quad_rect_square :: proc(pos: [2]f32, radius: f32) -> Quad_Rect {
	return Quad_Rect {
		top_left = {i32(pos[0] - radius), i32(pos[1] - radius)},
		bottom_right = {i32(pos[0] + radius), i32(pos[1] + radius)},
	}
}

quad_rect_line :: proc(start, finish: [2]f32, radius: f32) -> Quad_Rect {
	min := la.min(start, finish)
	max := la.max(start, finish)

	return Quad_Rect {
		top_left = {i32(min.x - radius), i32(min.y - radius)},
		bottom_right = {i32(max.x + radius), i32(max.y + radius)},
	}
}

quad_tree_add :: proc(self: ^Quad_Tree, ent: ^Quad_Ent, config: Quad_Config) {
	state := Quad_Insert_State {
		center      = {config.quad_size, config.quad_size},
		quad_radius = config.quad_size,
		quad        = self,
	}

	quad_tree_add_low(&state, ent, config)
}

quad_tree_add_low :: proc(
	state: ^Quad_Insert_State,
	ent: ^Quad_Ent,
	config: Quad_Config,
) {
	ent_top_left := ent.rect.top_left
	ent_bottom_right := ent.rect.bottom_right

	f_top_left := state.center - state.quad_radius
	f_bottom_right := state.center + state.quad_radius

	prev_state := state^

	for {
		state.quad.ent_count += 1

		left := ent_bottom_right[0] < state.center[0]
		right := ent_top_left[0] > state.center[0]

		top := ent_bottom_right[1] < state.center[1]
		bottom := ent_top_left[1] > state.center[1]

		assert(!(left && right))
		assert(!(top && bottom))

		idx := 0

		if left && top {
			idx = 0
		} else if right && top {
			idx = 1
		} else if left && bottom {
			idx = 2
		} else if right && bottom {
			idx = 3
		} else {
			break
		}

		if state.quad.ent_count > MAX_QUAD_ENTS &&
		   state.quad.children == nil &&
		   state.quad_radius >= MIN_QUAD_SIZE {

			state.quad.children = new([4]Quad_Tree)

			cursor := state.quad.ents

			state.quad.ents = nil
			state.quad.ent_count = 1

			for cursor != nil {
				e := cursor
				cursor = e.next

				cpy := state^

				quad_tree_add_low(&cpy, e, config)
			}
		}

		children := state.quad.children
		if children == nil do break

		state.quad = &children[idx]
		state.quad_radius >>= 1

		if left do state.center[0] -= state.quad_radius
		if right do state.center[0] += state.quad_radius
		if top do state.center[1] -= state.quad_radius
		if bottom do state.center[1] += state.quad_radius

		q_top_left := state.center - state.quad_radius
		q_bottom_right := state.center + state.quad_radius

		m_top_left := [2]i32{0, 0}
		m_bottom_right := [2]i32{config.quad_size, config.quad_size}

		if ent_bottom_right[0] < m_bottom_right[0] &&
		   ent_top_left[0] > m_top_left[0] &&
		   ent_bottom_right[1] < m_bottom_right[1] &&
		   ent_top_left[1] > m_top_left[1] {

			assert(ent_top_left[0] >= q_top_left[0])
			assert(ent_bottom_right[0] <= q_bottom_right[0])

			assert(ent_top_left[1] >= q_top_left[1])
			assert(ent_bottom_right[1] <= q_bottom_right[1])
		}

		assert(state.center[0] - state.quad_radius >= f_top_left[0])
		assert(state.center[1] - state.quad_radius >= f_top_left[1])

		assert(state.center[0] + state.quad_radius <= f_bottom_right[0])
		assert(state.center[1] + state.quad_radius <= f_bottom_right[1])
	}

	ent.next = state.quad.ents
	state.quad.ents = ent
}

Quad_Iter :: struct {
	cursor: ^Quad_Ent,
	quads:  []^Quad_Tree,
}

quad_iter_next :: proc(it: ^Quad_Iter) -> (^Quad_Ent, bool) {
	for {
		for it.cursor != nil {
			ent := it.cursor
			it.cursor = ent.next

			if ent.rect != {} {
				return ent, true
			}
		}

		if len(it.quads) == 0 {
			return nil, false
		}

		it.cursor = it.quads[0].ents
		it.quads = it.quads[1:]
	}

	return nil, false
}

quad_iter :: proc(
	self: ^Quad_Tree,
	rect: Quad_Rect,
	config: Quad_Config,
) -> Quad_Iter {
	quads := quad_tree_get_intersecting_quads(self, rect, config)
	return Quad_Iter{quads = quads}
}

quad_tree_get_intersecting_quads :: proc(
	self: ^Quad_Tree,
	rect: Quad_Rect,
	config: Quad_Config,
) -> []^Quad_Tree {
	top_left := rect.top_left
	bottom_right := rect.bottom_right

	size := config.quad_size

	f_top_left := [2]i32{0, 0}

	f_bottom_right := [2]i32{size * 2, size * 2}

	assert(top_left[0] <= bottom_right[0])
	assert(top_left[1] <= bottom_right[1])

	Dims :: struct {
		pos:    [2]i32,
		radius: i32,
	}

	Frontier_Slot :: struct {
		q:   ^Quad_Tree,
		met: Dims,
	}

	frontier: #soa[dynamic]Frontier_Slot
	append(
		&frontier,
		Frontier_Slot{q = self, met = {pos = {size, size}, radius = size}},
	)
	keep := 0
	for i := 0; i < len(frontier); i += 1 {
		slot := frontier[i]

		assert(slot.met.pos[0] - slot.met.radius >= f_top_left[0])
		assert(slot.met.pos[1] - slot.met.radius >= f_top_left[1])

		assert(slot.met.pos[0] + slot.met.radius <= f_bottom_right[0])
		assert(slot.met.pos[1] + slot.met.radius <= f_bottom_right[1])

		left := bottom_right[0] < slot.met.pos[0]
		right := top_left[0] > slot.met.pos[0]

		top := bottom_right[1] < slot.met.pos[1]
		bottom := top_left[1] > slot.met.pos[1]

		next_radius := slot.met.radius >> 1

		if slot.q.ents != nil {
			frontier.q[:len(frontier)][keep] = slot.q
			keep += 1
		}

		children := slot.q.children
		if children == nil do continue

		hits := [4]bool {
			!right && !bottom,
			!left && !bottom,
			!right && !top,
			!left && !top,
		}

		offsets := [4][2]i32 {
			{-next_radius, -next_radius},
			{next_radius, -next_radius},
			{-next_radius, next_radius},
			{next_radius, next_radius},
		}

		for j in 0 ..< 4 {
			child := &children[j]
			off := offsets[j]

			if hits[j] {
				append(
					&frontier,
					Frontier_Slot {
						q = child,
						met = {pos = slot.met.pos + off, radius = next_radius},
					},
				)
			} else {
				pos := slot.met.pos + off
				p_top_left := pos - next_radius
				p_bottom_right := pos + next_radius

				assert(
					top_left.x > p_bottom_right.x ||
					bottom_right.x < p_top_left.x ||
					top_left.y > p_bottom_right.y ||
					bottom_right.y < p_top_left.y,
				)
			}
		}
	}

	return frontier.q[:keep]
}

Spatial_Ent :: struct {
	next: ^Spatial_Ent,
}

Spatial_Pos :: [2]int

Spatial_Map :: struct {
	width:  int,
	height: int,
	slots:  [^]^Spatial_Ent,
}

Spatial_Iter :: struct {
	mapa:   ^Spatial_Map,
	i:      int,
	pos:    Spatial_Pos,
	cursor: ^Spatial_Ent,
}

QUERY_AREA :: 3

spatial_iter_next :: proc(
	iter: ^Spatial_Iter,
) -> (
	res: ^Spatial_Ent,
	ok: bool,
) {
	mapa := iter.mapa

	outher: for {
		if iter.cursor != nil {
			res = iter.cursor
			ok = true
			iter.cursor = res.next
			break outher
		}

		for {
			if iter.i >= QUERY_AREA * QUERY_AREA do break outher

			defer iter.i += 1

			x := iter.i % QUERY_AREA + iter.pos.x - 1
			y := iter.i / QUERY_AREA + iter.pos.y - 1

			if x < 0 || x >= mapa.width do continue
			if y < 0 || y >= mapa.height do continue

			iter.cursor = mapa.slots[x + y * mapa.width]

			break
		}
	}

	return
}

spatial_map_init :: proc(mapa: ^Spatial_Map, width: int, height: int) {
	mapa.width = width
	mapa.height = height
	mapa.slots = raw_data(make([]^Spatial_Ent, width * height))
}

spatial_map_clear :: proc(mapa: ^Spatial_Map) {
	slice.zero(mapa.slots[:mapa.width * mapa.height])
}

spatial_map_insert :: proc(
	mapa: ^Spatial_Map,
	pos: Spatial_Pos,
	ent: ^Spatial_Ent,
) {
	if pos.x < 0 || pos.x >= mapa.width do return
	if pos.y < 0 || pos.y >= mapa.height do return

	slot := &mapa.slots[pos.x + pos.y * mapa.width]
	ent.next = slot^
	slot^ = ent
}

@(test)
test_spatial :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator

	s: Spatial_Map
	spatial_map_init(&s, 3, 3)

	Ent :: struct {
		seen:      bool,
		using ent: Spatial_Ent,
	}

	ents: [4]Ent

	spatial_map_insert(&s, {0, 0}, &ents[0])
	spatial_map_insert(&s, {0, 1}, &ents[1])
	spatial_map_insert(&s, {0, 2}, &ents[2])
	spatial_map_insert(&s, {1, 0}, &ents[3])

	q: Spatial_Iter
	q.mapa = &s
	q.pos = {0, 0}

	for e in spatial_iter_next(&q) {
		base := (^Ent)(uintptr(e) - offset_of(Ent, ent))
		base.seen = true
	}

	testing.expect(t, ents[0].seen)
	testing.expect(t, ents[1].seen)
	testing.expect(t, !ents[2].seen)
	testing.expect(t, ents[3].seen)

	for &e in ents do e.seen = false

	q.i = 0
	q.pos = {-1, -1}

	for e in spatial_iter_next(&q) {
		base := (^Ent)(uintptr(e) - offset_of(Ent, ent))
		base.seen = true
	}

	testing.expect(t, ents[0].seen)
	testing.expect(t, !ents[1].seen)
	testing.expect(t, !ents[2].seen)
	testing.expect(t, !ents[3].seen)
}
