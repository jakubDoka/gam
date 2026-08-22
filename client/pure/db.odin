package pure_client

import "../../sim"
import "../../simt/nbio"
import "../../util/nm"
import "../../util/sqlite"
import "base:runtime"

Profile :: struct {
	name: sim.Player_Name,
	pk:   sim.Private_Key,
}

Saved_Text_Input :: struct {
	id:      int,
	content: string,
}

Saved_Server :: struct {
	nick_name:   string,
	conn_string: string,
	pk:          sim.Identity,
}

Saved_Asset :: struct {
	server: sim.Identity,
	id:     sim.Asset_ID,
	name:   nm.Name,
	type:   sim.Asset_Type,
}

// TODO(low): more consistent naming
Statements :: struct {
	save_input_content:        sqlite.Statement `
		INSERT INTO text_input VALUES (?, ?)
			ON CONFLICT (id) DO UPDATE SET content = ?2
	`,
	load_input_content:        sqlite.Statement `
		SELECT content FROM text_input WHERE id = ?
	`,
	delete_input_content:      sqlite.Statement `
		DELETE FROM text_input WHERE id = ?
	`,
	save_profile:              sqlite.Statement `
		INSERT INTO profile VALUES (?, ?)
	`,
	load_profiles:             sqlite.Statement `
		SELECT * FROM profile
	`,
	count_profiles:            sqlite.Statement `
		SELECT COUNT(*) FROM profile
	`,
	delete_profile:            sqlite.Statement `
		DELETE FROM profile WHERE name = ?
	`,
	edit_profile:              sqlite.Statement `
		UPDATE profile SET name = ? WHERE name = ?
	`,
	select_profile_by_name:    sqlite.Statement `
		SELECT * FROM profile WHERE name = ?
	`,
	select_theme_color:        sqlite.Statement `
		SELECT hue, saturation, brightness, alpha FROM theme WHERE name = ?
	`,
	save_theme_color:          sqlite.Statement `
		INSERT INTO theme VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET
				hue = ?2, saturation = ?3, brightness = ?4, alpha = ?5
	`,
	save_server:               sqlite.Statement `
		INSERT INTO server VALUES (?, ?, ?)
			ON CONFLICT (nick_name) DO UPDATE SET
				conn_string = ?2, pk = ?3
	`,
	load_server:               sqlite.Statement `
		SELECT * FROM server WHERE nick_name = ?
	`,
	load_servers:              sqlite.Statement `
		SELECT * FROM server
	`,
	delete_server:             sqlite.Statement `
		DELETE FROM server WHERE nick_name = ?
	`,
	save_asset:                sqlite.Statement `
		INSERT INTO asset VALUES (?, ?, ?, ?)
			ON CONFLICT (id, server) DO UPDATE SET name = ?3, type = ?4
			ON CONFLICT (server, name) DO UPDATE SET id = ?2, type = ?4 
	`,
	get_server_assets:         sqlite.Statement `
		SELECT * FROM asset WHERE server = ?
	`,
	get_server_assets_of_type: sqlite.Statement `
		SELECT * FROM asset WHERE server = ? AND type = ?
	`,
	get_asset:                 sqlite.Statement `
		SELECT * FROM asset WHERE id = ?
	`,
	delete_asset:              sqlite.Statement `
		DELETE FROM asset WHERE id = ?
	`,
}

delete_profile :: proc(client: ^Client, name: string) {
	_, delete_err := sqlite.exec(client.delete_profile, name)
	sqlite.assert_ok(client.delete_profile, delete_err)
}

save_server :: proc(client: ^Client, new_server: Saved_Server) {
	_, res := sqlite.exec(
		client.save_server,
		new_server.nick_name,
		new_server.conn_string,
		new_server.pk,
	)
	sqlite.assert_ok(client.save_server, res)
}

delete_server :: proc(client: ^Client, nick_name: string) {
	_, delete_err := sqlite.exec(client.delete_server, nick_name)
	sqlite.assert_ok(client.delete_server, delete_err)
}

edit_profile_name :: proc(client: ^Client, new, old: string) -> (err: string) {
	cnt, save_err := sqlite.exec(client.edit_profile, new, old)

	if save_err == .CONSTRAINT {
		return "name already taken"
	}

	sqlite.assert_ok(client.edit_profile, save_err)
	assert(cnt == 1)

	return
}

create_profile :: proc(client: ^Client, name: string) -> string {
	pk: sim.Private_Key
	nbio.rand_bytes(pk[:])

	if name == "" {
		return "name cannot be empty"
	}

	_, res := sqlite.exec(client.save_profile, name, pk)
	if res == .CONSTRAINT {
		return "name already taken"
	}

	sqlite.assert_ok(client.save_profile, res)
	return ""
}

select_profile :: proc(client: ^Client, name: string) {
	_, save_err := sqlite.exec(
		client.save_input_content,
		SELECTED_PROFILE_CID,
		name,
	)
	sqlite.assert_ok(client.save_input_content, save_err)
}
