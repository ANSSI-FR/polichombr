/*
 *
 *    User interface script for the families view
 *           (c) ANSSI-FR 2018
 *
 */

function expand_callback(event_data){
	/*
	 * Construct a subpanel with buttons linking to subfamilies
	 */
	console.log(`Family ${event_data["data"]} expand requested`);
	family_id = event_data["data"];
	function expand_subfamilies(family){
		family = family["family"];
		fam_div = $('#family_'+ family["id"]);

		fam_panel_body = $("<div></div>");
		fam_panel_body.attr("id", "family_subfamilies_panel_" + family["id"]);
		fam_panel_body.attr("class", "panel-body");
		fam_panel_body.attr("style", "display:none;");

		for (var i=0; i < family["subfamilies"].length; i++){
			subfam = family["subfamilies"][i];

			sub_fam_row = $("<div></div>");
			sub_fam_row.append("<div class='col-lg-1'></div>");

			button_name = $("<a></a>");
			button_name.attr("href", "/family/" + subfam["id"]);
			button_name.text(subfam["name"]);
			familycolorbystatus(button_name, subfam);

			sub_fam_row.append($("<div class='col-lg-3'></div>").append(button_name));
			fam_panel_body.append(sub_fam_row);
		}
		fam_div.append(fam_panel_body);
		fam_panel_body.show();
	};
	if ($('#family_subfamilies_panel_'+family_id).length){
		$('#family_subfamilies_panel_'+family_id).slideUp();
		$('#family_subfamilies_panel_'+family_id).remove();
	} else {
		$.get("/api/1.0/family/"+family_id, expand_subfamilies);
	}
};

function familycolorbystatus(element, family){
	if (family["status"] === 3){
		element.attr("class", "btn btn-primary");
	} else if (family["status"] === 2){
		element.attr("class", "btn btn-warning");
	} else if (family["status"] === 1){
		element.attr("class", "btn btn-success");
	} else if (family["status"] === 3){
		element.attr("class", "btn btn-default");
	} else {
		console.error("Invalid family status");
	}
};

function gen_tlp_button(element, tlp){
	/*
	 *
	 * Generic function for changing TLP button color
	 *
	 */
	if (tlp==1){
		element.attr("class", "btn btn-standard");
		element.text("TLP WHITE")
	} else if (tlp===2){
		element.attr("class", "btn btn-success");
		element.text("TLP GREEN")
	} else if (tlp===3){
		element.attr("class", "btn btn-warning");
		element.text("TLP AMBER")
	} else if (tlp===4){
		element.attr("class", "btn btn-danger");
		element.text("TLP RED")
	} else if (tlp===5){
		element.attr("class", "btn");
		element.text("TLP BLACK")
	}
};


function get_family_users(element, family_id){
	/*
	 *
	 * Generate a button for each user affected to the family
	 * This button points to the user profile
	 *
	 */
	function generate_user_buttons(family){
		family = family["family"];
		for (user_counter=0; user_counter < family["users"].length; user_counter++){
			user_button = $("<a></a>");
			user_button.attr("class", "btn btn-info");
			user_button.attr("href", "/user/"+family["users"][user_counter]["id"]);
			user_button.text(family["users"][user_counter]["nickname"]);
			element.append(user_button);
		}
	};
	family = $.get("/api/1.0/family/"+ family_id, generate_user_buttons);
};

function generate_family_row(family){
	row = $("<div></div>");
	row.attr("id", "family_" + family["id"]);
	row.attr("class", "row panel panel-default families");
	row.attr("style", "padding: 5px;");

	button_div = $("<div></div>");
	button_div.attr("class", "col-lg-4");

	button_name = $("<a></a>");
	button_name.attr("href", "/family/" + family["id"]);
	button_name.text(family["name"]);
	familycolorbystatus(button_name, family);

	button_div.append(button_name);


	tlp_div = $("<div></div>");
	tlp_div.attr("class", "col-lg-2");
	tlp_button = $("<p></p>");
	gen_tlp_button(tlp_button, family["TLP_sensibility"]);
	tlp_div.append(tlp_button);

	users_div = $("<div></div>");
	users_div.attr("class", "col-lg-4 text-center");
	users_div.attr("align", "center");
	users_div.attr("id", "users_cell_"+family["id"]);
	if (family["users"].length != 0){
		console.log("Getting users for family");
		get_family_users(users_div, family["id"]);
	}

	subs_div = $("<div></div>");
	subs_div.attr("class", "col-lg-1");
	if (family["subfamilies"].length > 0){
		expand_button = $("<p>Expand</p>");
		expand_button.attr("class", "btn");
		expand_button.attr("id", "btn_expand_"+ family["id"]);
		subs_div.append(expand_button);
		expand_button.click(family["id"], expand_callback);
	}

	row.append(button_div);
	row.append(tlp_div);
	row.append(users_div);
	row.append(subs_div);

	return row;
};

function family_sorter(fam1, fam2){
	return fam1["id"] - fam2["id"];
};

function parse_families(families){
	families = families["families"].sort(family_sorter);
	console.log(`Got ${families.length} families to parse`);
	for (i=0; i < families.length; i++){
		if (families[i]["parent_id"] === null){
			family_row = generate_family_row(families[i]);
			$("#families_container").append(family_row);
		}
	}
};


$(document).ready(function(){
	$.get("/api/1.0/families/", parse_families);
});
