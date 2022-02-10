let files = [];
let breakpoints = [];
let registers = [];
let current_file = 0;
let current_position = {address: "", line: "", file: ""};
let last_position    = {address: "", line: "", file: ""};

function attach_frag_children(host_elem, frag_elem) {
	if (host_elem.firstChild) {
		let section_parent = host_elem.parentElement;
		let new_host_elem = host_elem.cloneNode();
		new_host_elem.appendChild(frag_elem);
		section_parent.replaceChild(new_host_elem, host_elem)
	} else {
		host_elem.appendChild(frag_elem);
	}
}

async function toggle_breakpoint(file_name, line_num) {
	let line_elem = document.getElementById('code-line-' + line_num);
	let toggle_val = line_elem.classList.toggle("line-break");

	if (toggle_val) {
		await fetch('/set_breakpoint?file=' + file_name + "&line=" + line_num);
	} else {
		await fetch('/clear_breakpoint?file=' + file_name + "&line=" + line_num);
	}

	await get_breakpoints();
}

async function get_file_list() {
	let response = await fetch('/get_file_list');
	let file_list = await response.json();
	files = file_list.paths;
	current_file = 0;

	for (let i = 0; i < files.length; i++) {
		files[i].data = await get_file(files[i]);
	}
}

async function get_file(path_blob) {
	let file_path = path_blob.path + "/" + path_blob.name;
	let response = await fetch('/get_file?file=' + file_path);
	let file_blob = await response.json();
	return file_blob;
}

async function single_step() {
	await fetch('/single_step');
	await get_registers();
	await get_current_position();

	render_page();
}

async function step_into() {
	await fetch('/step_into');
	await get_registers();
	await get_current_position();

	render_page();
}

async function run_line() {
	await fetch('/run_line');
	await get_registers();
	await get_current_position();

	render_page();
}

async function cont() {
	await fetch('/cont');
	await get_registers();
	await get_current_position();

	render_page();
}

async function restart() {
	await fetch('/restart');
	current_position = {address: "", line: "", file: ""};
	old_position = {address: "", line: "", file: ""};

	await get_registers();
	await get_current_position();
	await get_breakpoints();

	render_page();
}

async function get_registers() {
	let response = await fetch('/get_registers');
	registers = await response.json();
}

async function get_current_position() {
	let response = await fetch('/current_position');
	let new_position = await response.json();

	old_position = current_position;
	current_position = new_position;
}

async function get_breakpoints() {
	let response = await fetch('/breakpoints');
	breakpoints = await response.json();	
}

function render_registers() {
	let reg_display_elem = document.getElementById('register-display');
	let reg_frag = document.createDocumentFragment();

	let reg_header_elem = document.createElement("h3");
	let reg_header_text = document.createTextNode("Registers");
	reg_header_elem.appendChild(reg_header_text);
	reg_frag.appendChild(reg_header_elem);

	for (let i = 0; i < registers.length; i++) {
		let register = registers[i];

		let reg_line = document.createElement("div");
		reg_line.classList.add("register-line");
		
		let reg_name = document.createTextNode(register.name + ":");
		let reg_name_elem = document.createElement("p");
		reg_name_elem.appendChild(reg_name);

		let reg_val = document.createTextNode(register.value);
		let reg_value_elem = document.createElement("span");
		reg_value_elem.appendChild(reg_val);

		reg_line.appendChild(reg_name_elem);
		reg_line.appendChild(reg_value_elem);

		reg_frag.appendChild(reg_line);	
	}

	attach_frag_children(reg_display_elem, reg_frag);
}

function render_file_list() {
	let ftree_display_elem = document.getElementById('ftree-display');

	let ftree_frag = document.createDocumentFragment();

	for (let i = 0; i < files.length; i++) {
		let file = files[i];
		let fline = document.createElement("p");
		let fname = document.createTextNode(file.name);

		if (i == current_file) {
			fline.classList.add("current-file");
		} else {
			let cur_idx = i.valueOf();
			fline.addEventListener("click", () => { 
				current_file = cur_idx;
				render_page();
			});
		}

		fline.appendChild(fname);
		ftree_frag.appendChild(fline);
	}

	attach_frag_children(ftree_display_elem, ftree_frag);	
}

function render_breakpoints() {
	for (let i = 0; i < breakpoints.length; i++) {
		let bp = breakpoints[i];
		if (bp.file == files[current_file].name) {
			let line_elem = document.getElementById('code-line-' + bp.line);
			line_elem.classList.add("line-break");
		}
	}
}

function render_position() {
	if (current_position.line == "") {
		return;
	}

	if (current_position.file == files[current_file].name) {
		let line_elem = document.getElementById('code-line-' + current_position.line);
		line_elem.classList.add("line-active");
	}

	if (current_position.line != "" && current_position.line != old_position.line && old_position.file == files[current_file].name) {
		let old_line_elem = document.getElementById('code-line-' + old_position.line);
		old_line_elem.classList.remove("line-active");
	}
}

function render_file(file) {
	let file_elem = document.getElementById('file-display');

	let chunk = file.data.data;
	let file_name = file.name;

	let re = /\n|\r|\r\n/gm;
	let start_idx = 0;
	let file_frag = document.createDocumentFragment();
	let line_count = 1;

	let file_header_elem = document.createElement("h3");
	let header_text = document.createTextNode("File - " + file_name);
	file_header_elem.appendChild(header_text);
	file_frag.appendChild(file_header_elem);

	let file_display_elem = document.createElement("div");
	for (;;) {
		let line_elem = document.createElement("div");
		line_elem.classList.add("code-line-wrapper");

		let pre_elem = document.createElement("pre");
		let code_elem = document.createElement("code");
		pre_elem.appendChild(code_elem);

		let ret = re.exec(chunk);
		if (!ret) {
			break;
		}

		let rem = chunk.substring(0, re.lastIndex);
		let line = chunk.substring(0, re.lastIndex);
		chunk = chunk.substring(re.lastIndex);
		re.lastIndex = 0;

		let count_elem = document.createElement("span");
		let cur_line_count = line_count.valueOf();
		count_elem.setAttribute('data-line-number', cur_line_count);
		count_elem.classList.add('code-line');
		count_elem.addEventListener("click", () => { toggle_breakpoint(file_name, cur_line_count); });

		line_elem.setAttribute('id', 'code-line-' + cur_line_count);
		line_elem.appendChild(count_elem);

		if (line[0] === undefined) {
			let break_elem = document.createElement("br");
			line_elem.appendChild(break_elem);
		} else {
			let file_text = document.createTextNode(line);
			code_elem.appendChild(file_text);
			line_elem.appendChild(pre_elem);
		}

		file_display_elem.appendChild(line_elem);
		start_idx = re.lastIndex;
		line_count += 1;
	}

	let line_count_width = Math.floor(Math.log10(line_count)) + 1;
	document.documentElement.style.setProperty('--line-count-width', line_count_width + 'ch');

	file_frag.appendChild(file_display_elem);
	attach_frag_children(file_elem, file_frag);
}


function render_page() {
	render_registers();

	for (let i = 0; i < files.length; i++) {
		if (files[i].name == current_position.file) {
			current_file = i;
			break;
		}
	}

	render_file_list();
	render_file(files[current_file]);
	render_breakpoints();
	render_position();
}

async function main() {
	await get_file_list();
	await get_registers();
	await get_current_position();
	await get_breakpoints();

	render_page();
}
